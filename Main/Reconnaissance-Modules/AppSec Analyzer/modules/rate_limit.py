"""
modules/rate_limit.py - Rate-Limit and Throttling Detection Module.

Detection strategy
──────────────────
1. Baseline latency measurement – establish a reference RTT over 5 sequential
   requests so that throttling-induced slowdowns can be measured against it.

2. Burst probe – fire N requests in rapid succession and count:
     • HTTP 429 (Too Many Requests) responses
     • Retry-After / X-RateLimit-* headers
     • Significant latency increase compared to baseline

3. Header inventory – collect every rate-limit related header the server sends
   (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After,
   RateLimit-Policy, …) and report them as INFO findings so the tester knows
   the enforcement parameters.

4. Endpoint sensitivity – repeat the burst on high-value endpoints
   (/login, /api/, /search) since many applications enforce stricter limits
   there than on the homepage.

5. Soft-throttle detection – detect increased latency without status-code
   changes (a "soft" rate limit that slows but does not block traffic).
"""

from __future__ import annotations

import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from core.exporter import Finding, Severity
from core.logger import get_logger
from core.requester import Requester, Response

log = get_logger("rate_limit")


# ── Configuration ─────────────────────────────────────────────────────────────

# Number of baseline requests used to compute reference latency
BASELINE_SAMPLE_COUNT = 5

# Number of burst requests fired in rapid succession
BURST_COUNT = 30

# Max concurrent workers during the burst (simulates parallel users)
BURST_WORKERS = 10

# Latency increase factor that we consider "significant" throttling
# 2.5× means responses are 2.5 times slower than baseline
LATENCY_SPIKE_FACTOR = 2.5

# Fraction of burst responses that must be 429 to flag rate-limiting
RATE_LIMIT_THRESHOLD = 0.10   # 10%

# High-sensitivity endpoints to probe additionally
HIGH_VALUE_PATHS = [
    "/login",
    "/signin",
    "/api/",
    "/api/v1/",
    "/search",
    "/wp-login.php",
    "/admin",
    "/account",
]

# Headers that reveal rate-limit configuration
RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-policy",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-retry-after",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
]


class RateLimitModule:
    """
    Detect rate-limiting, throttling, and request-quota enforcement.

    Parameters
    ----------
    target    : Normalised base URL of the target.
    requester : Shared Requester instance.
    """

    MODULE_NAME = "rate_limit"

    def __init__(self, target: str, requester: Requester) -> None:
        self.target    = target
        self.requester = requester
        self._findings: List[Finding] = []

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        """Execute all rate-limit detection strategies."""
        log.info(f"Rate-limit detection started → {self.target}")

        baseline_latency = self._measure_baseline_latency()

        if baseline_latency is None:
            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title="Could not establish baseline latency",
                severity=Severity.INFO,
                detail="All baseline requests failed; rate-limit analysis aborted.",
            ))
            return self._findings

        log.info(f"Baseline latency: {baseline_latency:.0f} ms")

        # Always harvest rate-limit headers from the baseline response first
        baseline_resp = self.requester.get(self.target)
        if baseline_resp:
            self._harvest_rate_limit_headers(baseline_resp, path="/")

        # Burst probe on the root path
        self._burst_probe(self.target, "/", baseline_latency)

        # Probe high-value endpoints (skip if they return 404 immediately)
        for path in HIGH_VALUE_PATHS:
            url  = self.target + path
            resp = self.requester.get(url)
            if resp is not None and resp.status_code not in (404, 410):
                log.debug(f"Probing high-value endpoint: {path}")
                self._harvest_rate_limit_headers(resp, path)
                self._burst_probe(url, path, baseline_latency)

        if not self._findings:
            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title="No rate-limiting detected",
                severity=Severity.INFO,
                detail=(
                    f"A burst of {BURST_COUNT} requests did not trigger "
                    f"HTTP 429 responses or measurable throttling. "
                    f"The target may allow unlimited requests, or the limit "
                    f"is higher than the probe volume."
                ),
            ))

        log.info(f"Rate-limit detection finished – {len(self._findings)} finding(s).")
        return self._findings

    # ── Layer 1: baseline latency ─────────────────────────────────────────────

    def _measure_baseline_latency(self) -> Optional[float]:
        """
        Send BASELINE_SAMPLE_COUNT sequential requests and return the
        median round-trip time in milliseconds.

        Sequential (not parallel) so that we measure server processing time
        rather than our own network concurrency overhead.
        """
        log.debug(f"Measuring baseline latency ({BASELINE_SAMPLE_COUNT} samples) …")
        samples: List[float] = []

        for i in range(BASELINE_SAMPLE_COUNT):
            resp = self.requester.get(self.target)
            if resp is not None:
                samples.append(resp.elapsed_ms)
                time.sleep(0.3)   # Small gap so we don't trigger rate-limits ourselves

        if not samples:
            return None

        median = statistics.median(samples)
        log.debug(
            f"Baseline samples: {[f'{s:.0f}' for s in samples]} ms  "
            f"(median {median:.0f} ms)"
        )
        return median

    # ── Layer 2: burst probe ──────────────────────────────────────────────────

    def _burst_probe(
        self,
        url: str,
        path: str,
        baseline_ms: float,
    ) -> None:
        """
        Fire BURST_COUNT parallel requests at *url* and analyse the responses.

        Detects:
          - HTTP 429 rate-limit status codes
          - Retry-After / X-RateLimit-* headers revealed under load
          - Soft throttling (latency spike without status-code change)
        """
        log.debug(f"Burst probe ({BURST_COUNT} req, {BURST_WORKERS} workers): {url}")

        responses: List[Response] = []

        with ThreadPoolExecutor(max_workers=BURST_WORKERS) as pool:
            futures = [pool.submit(self.requester.get, url)
                       for _ in range(BURST_COUNT)]
            for f in as_completed(futures):
                resp = f.result()
                if resp is not None:
                    responses.append(resp)

        if not responses:
            log.warning(f"All burst requests to {url} failed.")
            return

        self._analyse_burst_responses(responses, path, baseline_ms)

    def _analyse_burst_responses(
        self,
        responses: List[Response],
        path: str,
        baseline_ms: float,
    ) -> None:
        """
        Inspect a completed burst and emit findings.

        Called after _burst_probe collects all responses.
        """
        total   = len(responses)
        limited = [r for r in responses if r.status_code == 429]
        latencies = [r.elapsed_ms for r in responses]

        ratio = len(limited) / total if total else 0

        # ── 429 detection ────────────────────────────────────────────────────
        if ratio >= RATE_LIMIT_THRESHOLD:
            retry_after = ""
            if limited:
                retry_after = limited[0].header("retry-after")

            evidence = [
                f"Endpoint             : {path}",
                f"429 responses        : {len(limited)}/{total} ({ratio:.0%})",
                f"Burst size           : {BURST_COUNT} requests",
            ]
            if retry_after:
                evidence.append(f"Retry-After          : {retry_after}")

            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title=f"Rate-limiting confirmed (HTTP 429) – {path}",
                severity=Severity.MEDIUM,
                detail=(
                    f"{len(limited)} out of {total} burst requests to '{path}' "
                    f"were rejected with HTTP 429 Too Many Requests. "
                    f"Rate-limiting is actively enforced on this endpoint."
                ),
                evidence=evidence,
            ))
            log.info(f"Rate-limit 429 confirmed on {path} ({ratio:.0%} blocked).")

            # Harvest any rate-limit headers from the first 429 response
            if limited:
                self._harvest_rate_limit_headers(limited[0], path)

        # ── Soft throttle (latency spike) ─────────────────────────────────────
        if latencies:
            burst_median = statistics.median(latencies)
            spike_factor = burst_median / baseline_ms if baseline_ms > 0 else 1.0

            if spike_factor >= LATENCY_SPIKE_FACTOR:
                self._findings.append(Finding(
                    module=self.MODULE_NAME,
                    title=f"Soft throttling detected (latency spike) – {path}",
                    severity=Severity.LOW,
                    detail=(
                        f"Under burst load the median response time at '{path}' "
                        f"increased by a factor of {spike_factor:.1f}× compared "
                        f"to the baseline ({burst_median:.0f} ms vs "
                        f"{baseline_ms:.0f} ms baseline). "
                        f"This suggests soft rate-limiting or intentional "
                        f"back-pressure without 429 responses."
                    ),
                    evidence=[
                        f"Baseline median : {baseline_ms:.0f} ms",
                        f"Burst median    : {burst_median:.0f} ms",
                        f"Spike factor    : {spike_factor:.2f}×",
                    ],
                ))

    # ── Layer 3: header harvesting ────────────────────────────────────────────

    def _harvest_rate_limit_headers(self, resp: Response, path: str) -> None:
        """
        Collect known rate-limit response headers and emit them as INFO
        findings so the tester can read quota configuration from the report.
        """
        found: Dict[str, str] = {}
        for header_name in RATE_LIMIT_HEADERS:
            value = resp.header(header_name)
            if value:
                found[header_name] = value

        if found:
            evidence = [f"{k}: {v}" for k, v in found.items()]
            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title=f"Rate-limit headers exposed – {path}",
                severity=Severity.INFO,
                detail=(
                    f"The server returned rate-limit configuration headers "
                    f"on '{path}'. These reveal quota thresholds and reset "
                    f"windows that an attacker could use to stay under the limit."
                ),
                evidence=evidence,
            ))
            log.debug(f"Rate-limit headers on {path}: {found}")