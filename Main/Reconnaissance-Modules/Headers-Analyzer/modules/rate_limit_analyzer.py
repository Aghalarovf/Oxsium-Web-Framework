import math
import re
from email.utils import parsedate_to_datetime
from datetime import timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


RATE_LIMIT_NAME = re.compile(r"^(?:x-(?:ms-)?)?rate-?limit(?:-(?P<rest>.+))?$")
DURATION_FULL = re.compile(r"^(?:\d+(?:\.\d+)?(?:ms|s|m|h|d))+$")
DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d)")
DURATION_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}

COUNTER_FIELDS = {"limit", "remaining", "reset", "used", "policy"}
INFO_FIELDS = {"resource", "bucket", "global", "scope", "burst", "replenish", "requested", "retry"}
IDENTITY_FIELDS = {"key", "client", "user", "ip", "identity", "identifier"}

DIMENSION_WINDOWS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "month": 2592000}

RETRY_HEADERS = ("retry-after", "x-retry-after")
RETRY_MS_HEADERS = ("retry-after-ms", "x-ms-retry-after-ms")
MAX_REASONABLE_RETRY_SECONDS = 86400

STATIC_ASSET_MARKERS = ("image/", "font/", "text/css", "javascript", "video/", "audio/")
API_SEGMENTS = {"api", "graphql", "rest", "v1", "v2", "v3", "v4"}
AUTH_SEGMENTS = {
    "login", "logon", "signin", "signup", "register", "registration", "auth",
    "authenticate", "authorize", "oauth", "oauth2", "token", "tokens", "password",
    "passwd", "forgot", "reset", "recover", "recovery", "otp", "mfa", "2fa",
    "verify", "verification", "sms", "pin", "sso", "session", "sessions",
}

PER_MINUTE_MEDIUM = 60
PER_MINUTE_LOW = 20
MIN_SAMPLES_FOR_STATIC = 5


def _display(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))


def _fmt(number: Any) -> str:
    if isinstance(number, float) and number.is_integer():
        return str(int(number))
    if isinstance(number, float):
        return f"{number:.2f}".rstrip("0").rstrip(".")
    return str(number)


class RateLimitAnalysis:
    def __init__(self):
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.header_names: List[str] = []
        self.identity_headers: List[str] = []
        self.vendors: List[str] = []
        self.retry_after_header: Optional[str] = None
        self.retry_after: Optional[str] = None
        self.retry_after_seconds: Optional[float] = None
        self.retry_after_valid: Optional[bool] = None
        self.is_auth_endpoint: bool = False
        self.is_api_endpoint: bool = False
        self.issues: List[Tuple[str, str, str]] = []
        self.hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "groups": {
                dim: {key: value for key, value in group.items() if key != "conventions"}
                for dim, group in self.groups.items()
            },
            "headers": self.header_names,
            "identity_headers": self.identity_headers,
            "vendors": sorted(set(self.vendors)),
            "retry_after": self.retry_after,
            "retry_after_seconds": self.retry_after_seconds,
            "retry_after_valid": self.retry_after_valid,
            "is_auth_endpoint": self.is_auth_endpoint,
            "is_api_endpoint": self.is_api_endpoint,
            "issues": self.issues,
            "hint": self.hint,
        }


class RateLimitModule(BaseHeaderModule):
    name = "Rate Limit Analyzer"
    description = "Analyzes rate-limit and throttling headers (X-RateLimit-*, RateLimit-*, Retry-After) for missing, inconsistent or weak throttling signals."

    def __init__(self):
        self._counters: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def applies_to(self, response: HTTPResponse) -> bool:
        content_type = (self._get_header(response.headers, "Content-Type") or "").lower()
        return not any(marker in content_type for marker in STATIC_ASSET_MARKERS)

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        analysis = self.analyze(response)
        self._emit(analysis, result)
        result.metadata["rate_limit"] = analysis.to_dict()
        return result

    def analyze(self, response: HTTPResponse) -> RateLimitAnalysis:
        analysis = RateLimitAnalysis()
        headers = response.headers
        parsed_url = urlparse(response.url)
        path = parsed_url.path.lower()
        host = (parsed_url.hostname or "").lower()
        content_type = (self._get_header(headers, "Content-Type") or "").lower()
        segments = {part for part in re.split(r"[^a-z0-9]+", path) if part}

        analysis.is_auth_endpoint = bool(segments & AUTH_SEGMENTS)
        analysis.is_api_endpoint = "json" in content_type or bool(segments & API_SEGMENTS)

        now = self._response_epoch(headers)
        self._collect_headers(headers, analysis, now)
        self._collect_retry_after(headers, analysis, now)
        self._build_issues(response, analysis, host)
        return analysis

    @staticmethod
    def _number(value: Any) -> Optional[float]:
        try:
            number = float(str(value).strip())
        except ValueError:
            return None
        if not math.isfinite(number):
            return None
        return int(number) if number.is_integer() else number

    @staticmethod
    def _http_date(text: str) -> Optional[float]:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    def _response_epoch(self, headers: Dict[str, str]) -> Optional[float]:
        raw = headers.get("date")
        return self._http_date(raw) if raw else None

    def _parse_reset(self, raw: str, now: Optional[float], forced: Optional[str]) -> Tuple[Optional[float], Optional[str]]:
        text = raw.strip()
        if DURATION_FULL.match(text):
            seconds = sum(float(amount) * DURATION_UNITS[unit] for amount, unit in DURATION_PART.findall(text))
            return seconds, "duration"
        number = self._number(text)
        if number is not None:
            if number < 0:
                return None, None
            if forced == "delta":
                return float(number), "delta"
            if number >= 1e12:
                number = number / 1000
            if number >= 1e9:
                return (number - now if now is not None else None), "epoch"
            return float(number), "delta"
        epoch = self._http_date(text)
        if epoch is not None:
            return (epoch - now if now is not None else None), "date"
        return None, None

    def _new_group(self) -> Dict[str, Any]:
        return {
            "limit": None,
            "remaining": None,
            "used": None,
            "reset": None,
            "reset_kind": None,
            "window": None,
            "invalid": [],
            "conventions": {},
        }

    def _collect_headers(self, headers: Dict[str, str], analysis: RateLimitAnalysis, now: Optional[float]) -> None:
        for name, value in headers.items():
            if name == "x-shopify-shop-api-call-limit":
                self._collect_shopify(name, value, analysis)
                continue
            if name == "x-envoy-ratelimited":
                analysis.header_names.append(name)
                analysis.vendors.append("Envoy rate limit filter")
                continue
            match = RATE_LIMIT_NAME.match(name)
            if not match:
                continue
            analysis.header_names.append(name)
            if name.startswith("x-ms-ratelimit"):
                analysis.vendors.append("Azure Resource Manager style limits")
            elif not name.startswith("x-"):
                analysis.vendors.append("IETF RateLimit header fields")

            rest = match.group("rest")
            if rest is None:
                self._collect_structured(value, analysis)
                continue

            tokens = rest.split("-")
            field = tokens[0]
            modifiers = tokens[1:]

            if field in IDENTITY_FIELDS:
                analysis.identity_headers.append(name)
                continue
            if field in INFO_FIELDS:
                self._collect_info_field(name, field, value, analysis, now)
                continue
            if field not in COUNTER_FIELDS:
                continue

            dimension = "-".join(token for token in modifiers if token != "after")
            group = analysis.groups.setdefault(dimension, self._new_group())
            if dimension in DIMENSION_WINDOWS and group["window"] is None:
                group["window"] = DIMENSION_WINDOWS[dimension]
            if field == "limit" and dimension in DIMENSION_WINDOWS:
                analysis.vendors.append("Kong style per-window counters")
            if dimension in ("requests", "tokens"):
                analysis.vendors.append("OpenAI style request/token counters")

            convention = "legacy" if name.startswith("x-") else "ietf"
            self._apply_field(name, field, value, group, convention, "after" in modifiers, now)

    def _collect_info_field(self, name: str, field: str, value: str, analysis: RateLimitAnalysis, now: Optional[float]) -> None:
        if field in ("burst", "replenish", "requested"):
            analysis.vendors.append("Spring Cloud Gateway RequestRateLimiter")
        elif field == "resource":
            analysis.vendors.append("GitHub style resource buckets")
        elif field in ("bucket", "global"):
            analysis.vendors.append("Discord style bucket headers")
        elif field == "retry" and analysis.retry_after is None:
            self._set_retry(name, value, analysis, now)

    def _collect_shopify(self, name: str, value: str, analysis: RateLimitAnalysis) -> None:
        analysis.header_names.append(name)
        analysis.vendors.append("Shopify style call limit")
        match = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*$", value)
        group = analysis.groups.setdefault("", self._new_group())
        if not match:
            group["invalid"].append(name)
            return
        used, limit = int(match.group(1)), int(match.group(2))
        group["used"] = used
        group["limit"] = limit
        group["remaining"] = limit - used

    def _collect_structured(self, value: str, analysis: RateLimitAnalysis) -> None:
        group = analysis.groups.setdefault("", self._new_group())
        limit = re.search(r"(?:\blimit|\bq)\s*=\s*(\d+)", value, re.I)
        remaining = re.search(r"(?:\bremaining|\br)\s*=\s*(\d+)", value, re.I)
        reset = re.search(r"(?:\breset|\bt)\s*=\s*(\d+)", value, re.I)
        if not (limit or remaining or reset):
            group["invalid"].append("ratelimit")
            return
        conventions = group["conventions"].setdefault("ietf", {})
        if limit:
            group["limit"] = int(limit.group(1))
            conventions["limit"] = group["limit"]
        if remaining:
            group["remaining"] = int(remaining.group(1))
            conventions["remaining"] = group["remaining"]
        if reset:
            group["reset"] = float(reset.group(1))
            group["reset_kind"] = "delta"

    def _apply_field(self, name: str, field: str, value: str, group: Dict[str, Any], convention: str, after: bool, now: Optional[float]) -> None:
        if field == "policy":
            self._apply_policy(value, group, convention)
            return
        if field == "reset":
            seconds, kind = self._parse_reset(value, now, "delta" if after else None)
            if kind is None:
                group["invalid"].append(name)
                return
            group["reset"] = seconds
            group["reset_kind"] = kind
            return
        number = self._number(value)
        if number is None:
            group["invalid"].append(name)
            return
        group[field] = number
        if field in ("limit", "remaining"):
            group["conventions"].setdefault(convention, {})[field] = number

    def _apply_policy(self, value: str, group: Dict[str, Any], convention: str) -> None:
        quota = re.search(r"\bq\s*=\s*(\d+)", value) or re.search(r"(?:^|[\s,\"])(\d+)\s*;", value)
        window = re.search(r"\bw\s*=\s*(\d+)", value)
        if quota and group["limit"] is None:
            group["limit"] = int(quota.group(1))
            group["conventions"].setdefault(convention, {})["limit"] = group["limit"]
        if window:
            group["window"] = int(window.group(1))

    def _collect_retry_after(self, headers: Dict[str, str], analysis: RateLimitAnalysis, now: Optional[float]) -> None:
        for name in RETRY_HEADERS:
            raw = headers.get(name)
            if raw is not None:
                self._set_retry(name, raw, analysis, now)
                return
        for name in RETRY_MS_HEADERS:
            raw = headers.get(name)
            if raw is None:
                continue
            number = self._number(raw)
            analysis.retry_after_header = name
            analysis.retry_after = raw
            analysis.retry_after_valid = number is not None and number >= 0
            analysis.retry_after_seconds = number / 1000 if analysis.retry_after_valid else None
            return

    def _set_retry(self, name: str, raw: str, analysis: RateLimitAnalysis, now: Optional[float]) -> None:
        analysis.retry_after_header = name
        analysis.retry_after = raw
        number = self._number(raw)
        if number is not None:
            analysis.retry_after_valid = number >= 0
            analysis.retry_after_seconds = float(number) if number >= 0 else None
            return
        epoch = self._http_date(raw.strip())
        if epoch is None:
            analysis.retry_after_valid = False
            return
        analysis.retry_after_valid = True
        analysis.retry_after_seconds = max(0.0, epoch - now) if now is not None else None

    def _build_issues(self, response: HTTPResponse, analysis: RateLimitAnalysis, host: str) -> None:
        status = response.status_code
        issues = analysis.issues
        groups = analysis.groups
        has_signal = bool(analysis.header_names) or analysis.retry_after is not None

        if status == 429:
            issues.append(("INFO", "HTTP 429", "Request was throttled; rate limiting is actively enforced on this endpoint"))
            has_reset = any(group["reset_kind"] is not None for group in groups.values())
            if analysis.retry_after is None and not has_reset:
                issues.append((
                    "LOW",
                    "Retry-After",
                    "429 response carries neither Retry-After nor a reset hint; clients cannot back off correctly, which encourages retry storms",
                ))

        if analysis.retry_after is not None:
            label = _display(analysis.retry_after_header or "retry-after")
            if analysis.retry_after_valid is False:
                issues.append(("LOW", label, "Value is neither a non-negative number of seconds nor an HTTP date; clients will ignore it"))
            elif analysis.retry_after_seconds is not None and analysis.retry_after_seconds > MAX_REASONABLE_RETRY_SECONDS:
                issues.append(("INFO", label, "Retry delay exceeds 24 hours; clients and intermediaries may treat the resource as unavailable rather than throttled"))
            elif status in (429, 503):
                issues.append(("OK", label, "Retry delay is present and valid"))

        for name in analysis.identity_headers:
            issues.append((
                "LOW",
                _display(name),
                "Header exposes the identifier the limit is keyed on (client, user, key or IP); it can leak account or API-key data and shows which identifier to rotate to evade the limit",
            ))

        for dimension, group in sorted(groups.items()):
            self._check_group(status, dimension, group, analysis)

        if analysis.vendors:
            analysis.hint = "Implementation hint: " + ", ".join(sorted(set(analysis.vendors)))

        if not has_signal and status != 429 and not 300 <= status < 400:
            if analysis.is_auth_endpoint:
                issues.append((
                    "LOW",
                    "Rate Limit",
                    "No rate-limit headers on an authentication-related endpoint; brute-force throttling cannot be confirmed from this response (a limit may still be enforced without advertising it)",
                ))
            elif analysis.is_api_endpoint:
                issues.append(("INFO", "Rate Limit", "No rate-limit headers on an API response; the quota is not advertised to clients"))

        if status != 429:
            self._track_counters(host, analysis)

    def _check_group(self, status: int, dimension: str, group: Dict[str, Any], analysis: RateLimitAnalysis) -> None:
        issues = analysis.issues
        label = f"Rate Limit [{dimension}]" if dimension else "Rate Limit"
        limit = group["limit"]
        remaining = group["remaining"]
        window = group["window"]

        for name in group["invalid"]:
            issues.append(("LOW", _display(name), "Value could not be parsed; clients cannot interpret it"))

        if limit is not None and limit <= 0:
            issues.append(("LOW", label, "Advertised limit is zero or negative; every request would be rejected or the value is bogus"))

        if remaining is not None and remaining < 0:
            issues.append(("LOW", label, "Remaining quota is negative; the counter is inconsistent"))

        if limit is not None and remaining is not None and remaining > limit:
            issues.append(("LOW", label, "Remaining quota exceeds the advertised limit; the counters are inconsistent"))

        if remaining == 0 and status != 429:
            issues.append(("INFO", label, "Quota is exhausted but the request was not rejected; the next request is likely to be throttled"))

        if remaining is not None and limit is None:
            issues.append(("INFO", label, "Remaining quota is reported without a limit; clients cannot compute the total budget"))

        if (limit is not None or remaining is not None) and group["reset_kind"] is None and not any("reset" in item for item in group["invalid"]):
            issues.append(("INFO", label, "No reset information accompanies the quota; clients cannot tell when it replenishes"))

        reset = group["reset"]
        if reset is not None and group["reset_kind"] in ("epoch", "date") and reset < 0:
            issues.append(("LOW", label, "Reset timestamp is already in the past relative to the response Date; the value is stale or clocks are skewed"))

        if reset is not None and window and group["reset_kind"] in ("delta", "duration") and reset > window * 1.01 + 1:
            issues.append(("LOW", label, "Reset time exceeds the policy window; the advertised values contradict each other"))

        conventions = group["conventions"]
        if "legacy" in conventions and "ietf" in conventions:
            legacy_limit = conventions["legacy"].get("limit")
            ietf_limit = conventions["ietf"].get("limit")
            if legacy_limit is not None and ietf_limit is not None and legacy_limit != ietf_limit:
                issues.append(("LOW", label, "Legacy X-RateLimit-* and standard RateLimit-* headers advertise different limits"))

        if analysis.is_auth_endpoint and limit and limit > 0 and window:
            per_minute = limit * 60 / window
            if per_minute > PER_MINUTE_LOW:
                severity = "MEDIUM" if per_minute > PER_MINUTE_MEDIUM else "LOW"
                issues.append((
                    severity,
                    label,
                    f"Limit of {_fmt(limit)} requests per {_fmt(window)}s on an authentication-related endpoint allows about {per_minute:.0f} attempts per minute; a much tighter limit is advisable against brute force and credential stuffing",
                ))

    def _track_counters(self, host: str, analysis: RateLimitAnalysis) -> None:
        for dimension, group in analysis.groups.items():
            remaining = group["remaining"]
            if remaining is None:
                continue
            state = self._counters.setdefault((host, dimension), {"values": [], "reported": False})
            if state["reported"]:
                continue
            state["values"].append(remaining)
            if len(state["values"]) >= MIN_SAMPLES_FOR_STATIC and len(set(state["values"])) == 1:
                state["reported"] = True
                label = f"Rate Limit [{dimension}]" if dimension else "Rate Limit"
                analysis.issues.append((
                    "LOW",
                    label,
                    f"Remaining counter stayed at the same value across {MIN_SAMPLES_FOR_STATIC} responses from this host; the quota may not be tracked per request, or the headers may be static or cached",
                ))
            elif len(state["values"]) >= MIN_SAMPLES_FOR_STATIC:
                state["reported"] = True

    def _emit(self, analysis: RateLimitAnalysis, result: ModuleResult) -> None:
        if not analysis.issues and (analysis.header_names or analysis.retry_after is not None):
            result.add_finding("OK", "Rate Limit", self._ok_detail(analysis))
        for severity, header, detail in analysis.issues:
            result.add_finding(severity, header, detail)
        if analysis.hint:
            result.add_finding("INFO", "Rate Limit", analysis.hint)

    def _ok_detail(self, analysis: RateLimitAnalysis) -> str:
        for group in analysis.groups.values():
            if group["limit"] is not None and group["window"]:
                return f"Rate-limit headers are present and consistent (limit {_fmt(group['limit'])} per {_fmt(group['window'])}s)"
            if group["limit"] is not None:
                return f"Rate-limit headers are present and consistent (limit {_fmt(group['limit'])})"
        return "Rate-limit headers are present and consistent"
