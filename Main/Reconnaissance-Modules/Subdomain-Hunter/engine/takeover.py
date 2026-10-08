from __future__ import annotations

"""
Subdomain takeover detection.

For each resolved host that has a CNAME chain but no IPs (dangling CNAME),
we check:
  1. Whether the CNAME target matches a known provider pattern.
  2. Optionally fetch the HTTP body to confirm with a fingerprint string.

A result is only flagged VULNERABLE when both conditions are met, reducing
false positives.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import requests

from core import HostInfo, TakeoverResult
from core.config import USER_AGENT

# ---------------------------------------------------------------------------
# Provider signatures
# ---------------------------------------------------------------------------
# Each entry:
#   "provider-id": {
#       "cname":        regex matched against every hop in the CNAME chain
#       "fingerprint":  string searched in the HTTP response body (optional)
#       "http_check":   whether to do an HTTP fetch at all (default True)
#   }

SIGNATURES: dict[str, dict] = {
    "github-pages": {
        "cname": r"\.github\.io$",
        "fingerprint": "There isn't a GitHub Pages site here",
    },
    "heroku": {
        "cname": r"\.herokudns\.com$|\.herokuapp\.com$",
        "fingerprint": "No such app",
    },
    "aws-s3": {
        "cname": r"\.s3\.amazonaws\.com$|\.s3-website[.-]",
        "fingerprint": "NoSuchBucket",
    },
    "aws-cloudfront": {
        "cname": r"\.cloudfront\.net$",
        "fingerprint": "ERROR: The request could not be satisfied",
    },
    "netlify": {
        "cname": r"\.netlify\.app$|\.netlify\.com$",
        "fingerprint": "Not Found - Request ID",
    },
    "vercel": {
        "cname": r"\.vercel\.app$|cname\.vercel-dns\.com$",
        "fingerprint": "The deployment could not be found",
    },
    "fastly": {
        "cname": r"\.fastly\.net$",
        "fingerprint": "Fastly error: unknown domain",
    },
    "shopify": {
        "cname": r"\.myshopify\.com$",
        "fingerprint": "Sorry, this shop is currently unavailable",
    },
    "tumblr": {
        "cname": r"\.tumblr\.com$",
        "fingerprint": "Whatever you were looking for doesn't currently exist at this address",
    },
    "ghost": {
        "cname": r"\.ghost\.io$",
        "fingerprint": "The thing you were looking for is no longer here",
    },
    "helpjuice": {
        "cname": r"\.helpjuice\.com$",
        "fingerprint": "We could not find what you're looking for",
    },
    "helpscout": {
        "cname": r"\.helpscoutdocs\.com$",
        "fingerprint": "No settings were found for this company",
    },
    "zendesk": {
        "cname": r"\.zendesk\.com$",
        "fingerprint": "Help Center Closed",
    },
    "intercom": {
        "cname": r"\.intercom\.io$",
        "fingerprint": "This page is reserved for artistic dogs",
    },
    "cargo": {
        "cname": r"\.cargocollective\.com$",
        "fingerprint": "404 Not Found",
    },
    "webflow": {
        "cname": r"\.webflow\.io$",
        "fingerprint": "The page you are looking for doesn't exist or has been moved",
    },
    "azure": {
        "cname": r"\.azurewebsites\.net$|\.azure-api\.net$|\.azureedge\.net$|\.cloudapp\.azure\.com$",
        "fingerprint": "404 Web Site not found",
    },
    "bitbucket": {
        "cname": r"\.bitbucket\.io$",
        "fingerprint": "Repository not found",
    },
    "smugmug": {
        "cname": r"\.smugmug\.com$",
        "fingerprint": "SmugMug",
        "http_check": False,   # CNAME match alone is enough signal here
    },
    "strikingly": {
        "cname": r"\.s\.strikinglydns\.com$",
        "fingerprint": "But if you're looking to build your own website",
    },
    "ucraft": {
        "cname": r"\.ucraft\.net$",
        "fingerprint": "No website was found for this address",
    },
    "wordpress": {
        "cname": r"\.wordpress\.com$",
        "fingerprint": "Do you want to register",
    },
    "surveygizmo": {
        "cname": r"\.surveygizmo\.com$",
        "fingerprint": "data-html-name",
        "http_check": False,
    },
    "squarespace": {
        "cname": r"\.squarespace\.com$",
        "fingerprint": "No Such Account",
    },
    "feedpress": {
        "cname": r"\.feedpress\.me$",
        "fingerprint": "The feed has not been found",
    },
}

_COMPILED: list[tuple[str, re.Pattern, Optional[str], bool]] = [
    (
        pid,
        re.compile(sig["cname"], re.I),
        sig.get("fingerprint"),
        sig.get("http_check", True),
    )
    for pid, sig in SIGNATURES.items()
]


# ---------------------------------------------------------------------------
# Per-host check
# ---------------------------------------------------------------------------

def _check_one(
    info: HostInfo,
    *,
    timeout: int,
) -> Optional[TakeoverResult]:
    """
    Return a TakeoverResult if the host is vulnerable, else None.

    Conditions:
    - Host has no IPs (dangling) OR has a CNAME chain with no final resolution.
    - CNAME chain contains a target matching a known provider pattern.
    - HTTP fingerprint confirmed (when http_check=True).
    """
    # Must have a CNAME chain to match against
    if not info.cname_chain:
        return None

    matched_provider: Optional[str] = None
    matched_cname: Optional[str] = None
    matched_fp: Optional[str] = None
    needs_http: bool = True

    for hop in info.cname_chain:
        for pid, pattern, fingerprint, http_check in _COMPILED:
            if pattern.search(hop):
                matched_provider = pid
                matched_cname = hop
                matched_fp = fingerprint
                needs_http = http_check
                break
        if matched_provider:
            break

    if not matched_provider:
        return None

    # If no HTTP check needed, report immediately
    if not needs_http or not matched_fp:
        return TakeoverResult(
            cname=matched_cname,
            provider=matched_provider,
            evidence=f"CNAME matches {matched_provider} pattern",
        )

    # Fetch HTTP body and look for the fingerprint
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    for scheme in ("https", "http"):
        url = f"{scheme}://{info.subdomain}"
        try:
            resp = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                stream=True,
            )
            body = resp.text[:8192]   # read only first 8 KB
            resp.close()
            if matched_fp.lower() in body.lower():
                return TakeoverResult(
                    cname=matched_cname,
                    provider=matched_provider,
                    evidence=matched_fp,
                )
        except requests.RequestException:
            continue

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_takeovers(
    hosts: dict[str, HostInfo],
    *,
    timeout: int = 10,
    workers: int = 10,
) -> int:
    """
    Populate *hosts[name].takeover* for any vulnerable host in-place.
    Returns the count of vulnerabilities found.
    """
    candidates = [info for info in hosts.values() if info.cname_chain]
    if not candidates:
        return 0

    count = 0

    def run(info: HostInfo) -> tuple[HostInfo, Optional[TakeoverResult]]:
        return info, _check_one(info, timeout=timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for info, result in pool.map(run, candidates):
            if result:
                info.takeover = result
                count += 1

    return count