from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

OPEN_REDIRECT_PARAM_NAMES = [
    "redirect", "redirect_url", "redirect_uri", "redirecturl",
    "url", "next", "next_url", "continue", "return", "return_to",
    "returnto", "return_url", "callback", "dest", "destination",
    "redir", "target", "rurl", "out", "view", "goto", "go",
    "forward", "forward_url", "link", "image_url", "data", "u",
]


class RedirectAnalysis:
    def __init__(self):
        self.is_redirect: bool = False
        self.status_code: int = 0
        self.location: Optional[str] = None
        self.location_is_absolute: bool = False
        self.location_is_protocol_relative: bool = False
        self.target_host: Optional[str] = None
        self.source_host: Optional[str] = None
        self.scheme_downgrade: bool = False
        self.cross_host: bool = False
        self.reflected_param: Optional[str] = None
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_redirect": self.is_redirect,
            "status_code": self.status_code,
            "location": self.location,
            "location_is_absolute": self.location_is_absolute,
            "location_is_protocol_relative": self.location_is_protocol_relative,
            "target_host": self.target_host,
            "source_host": self.source_host,
            "scheme_downgrade": self.scheme_downgrade,
            "cross_host": self.cross_host,
            "reflected_param": self.reflected_param,
            "issues": self.issues,
        }


class RedirectAnalyzerModule(BaseHeaderModule):
    name = "Redirect Analyzer"
    description = "Analyzes HTTP redirect responses for open-redirect indicators, protocol downgrades, and cross-host targets."

    def applies_to(self, response: HTTPResponse) -> bool:
        if response.status_code in REDIRECT_STATUS_CODES:
            return True
        return self._get_header(response.headers, "Location") is not None

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        analysis = self.analyze(response)
        self._emit(analysis, result)
        result.metadata["redirect"] = analysis.to_dict()
        return result

    def analyze(self, response: HTTPResponse) -> RedirectAnalysis:
        analysis = RedirectAnalysis()
        analysis.status_code = response.status_code

        location = self._get_header(response.headers, "Location")
        if location is None:
            return analysis

        location = location.strip()
        analysis.location = location
        analysis.is_redirect = response.status_code in REDIRECT_STATUS_CODES

        source_parsed = urlparse(response.url)
        analysis.source_host = source_parsed.netloc or None

        if location.startswith("//"):
            analysis.location_is_protocol_relative = True
            target_parsed = urlparse(f"{source_parsed.scheme}:{location}")
        elif location.startswith("http://") or location.startswith("https://"):
            analysis.location_is_absolute = True
            target_parsed = urlparse(location)
        else:
            target_parsed = None

        if target_parsed is not None:
            analysis.target_host = target_parsed.netloc or None
            if analysis.source_host and analysis.target_host and analysis.target_host.lower() != analysis.source_host.lower():
                analysis.cross_host = True
            if source_parsed.scheme == "https" and target_parsed.scheme == "http":
                analysis.scheme_downgrade = True

        reflected_param = self._find_reflected_param(source_parsed, location)
        if reflected_param:
            analysis.reflected_param = reflected_param

        self._build_issues(analysis)
        return analysis

    def _find_reflected_param(self, source_parsed, location: str) -> Optional[str]:
        query_pairs = parse_qsl(source_parsed.query, keep_blank_values=True)
        if not query_pairs:
            return None

        location_lower = location.lower()
        for key, value in query_pairs:
            if not value or len(value) < 4:
                continue
            key_lower = key.lower()
            value_lower = value.lower().strip()
            if key_lower not in OPEN_REDIRECT_PARAM_NAMES:
                continue
            comparable = value_lower.lstrip("/")
            if comparable and comparable in location_lower:
                return key
        return None

    def _build_issues(self, analysis: RedirectAnalysis):
        if not analysis.is_redirect:
            analysis.issues.append(("INFO", f"Location header present on a non-redirect status code ({analysis.status_code})"))

        if analysis.reflected_param and analysis.cross_host:
            analysis.issues.append((
                "HIGH",
                f"Redirect target appears controlled by request parameter '{analysis.reflected_param}' and points to a different host ('{analysis.target_host}') — possible open redirect",
            ))
        elif analysis.reflected_param:
            analysis.issues.append((
                "MEDIUM",
                f"Redirect target appears controlled by request parameter '{analysis.reflected_param}' — verify it cannot be pointed at an external host",
            ))

        if analysis.location_is_protocol_relative:
            analysis.issues.append((
                "MEDIUM",
                f"Protocol-relative redirect target ('{analysis.location}') resolves to an attacker-influenceable scheme",
            ))

        if analysis.scheme_downgrade:
            analysis.issues.append((
                "HIGH",
                f"Redirect downgrades from HTTPS to HTTP (target: '{analysis.target_host}') — traffic after the redirect is unencrypted",
            ))

        if analysis.cross_host and not analysis.reflected_param and not analysis.scheme_downgrade:
            analysis.issues.append((
                "LOW",
                f"Redirect points to a different host ('{analysis.target_host}') than the requested host ('{analysis.source_host}')",
            ))

        if analysis.status_code == 300:
            analysis.issues.append(("INFO", "Status 300 Multiple Choices is rarely used and may indicate a misconfigured or custom redirect handler"))

    def _emit(self, analysis: RedirectAnalysis, result: ModuleResult):
        if analysis.location is None:
            result.add_finding("OK", "Redirect", "No Location header present")
            return
        if not analysis.issues:
            result.add_finding("OK", "Redirect", f"Redirect to '{analysis.location}' shows no indicators of open-redirect or downgrade issues")
            return
        for severity, detail in analysis.issues:
            result.add_finding(severity, "Location", detail)
