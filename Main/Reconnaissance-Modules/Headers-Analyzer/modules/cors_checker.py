from typing import Dict, List, Optional, Tuple, Any
import re

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


CORS_SAFE_METHODS = ["GET", "HEAD", "POST"]
CORS_SAFE_HEADERS = ["Accept", "Accept-Language", "Content-Language", "Content-Type"]

DANGEROUS_ORIGIN_PATTERNS = [
    re.compile(r".*\.\w+\.\w+$"),
    re.compile(r"https?://\*"),
    re.compile(r"\*\.\w+$"),
]


class CORSAnalysis:
    def __init__(self):
        self.allow_origin_header_present: bool = False
        self.allow_origin_value: Optional[str] = None
        self.allow_credentials: bool = False
        self.allow_methods: Optional[str] = None
        self.allow_headers: Optional[str] = None
        self.expose_headers: Optional[str] = None
        self.max_age: Optional[str] = None
        self.vary_origin: bool = False
        self.reflects_origin: bool = False
        self.wildcard_origin: bool = False
        self.wildcard_with_credentials: bool = False
        self.null_origin_allowed: bool = False
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow_origin_header_present": self.allow_origin_header_present,
            "allow_origin_value": self.allow_origin_value,
            "allow_credentials": self.allow_credentials,
            "allow_methods": self.allow_methods,
            "allow_headers": self.allow_headers,
            "expose_headers": self.expose_headers,
            "max_age": self.max_age,
            "vary_origin": self.vary_origin,
            "reflects_origin": self.reflects_origin,
            "wildcard_origin": self.wildcard_origin,
            "wildcard_with_credentials": self.wildcard_with_credentials,
            "null_origin_allowed": self.null_origin_allowed,
            "issues": self.issues,
        }


class CORSModule(BaseHeaderModule):
    name = "CORS Misconfiguration Analyzer"
    description = "Analyzes Cross-Origin Resource Sharing (CORS) headers for misconfigurations that enable cross-origin data theft."

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        headers = response.headers

        analysis = self.check_cors_headers(headers, response.request_headers)
        self._emit_cors(analysis, result)

        result.metadata["cors"] = analysis.to_dict()
        return result

    def check_cors_headers(self, headers: Dict[str, str], request_headers: Optional[Dict[str, str]] = None) -> CORSAnalysis:
        analysis = CORSAnalysis()

        acao = self._get_header(headers, "Access-Control-Allow-Origin")
        acac = self._get_header(headers, "Access-Control-Allow-Credentials")
        acam = self._get_header(headers, "Access-Control-Allow-Methods")
        acah = self._get_header(headers, "Access-Control-Allow-Headers")
        aceh = self._get_header(headers, "Access-Control-Expose-Headers")
        acma = self._get_header(headers, "Access-Control-Max-Age")
        vary = self._get_header(headers, "Vary")

        if acao is None:
            analysis.allow_origin_header_present = False
            analysis.issues.append(("INFO", "Access-Control-Allow-Origin header is absent — CORS is not configured (default same-origin)"))
            return analysis

        analysis.allow_origin_header_present = True
        analysis.allow_origin_value = acao.strip()

        if vary and "origin" in vary.lower():
            analysis.vary_origin = True

        if acao.strip() == "*":
            analysis.wildcard_origin = True
            analysis.issues.append(("MEDIUM", "Access-Control-Allow-Origin: * — any domain can read responses cross-origin"))

        if acao.strip().lower() == "null":
            analysis.null_origin_allowed = True
            analysis.issues.append(("HIGH", "Access-Control-Allow-Origin: null — sandboxed iframes and data: URIs can bypass CORS"))

        if acao.strip().startswith("http://") or acao.strip().startswith("https://"):
            if self._is_dangerous_origin(acao.strip()):
                analysis.reflects_origin = True
                analysis.issues.append(("MEDIUM", f"Access-Control-Allow-Origin reflects or allows trusted-origin overlap: '{acao.strip()}'"))

        if acac and acac.strip().lower() == "true":
            analysis.allow_credentials = True
            if analysis.wildcard_origin:
                analysis.wildcard_with_credentials = True
                analysis.issues.append(("HIGH", "Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: * — credentials exposed to any origin (spec-invalid, but some browsers still process it)"))
            else:
                analysis.issues.append(("LOW", "Access-Control-Allow-Credentials: true — ensures cookies/auth headers are only sent when origin is explicitly trusted"))

        if analysis.allow_credentials and not analysis.vary_origin and not analysis.wildcard_origin:
            analysis.issues.append(("LOW", "Vary: Origin header is recommended when credentials are allowed with a dynamic origin"))

        if acam:
            analysis.allow_methods = acam
            methods = [m.strip() for m in acam.split(",")]
            unsafe_methods = [m for m in methods if m.upper() not in CORS_SAFE_METHODS]
            if unsafe_methods:
                analysis.issues.append(("INFO", f"Non-basic CORS methods allowed: {', '.join(unsafe_methods)}"))

        if acah:
            analysis.allow_headers = acah
            if acah.strip() == "*":
                analysis.issues.append(("INFO", "Access-Control-Allow-Headers: * — any custom header accepted cross-origin"))

        if aceh:
            analysis.expose_headers = aceh
            sensitive_exposed = self._find_sensitive_exposed_headers(aceh)
            if sensitive_exposed:
                analysis.issues.append(("MEDIUM", f"Access-Control-Expose-Headers exposes potentially sensitive headers: {', '.join(sensitive_exposed)}"))

        if acma:
            analysis.max_age = acma
            try:
                max_age_int = int(acma.strip())
                if max_age_int > 86400:
                    analysis.issues.append(("LOW", f"Access-Control-Max-Age is {max_age_int}s — preflight caching may be unnecessarily long"))
            except ValueError:
                pass

        if analysis.wildcard_with_credentials:
            analysis.issues.append(("CRITICAL", "Wildcard origin with credentials: an attacker can perform authenticated cross-origin requests from any domain"))

        is_origin_reflected = self._check_origin_reflection(request_headers or {}, acao.strip())
        if is_origin_reflected and analysis.allow_credentials:
            analysis.issues.append(("CRITICAL", "Origin reflection with credentials enabled — attacker-supplied Origin header is echoed, allowing credential theft"))

        return analysis

    def _is_dangerous_origin(self, origin: str) -> bool:
        parsed = re.match(r"https?://([^/:]+)", origin)
        if not parsed:
            return False
        hostname = parsed.group(1)

        if re.match(r"^[\w.-]+\.\w+$", hostname):
            parts = hostname.split(".")
            if len(parts) <= 2:
                return True

        for pattern in DANGEROUS_ORIGIN_PATTERNS:
            if pattern.match(origin):
                return True

        dangerous_tlds = [".com", ".org", ".net", ".io", ".app", ".dev"]
        for tld in dangerous_tlds:
            if hostname.endswith(tld) and hostname.count(".") == 1:
                return True

        return False

    def _check_origin_reflection(self, request_headers: Dict[str, str], acao_value: str) -> bool:
        origin = self._get_header(request_headers, "Origin")
        if origin is None:
            return False
        origin_clean = origin.strip().rstrip("/")
        acao_clean = acao_value.strip().rstrip("/")
        return origin_clean == acao_clean

    def _find_sensitive_exposed_headers(self, expose_value: str) -> List[str]:
        sensitive = []
        exposed = [h.strip().lower() for h in expose_value.split(",")]
        sensitive_patterns = [
            "token", "auth", "secret", "key", "session", "cookie",
            "jwt", "api", "csrf", "xsrf", "set-cookie", "authorization",
            "x-auth", "x-token", "x-api-key", "x-session",
        ]
        for header in exposed:
            for pattern in sensitive_patterns:
                if pattern in header:
                    sensitive.append(header)
                    break
        return sensitive

    def _emit_cors(self, analysis: CORSAnalysis, result: ModuleResult):
        if not analysis.allow_origin_header_present:
            result.add_finding("OK", "CORS", "No CORS headers present — same-origin policy enforced by default")
            return
        if not analysis.issues:
            result.add_finding("OK", "CORS", "CORS configuration appears safe")
            return
        for sev, detail in analysis.issues:
            result.add_finding(sev, "CORS", detail)
