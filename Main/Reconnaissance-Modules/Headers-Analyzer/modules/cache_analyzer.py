from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


SENSITIVE_PATH_KEYWORDS = [
    "account", "profile", "login", "logout", "signin", "signup",
    "session", "token", "auth", "admin", "dashboard", "settings",
    "billing", "payment", "checkout", "cart", "order", "invoice",
    "wallet", "user", "users", "me", "api/user", "api/account",
    "private", "secure", "password", "reset", "verify", "mfa", "otp",
]

CACHEABLE_CONTENT_TYPES = ["json", "xml", "text/html", "text/plain"]

STATIC_ASSET_CONTENT_TYPES = [
    "image/", "font/", "text/css", "javascript", "video/", "audio/",
]


class CacheAnalysis:
    def __init__(self):
        self.cache_control: Optional[str] = None
        self.pragma: Optional[str] = None
        self.expires: Optional[str] = None
        self.etag: Optional[str] = None
        self.last_modified: Optional[str] = None
        self.vary: Optional[str] = None
        self.age: Optional[str] = None
        self.directives: Dict[str, Optional[str]] = {}
        self.is_sensitive: bool = False
        self.is_static_asset: bool = False
        self.has_auth_context: bool = False
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cache_control": self.cache_control,
            "pragma": self.pragma,
            "expires": self.expires,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "vary": self.vary,
            "age": self.age,
            "directives": self.directives,
            "is_sensitive": self.is_sensitive,
            "is_static_asset": self.is_static_asset,
            "has_auth_context": self.has_auth_context,
            "issues": self.issues,
        }


class CacheAnalyzerModule(BaseHeaderModule):
    name = "Cache Control Analyzer"
    description = "Analyzes caching headers to detect sensitive responses that may be stored by browsers or shared caches."

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        analysis = self.analyze(response)
        self._emit(analysis, result)
        result.metadata["cache"] = analysis.to_dict()
        return result

    def analyze(self, response: HTTPResponse) -> CacheAnalysis:
        analysis = CacheAnalysis()
        headers = response.headers

        analysis.cache_control = self._get_header(headers, "Cache-Control")
        analysis.pragma = self._get_header(headers, "Pragma")
        analysis.expires = self._get_header(headers, "Expires")
        analysis.etag = self._get_header(headers, "ETag")
        analysis.last_modified = self._get_header(headers, "Last-Modified")
        analysis.vary = self._get_header(headers, "Vary")
        analysis.age = self._get_header(headers, "Age")

        if analysis.cache_control:
            analysis.directives = self._parse_cache_control(analysis.cache_control)

        content_type = self._get_header(headers, "Content-Type") or ""
        analysis.is_static_asset = any(marker in content_type.lower() for marker in STATIC_ASSET_CONTENT_TYPES)
        analysis.is_sensitive = self._looks_sensitive(response, content_type)
        analysis.has_auth_context = self._get_header(response.request_headers, "Authorization") is not None \
            or self._get_header(response.request_headers, "Cookie") is not None \
            or self._get_header(headers, "Set-Cookie") is not None

        if analysis.is_static_asset and not analysis.is_sensitive:
            return analysis

        self._build_issues(analysis)
        return analysis

    def _parse_cache_control(self, header_value: str) -> Dict[str, Optional[str]]:
        directives: Dict[str, Optional[str]] = {}
        for part in header_value.split(","):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                key, _, val = part.partition("=")
                directives[key.strip().lower()] = val.strip().strip('"')
            else:
                directives[part.lower()] = None
        return directives

    def _looks_sensitive(self, response: HTTPResponse, content_type: str) -> bool:
        path = urlparse(response.url).path.lower()
        for keyword in SENSITIVE_PATH_KEYWORDS:
            if keyword in path:
                return True
        if "json" in content_type.lower() and self._get_header(response.request_headers, "Authorization") is not None:
            return True
        return False

    def _build_issues(self, analysis: CacheAnalysis):
        directives = analysis.directives

        if analysis.cache_control is None:
            if analysis.is_sensitive:
                analysis.issues.append((
                    "MEDIUM",
                    "No Cache-Control header on a response that appears to contain sensitive or authenticated data",
                ))
            else:
                analysis.issues.append(("INFO", "No Cache-Control header present"))

        if directives:
            has_no_store = "no-store" in directives
            has_no_cache = "no-cache" in directives
            has_public = "public" in directives
            has_private = "private" in directives
            max_age = directives.get("max-age")

            if analysis.is_sensitive and has_public:
                analysis.issues.append((
                    "HIGH",
                    "public directive on a sensitive response — shared caches and proxies may store this content",
                ))

            if analysis.is_sensitive and not has_no_store:
                if has_private or has_no_cache:
                    analysis.issues.append((
                        "LOW",
                        "Sensitive response is not marked Cache-Control: no-store; current directives only limit shared-cache storage, not local storage",
                    ))
                elif max_age is not None:
                    try:
                        if int(max_age) > 0:
                            analysis.issues.append((
                                "MEDIUM",
                                f"Sensitive response allows caching for {max_age}s without no-store",
                            ))
                    except ValueError:
                        pass

            if has_public and has_private:
                analysis.issues.append(("INFO", "Cache-Control combines conflicting 'public' and 'private' directives"))

            if has_no_store and has_public:
                analysis.issues.append(("INFO", "Cache-Control combines conflicting 'no-store' and 'public' directives"))

        if analysis.pragma and "no-cache" in analysis.pragma.lower() and analysis.cache_control is None:
            analysis.issues.append((
                "INFO",
                "Relying on Pragma: no-cache without Cache-Control — Pragma is a legacy HTTP/1.0 directive not honored by all clients and intermediaries",
            ))

        if analysis.is_sensitive and (analysis.etag or analysis.last_modified) and directives.get("no-store") is None:
            analysis.issues.append((
                "LOW",
                "Validator headers (ETag/Last-Modified) present on a sensitive response — conditional requests may keep a cached copy available",
            ))

        if analysis.has_auth_context and analysis.vary:
            vary_lower = analysis.vary.lower()
            if "authorization" not in vary_lower and "cookie" not in vary_lower and vary_lower.strip() != "*":
                analysis.issues.append((
                    "LOW",
                    "Response varies by authenticated context but Vary header does not include Authorization/Cookie — risk of shared-cache mixing between users",
                ))

        if analysis.is_sensitive and analysis.age is not None:
            analysis.issues.append(("MEDIUM", f"Age header ({analysis.age}s) indicates a sensitive response was served from a shared cache"))

    def _emit(self, analysis: CacheAnalysis, result: ModuleResult):
        if not analysis.issues:
            if analysis.is_static_asset:
                result.add_finding("OK", "Cache-Control", "Static asset response, caching behavior not evaluated")
            else:
                result.add_finding("OK", "Cache-Control", "No caching issues detected")
            return
        for severity, detail in analysis.issues:
            result.add_finding(severity, "Cache-Control", detail)
