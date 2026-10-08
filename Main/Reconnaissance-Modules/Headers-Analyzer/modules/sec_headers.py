import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


CSP_UNSAFE_SOURCES = [
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "data:",
    "http:",
    "https:",
]

CSP_HIGH_SEVERITY_SOURCES = {
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "https:",
}

CSP_WILDCARD_PATTERNS = [
    re.compile(r"(?:^|\s)\*(?:\s|$)"),
    re.compile(r"(?:^|\s)\*\.[a-z]+"),
]

CSP_REQUIRED_DIRECTIVES = [
    "default-src",
    "script-src",
    "object-src",
    "base-uri",
]

REFERRER_UNSAFE_VALUES = [
    "unsafe-url",
    "no-referrer-when-downgrade",
]

REFERRER_SAFE_VALUES = [
    "no-referrer",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
]

PERMISSIONS_SENSITIVE_FEATURES = [
    "geolocation",
    "camera",
    "microphone",
    "payment",
    "usb",
    "fullscreen",
    "accelerometer",
    "autoplay",
    "encrypted-media",
    "gyroscope",
    "magnetometer",
    "midi",
    "picture-in-picture",
    "speaker-selection",
    "sync-xhr",
    "xr-spatial-tracking",
]

FRAME_OPTIONS_VALID = ["deny", "sameorigin"]


class HSTSAnalysis:
    def __init__(self):
        self.present: bool = False
        self.max_age: Optional[int] = None
        self.include_subdomains: bool = False
        self.preload: bool = False
        self.issues: List[Tuple[str, str]] = []
        self.raw: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "max_age": self.max_age,
            "include_subdomains": self.include_subdomains,
            "preload": self.preload,
            "issues": self.issues,
            "raw": self.raw,
        }


class CSPAnalysis:
    def __init__(self):
        self.present: bool = False
        self.directives: Dict[str, Optional[str]] = {}
        self.unsafe_sources: List[str] = []
        self.missing_directives: List[str] = []
        self.wildcard_sources: List[str] = []
        self.issues: List[Tuple[str, str]] = []
        self.raw: Optional[str] = None
        self.report_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "report_only": self.report_only,
            "directives": self.directives,
            "unsafe_sources": self.unsafe_sources,
            "missing_directives": self.missing_directives,
            "wildcard_sources": self.wildcard_sources,
            "issues": self.issues,
            "raw": self.raw,
        }


class SecurityHeadersModule(BaseHeaderModule):
    name = "Security Headers Analyzer"
    description = "Analyzes core HTTP security headers for misconfigurations and missing protections."

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        headers = response.headers
        url = response.final_url

        hsts = self.check_hsts(headers, url)
        self._emit_hsts(hsts, result)

        csp = self.check_csp(headers)
        self._emit_csp(csp, result)

        self.check_frame_options(headers, result)
        self.check_content_type_options(headers, result)
        self.check_referrer_permissions(headers, result)
        self.check_xss_protection(headers, result)

        result.metadata["hsts"] = hsts.to_dict()
        result.metadata["csp"] = csp.to_dict()

        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}
        result.findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

        return result

    def check_hsts(self, headers: Dict[str, str], url: str = "") -> HSTSAnalysis:
        analysis = HSTSAnalysis()
        hsts_value = self._get_header(headers, "Strict-Transport-Security")

        is_https = url.startswith("https://") if url else True

        if not hsts_value:
            analysis.present = False
            analysis.issues.append(("HIGH", "Strict-Transport-Security header is missing"))
            return analysis

        raw_hsts_list = []
        for k, v in headers.items():
            if k.lower() == "strict-transport-security":
                raw_hsts_list.append(v)
        if len(raw_hsts_list) > 1:
            analysis.issues.append(("MEDIUM", f"Multiple Strict-Transport-Security headers detected ({len(raw_hsts_list)}); only the first is used"))

        analysis.present = True
        analysis.raw = hsts_value
        directives = self._parse_directives(hsts_value)

        max_age_str = directives.get("max-age")
        if max_age_str is None:
            analysis.issues.append(("HIGH", "HSTS max-age directive is missing"))
        else:
            try:
                max_age = int(max_age_str.strip())
                analysis.max_age = max_age
                if max_age == 0:
                    analysis.issues.append(("HIGH", "HSTS max-age is set to 0, effectively disabling HSTS"))
                elif max_age < 2592000:
                    analysis.issues.append(("MEDIUM", f"HSTS max-age is too short: {max_age}s (recommended: ≥31536000)"))
                elif max_age < 31536000:
                    analysis.issues.append(("LOW", f"HSTS max-age below recommended 1 year: {max_age}s"))
                if max_age > 63072000:
                    analysis.issues.append(("INFO", f"HSTS max-age={max_age}s exceeds 2 years; preload lists recommend ≤63072000"))
            except ValueError:
                analysis.issues.append(("HIGH", f"HSTS max-age is not a valid integer: '{max_age_str}'"))

        analysis.include_subdomains = "includesubdomains" in directives
        analysis.preload = "preload" in directives

        if not analysis.include_subdomains:
            analysis.issues.append(("LOW", "HSTS includeSubDomains directive is absent"))

        if analysis.preload and not analysis.include_subdomains:
            analysis.issues.append(("MEDIUM", "HSTS preload requires includeSubDomains to be set"))

        if not is_https and analysis.present:
            analysis.issues.append(("INFO", "HSTS header present on HTTP response (has no effect, must be HTTPS)"))

        return analysis

    def check_csp(self, headers: Dict[str, str]) -> CSPAnalysis:
        analysis = CSPAnalysis()

        csp_value = self._get_header(headers, "Content-Security-Policy")
        csp_ro_value = self._get_header(headers, "Content-Security-Policy-Report-Only")

        if not csp_value and not csp_ro_value:
            analysis.present = False
            analysis.issues.append(("HIGH", "Content-Security-Policy header is missing"))
            return analysis

        analysis.present = True

        if csp_ro_value and not csp_value:
            analysis.report_only = True
            analysis.raw = csp_ro_value
            analysis.issues.append(("MEDIUM", "Only Content-Security-Policy-Report-Only is present; policy is not enforced"))
            raw = csp_ro_value
        else:
            analysis.raw = csp_value
            raw = csp_value

        directives = self._parse_csp_directives(raw)
        analysis.directives = directives

        NO_FALLBACK_DIRECTIVES = {"base-uri"}

        for required in CSP_REQUIRED_DIRECTIVES:
            if required not in directives:
                if required not in NO_FALLBACK_DIRECTIVES and "default-src" in directives:
                    continue
                analysis.missing_directives.append(required)
                analysis.issues.append(("MEDIUM", f"CSP missing required directive: '{required}'"))

        csp_header_count = sum(
            1 for k in headers if k.lower() in ("content-security-policy", "content-security-policy-report-only")
        )
        if csp_header_count > 2:
            analysis.issues.append(("MEDIUM", f"Multiple CSP headers detected ({csp_header_count}); browser applies most restrictive — verify intended policy"))

        for directive, sources in directives.items():
            if sources is None:
                continue
            source_list = sources.split()
            for src in source_list:
                src_lower = src.lower()
                if src_lower in CSP_UNSAFE_SOURCES:
                    analysis.unsafe_sources.append(f"{directive}: {src}")
                    sev = "HIGH" if src_lower in CSP_HIGH_SEVERITY_SOURCES else "MEDIUM"
                    analysis.issues.append((sev, f"Unsafe CSP source '{src}' in directive '{directive}'"))

            for pattern in CSP_WILDCARD_PATTERNS:
                if pattern.search(sources):
                    analysis.wildcard_sources.append(f"{directive}: {sources}")
                    analysis.issues.append(("MEDIUM", f"Wildcard source detected in CSP directive '{directive}'"))
                    break

        script_src = directives.get("script-src") or directives.get("default-src", "")
        if script_src:
            nonce_match = re.search(r"'nonce-([^']+)'", script_src)
            hash_match = re.search(r"'sha(?:256|384|512)-[^']++'", script_src)
            has_strict_dynamic = "'strict-dynamic'" in script_src
            has_unsafe_inline = "'unsafe-inline'" in script_src

            if not nonce_match and not hash_match:
                if not has_strict_dynamic:
                    analysis.issues.append(("LOW", "CSP script-src lacks nonce, hash, or 'strict-dynamic'"))

            if (nonce_match or hash_match) and has_unsafe_inline:
                analysis.issues.append((
                    "LOW",
                    "CSP script-src has both nonce/hash and 'unsafe-inline'; "
                    "modern browsers ignore unsafe-inline, but legacy browsers remain vulnerable"
                ))

        base_uri = directives.get("base-uri")
        if base_uri is not None:
            base_uri_sources = base_uri.split()
            for src in base_uri_sources:
                src_lower = src.lower()
                if src_lower in ("*", "http:", "https:"):
                    analysis.issues.append(("HIGH", f"base-uri allows unrestricted origins via '{src}'; enables base tag injection"))
                elif src_lower in ("'unsafe-inline'", "'unsafe-eval'"):
                    analysis.issues.append(("HIGH", f"base-uri contains invalid keyword '{src}'; has no effect but indicates misconfiguration"))
                elif src_lower == "data:":
                    analysis.issues.append(("MEDIUM", "base-uri allows data: URIs; may be exploitable for base tag injection"))
            if not base_uri_sources:
                analysis.issues.append(("MEDIUM", "base-uri directive is present but empty; restrict to 'self' or explicit origins"))

        frame_ancestors = directives.get("frame-ancestors")
        if frame_ancestors is None:
            analysis.issues.append(("LOW", "CSP 'frame-ancestors' directive is absent (consider replacing X-Frame-Options)"))
        else:
            fa_stripped = frame_ancestors.strip().lower()
            if fa_stripped == "*":
                analysis.issues.append(("HIGH", "CSP 'frame-ancestors *' allows framing from any origin"))
            elif fa_stripped == "'none'":
                analysis.issues.append(("OK", "CSP 'frame-ancestors' is set to 'none'; framing is fully blocked"))
            elif fa_stripped == "'self'":
                analysis.issues.append(("INFO", "CSP 'frame-ancestors' restricts framing to same origin only"))
            elif not fa_stripped:
                analysis.issues.append(("MEDIUM", "CSP 'frame-ancestors' directive is present but empty; no framing restriction is enforced"))
            else:
                fa_sources = frame_ancestors.split()
                for src in fa_sources:
                    if src.lower() in ("http:", "https:", "*"):
                        analysis.issues.append(("HIGH", f"CSP 'frame-ancestors' contains overly broad source '{src}'"))
                        break
                else:
                    analysis.issues.append(("INFO", f"CSP 'frame-ancestors' restricts framing to explicit origins: {frame_ancestors.strip()}; verify these are intentional"))

        return analysis

    def _parse_csp_directives(self, csp_value: str) -> Dict[str, Optional[str]]:
        directives = {}
        for segment in csp_value.split(";"):
            segment = segment.strip()
            if not segment:
                continue
            parts = segment.split(None, 1)
            directive_name = parts[0].lower()
            directive_value = parts[1] if len(parts) > 1 else None
            directives[directive_name] = directive_value
        return directives

    def check_frame_options(self, headers: Dict[str, str], result: ModuleResult):
        value = self._get_header(headers, "X-Frame-Options")

        if value is None:
            result.add_finding("HIGH", "X-Frame-Options", "Header is missing; page may be vulnerable to clickjacking")
            return

        tokens = [t.strip() for t in value.split(",") if t.strip()]
        unique_tokens = list(dict.fromkeys(t.lower() for t in tokens))

        if len(tokens) > 1:
            if len(unique_tokens) == 1:
                result.add_finding(
                    "MEDIUM",
                    "X-Frame-Options",
                    f"Duplicate X-Frame-Options header value detected: '{value}'; only the first is used by browsers"
                )
            else:
                result.add_finding(
                    "MEDIUM",
                    "X-Frame-Options",
                    f"Multiple conflicting X-Frame-Options values: '{value}'; behavior is undefined"
                )

        normalized = unique_tokens[0] if unique_tokens else ""

        if normalized in FRAME_OPTIONS_VALID:
            result.add_finding("OK", "X-Frame-Options", f"Correctly set to '{tokens[0]}'")
        elif normalized.startswith("allow-from"):
            result.add_finding(
                "LOW",
                "X-Frame-Options",
                f"ALLOW-FROM is obsolete and not supported in modern browsers: '{value}'"
            )
        elif normalized in ("allowall", "allow-all", "*"):
            result.add_finding(
                "HIGH",
                "X-Frame-Options",
                f"Value '{value}' explicitly permits framing from any origin — equivalent to no protection"
            )
        else:
            result.add_finding(
                "MEDIUM",
                "X-Frame-Options",
                f"Unrecognized or misconfigured value: '{value}'"
            )

        csp_header = self._get_header(headers, "Content-Security-Policy")
        if csp_header and "frame-ancestors" in csp_header and value is not None:
            result.add_finding(
                "INFO",
                "X-Frame-Options",
                "Both X-Frame-Options and CSP frame-ancestors are set; "
                "modern browsers prefer frame-ancestors — consider removing X-Frame-Options"
            )

    def check_content_type_options(self, headers: Dict[str, str], result: ModuleResult):
        value = self._get_header(headers, "X-Content-Type-Options")

        if value is None:
            result.add_finding(
                "MEDIUM",
                "X-Content-Type-Options",
                "Header is missing; MIME-type sniffing may lead to XSS via content confusion attacks"
            )
            return

        tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
        unique_tokens = list(dict.fromkeys(tokens))

        if len(tokens) > 1:
            result.add_finding(
                "LOW",
                "X-Content-Type-Options",
                f"Duplicate X-Content-Type-Options header value detected: '{value}'; only the first is used"
            )

        effective = unique_tokens[0] if unique_tokens else ""

        if effective == "nosniff":
            result.add_finding("OK", "X-Content-Type-Options", "Correctly set to 'nosniff'")
        else:
            result.add_finding(
                "LOW",
                "X-Content-Type-Options",
                f"Invalid value '{value}'; only 'nosniff' is valid"
            )

    def check_xss_protection(self, headers: Dict[str, str], result: ModuleResult):
        value = self._get_header(headers, "X-XSS-Protection")

        if value is None:
            return

        normalized = value.strip().lower()

        if normalized == "0":
            result.add_finding(
                "INFO",
                "X-XSS-Protection",
                "Header explicitly disabled (0); acceptable if a strong CSP is in place"
            )
        elif normalized in ("1", "1; mode=block"):
            result.add_finding(
                "LOW",
                "X-XSS-Protection",
                f"Deprecated header '{value}' is present; modern browsers ignore it, "
                "and in legacy browsers (IE/old Chrome) it can introduce new XSS vectors. "
                "Remove it and rely on Content-Security-Policy instead."
            )
        elif normalized.startswith("1; report="):
            result.add_finding(
                "LOW",
                "X-XSS-Protection",
                f"Deprecated header '{value}' with report URI detected; remove it and use CSP report-uri instead."
            )
        else:
            result.add_finding(
                "INFO",
                "X-XSS-Protection",
                f"Unrecognized X-XSS-Protection value: '{value}'"
            )

    def check_referrer_permissions(self, headers: Dict[str, str], result: ModuleResult):
        self._check_referrer_policy(headers, result)
        self._check_permissions_policy(headers, result)

    def _check_referrer_policy(self, headers: Dict[str, str], result: ModuleResult):
        value = self._get_header(headers, "Referrer-Policy")

        if value is None:
            result.add_finding(
                "LOW",
                "Referrer-Policy",
                "Header is absent; browser default may leak full URL in Referer header to cross-origin destinations"
            )
            return

        tokens = [t.strip().lower() for t in value.split(",")]

        if len(tokens) > 1:
            result.add_finding(
                "MEDIUM",
                "Referrer-Policy",
                f"Multiple Referrer-Policy values detected: '{value}'; browser uses the last valid value"
            )

        worst_severity = None
        worst_token = None
        severity_rank = {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "OK": 0}

        for token in tokens:
            if token in REFERRER_UNSAFE_VALUES:
                sev = "MEDIUM"
            elif token == "" or token == "origin":
                sev = "LOW"
            elif token in REFERRER_SAFE_VALUES:
                sev = "OK"
            else:
                sev = "INFO"

            if worst_severity is None or severity_rank.get(sev, 0) > severity_rank.get(worst_severity, 0):
                worst_severity = sev
                worst_token = token

        if worst_severity == "OK" and len(tokens) == 1:
            result.add_finding("OK", "Referrer-Policy", f"Secure policy in use: '{value}'")
        elif worst_severity == "MEDIUM":
            result.add_finding(
                "MEDIUM",
                "Referrer-Policy",
                f"Insecure policy '{worst_token}' present; leaks full URL to cross-origin requests"
            )
        elif worst_severity == "LOW" and worst_token == "origin":
            result.add_finding(
                "LOW",
                "Referrer-Policy",
                f"Policy '{worst_token}' sends origin to cross-origin requests; consider 'strict-origin' instead"
            )
        elif worst_severity == "LOW":
            result.add_finding(
                "LOW",
                "Referrer-Policy",
                "Empty or weak Referrer-Policy falls back to browser default behavior"
            )
        else:
            result.add_finding(
                "INFO",
                "Referrer-Policy",
                f"Policy '{value}' detected; verify it matches your security intent"
            )

    def _check_permissions_policy(self, headers: Dict[str, str], result: ModuleResult):
        value = self._get_header(headers, "Permissions-Policy")
        legacy_value = self._get_header(headers, "Feature-Policy")

        if value is None and legacy_value is None:
            result.add_finding(
                "LOW",
                "Permissions-Policy",
                "Header is absent; browser features (camera, geolocation, etc.) are not restricted"
            )
            return

        if legacy_value and not value:
            result.add_finding(
                "LOW",
                "Permissions-Policy",
                "Only deprecated Feature-Policy is present; migrate to Permissions-Policy"
            )
            value = legacy_value

        result.add_finding("INFO", "Permissions-Policy", f"Header present: '{value[:120]}{'...' if len(value) > 120 else ''}'")

        unrestricted_features = self._find_unrestricted_permissions_features(value)
        if unrestricted_features:
            result.add_finding(
                "LOW",
                "Permissions-Policy",
                f"{len(unrestricted_features)} sensitive feature(s) not explicitly restricted: "
                + ", ".join(unrestricted_features)
            )

    def _find_unrestricted_permissions_features(self, policy_value: str) -> List[str]:
        mentioned = set()
        for segment in policy_value.split(","):
            segment = segment.strip()
            if not segment:
                continue
            feature_name = segment.split("=")[0].split("(")[0].strip().lower()
            mentioned.add(feature_name)

        unrestricted = []
        for feature in PERMISSIONS_SENSITIVE_FEATURES:
            if feature not in mentioned:
                unrestricted.append(feature)
        return unrestricted

    def _emit_hsts(self, hsts: HSTSAnalysis, result: ModuleResult):
        if not hsts.present:
            result.add_finding("HIGH", "Strict-Transport-Security", "Header is missing")
            return

        if not hsts.issues:
            result.add_finding(
                "OK",
                "Strict-Transport-Security",
                f"Properly configured (max-age={hsts.max_age}, "
                f"includeSubDomains={hsts.include_subdomains}, preload={hsts.preload})"
            )
        else:
            for sev, detail in hsts.issues:
                result.add_finding(sev, "Strict-Transport-Security", detail)

    def _emit_csp(self, csp: CSPAnalysis, result: ModuleResult):
        if not csp.present:
            result.add_finding("HIGH", "Content-Security-Policy", "Header is missing")
            return

        if not csp.issues:
            result.add_finding("OK", "Content-Security-Policy", "Policy is present with no detected issues")
        else:
            for sev, detail in csp.issues:
                result.add_finding(sev, "Content-Security-Policy", detail)
