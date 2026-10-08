from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from modules.base import BaseJSModule, Finding


SCRIPT_TAG_PATTERN = re.compile(
    r"""<script\b([^>]*)>""",
    re.IGNORECASE | re.DOTALL,
)

SRC_ATTR_PATTERN       = re.compile(r"""\bsrc\s*=\s*["'`]([^"'`]+)["'`]""",       re.IGNORECASE)
INTEGRITY_ATTR_PATTERN = re.compile(r"""\bintegrity\s*=\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE)
CROSSORIGIN_ATTR_PATTERN = re.compile(r"""\bcrossorigin\s*=\s*["'`]([^"'`]*)["'`]""", re.IGNORECASE)
NONCE_ATTR_PATTERN     = re.compile(r"""\bnonce\s*=\s*["'`]([^"'`]+)["'`]""",     re.IGNORECASE)

CSP_META_PATTERN = re.compile(
    r"""<meta\b[^>]*http-equiv\s*=\s*["'`]Content-Security-Policy["'`][^>]*content\s*=\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE | re.DOTALL,
)

CSP_HEADER_PATTERN = re.compile(
    r"""Content-Security-Policy\s*:\s*([^\r\n]+)""",
    re.IGNORECASE,
)

NONCE_PLACEHOLDER_PATTERNS: list[re.Pattern] = [
    re.compile(r"""nonce\s*=\s*["'`](?:NONCE|{nonce}|\{\{nonce\}\}|%nonce%|\$nonce|\$\{nonce\})["'`]""", re.IGNORECASE),
    re.compile(r"""nonce\s*=\s*["'`][a-zA-Z0-9+/=]{8,}["'`]"""),
]

TRUSTED_CDN_HOSTS: frozenset[str] = frozenset([
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "code.jquery.com", "ajax.googleapis.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.bootcss.com", "cdn.staticfile.org",
])

SRI_HASH_PATTERN    = re.compile(r"""^(sha256|sha384|sha512)-[A-Za-z0-9+/=]{40,}$""")
WEAK_SRI_PATTERN    = re.compile(r"""^sha1-""")

CSP_DANGEROUS_DIRECTIVES: list[tuple[str, str, re.Pattern]] = [
    ("unsafe_inline_script",   "critical", re.compile(r"""script-src[^;]*'unsafe-inline'""",    re.IGNORECASE)),
    ("unsafe_eval_script",     "critical", re.compile(r"""script-src[^;]*'unsafe-eval'""",      re.IGNORECASE)),
    ("wildcard_script_src",    "critical", re.compile(r"""script-src\s+\*""",                   re.IGNORECASE)),
    ("unsafe_inline_style",    "high",     re.compile(r"""style-src[^;]*'unsafe-inline'""",     re.IGNORECASE)),
    ("data_uri_script",        "high",     re.compile(r"""script-src[^;]*\bdata:""",            re.IGNORECASE)),
    ("http_in_csp",            "high",     re.compile(r"""script-src[^;]*\bhttp://""",          re.IGNORECASE)),
    ("missing_default_src",    "medium",   re.compile(r"""^(?!.*default-src).*$""",             re.IGNORECASE)),
    ("missing_object_src",     "medium",   re.compile(r"""^(?!.*object-src).*$""",              re.IGNORECASE)),
    ("missing_base_uri",       "medium",   re.compile(r"""^(?!.*base-uri).*$""",                re.IGNORECASE)),
    ("nonce_with_unsafe_inline","high",    re.compile(r"""script-src[^;]*nonce-[^;]*'unsafe-inline'""", re.IGNORECASE)),
    ("strict_dynamic_missing", "low",      re.compile(r"""script-src[^;]*nonce-(?![^;]*'strict-dynamic')""", re.IGNORECASE)),
]


class CspSriModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        self._run_sri_check(content)
        self._run_csp_nonce_analysis(content)
        self._run_script_source_audit(content)

        return self.findings

    def check_sri_attributes(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for match in SCRIPT_TAG_PATTERN.finditer(content):
            attrs       = match.group(1)
            src_match   = SRC_ATTR_PATTERN.search(attrs)
            if not src_match:
                continue

            src         = src_match.group(1).strip()
            fingerprint = f"sri:{src}"
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            line          = self._get_line_number(content, match.start())
            ctx           = self._get_context(content, match.start())
            integrity     = INTEGRITY_ATTR_PATTERN.search(attrs)
            crossorigin   = CROSSORIGIN_ATTR_PATTERN.search(attrs)
            is_external   = self._is_external_src(src)

            if not is_external:
                continue

            if not integrity:
                findings.append(self._finding(
                    type       = "missing_sri_integrity",
                    value      = src[:256],
                    severity   = "high",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "src":             src,
                        "has_integrity":   False,
                        "has_crossorigin": bool(crossorigin),
                        "is_trusted_cdn":  self._is_trusted_cdn(src),
                    },
                ))
                continue

            hash_value = integrity.group(1).strip()

            if WEAK_SRI_PATTERN.match(hash_value):
                findings.append(self._finding(
                    type       = "weak_sri_algorithm",
                    value      = hash_value[:256],
                    severity   = "high",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "src":           src,
                        "hash":          hash_value,
                        "has_integrity": True,
                        "algorithm":     "sha1",
                    },
                ))
            elif not SRI_HASH_PATTERN.match(hash_value):
                findings.append(self._finding(
                    type       = "invalid_sri_format",
                    value      = hash_value[:256],
                    severity   = "medium",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_MEDIUM,
                    meta       = {
                        "src":           src,
                        "hash":          hash_value,
                        "has_integrity": True,
                    },
                ))

            if integrity and not crossorigin:
                findings.append(self._finding(
                    type       = "sri_missing_crossorigin",
                    value      = src[:256],
                    severity   = "medium",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "src":             src,
                        "has_integrity":   True,
                        "has_crossorigin": False,
                    },
                ))

        return findings

    def analyze_csp_nonces(self, content: str) -> list[Finding]:
        findings: list[Finding] = []

        csp_values: list[str] = []
        for match in CSP_META_PATTERN.finditer(content):
            csp_values.append(match.group(1))
        for match in CSP_HEADER_PATTERN.finditer(content):
            csp_values.append(match.group(1))

        if not csp_values:
            findings.append(self._finding(
                type       = "no_csp_found",
                value      = "No Content-Security-Policy detected",
                severity   = "high",
                context    = "",
                line       = 0,
                confidence = self.CONFIDENCE_MEDIUM,
                meta       = {"vuln_category": "csp_missing"},
            ))
            return findings

        for csp in csp_values:
            for directive_type, severity, pattern in CSP_DANGEROUS_DIRECTIVES:
                if pattern.search(csp):
                    findings.append(self._finding(
                        type       = f"csp_{directive_type}",
                        value      = csp[:256],
                        severity   = severity,
                        context    = csp[:128],
                        line       = 0,
                        confidence = self.CONFIDENCE_HIGH,
                        meta       = {
                            "vuln_category":    "csp_misconfiguration",
                            "directive":        directive_type,
                            "full_policy":      csp[:512],
                        },
                    ))

        for match in NONCE_PLACEHOLDER_PATTERNS[1].finditer(content):
            findings.append(self._finding(
                type       = "hardcoded_csp_nonce",
                value      = match.group(0)[:128],
                severity   = "critical",
                context    = self._get_context(content, match.start()),
                line       = self._get_line_number(content, match.start()),
                confidence = self.CONFIDENCE_HIGH,
                meta       = {
                    "vuln_category": "csp_nonce_hardcoded",
                    "nonce_value":   match.group(0)[:64],
                },
            ))

        return findings

    def audit_script_sources(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for match in SCRIPT_TAG_PATTERN.finditer(content):
            attrs     = match.group(1)
            src_match = SRC_ATTR_PATTERN.search(attrs)
            if not src_match:
                continue

            src         = src_match.group(1).strip()
            fingerprint = f"src_audit:{src}"
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            line        = self._get_line_number(content, match.start())
            ctx         = self._get_context(content, match.start())
            parsed      = self._safe_parse_url(src)
            integrity   = INTEGRITY_ATTR_PATTERN.search(attrs)
            nonce       = NONCE_ATTR_PATTERN.search(attrs)

            if not parsed:
                continue

            scheme = parsed.scheme.lower()
            host   = parsed.netloc.lower()

            if scheme == "http":
                findings.append(self._finding(
                    type       = "script_src_http",
                    value      = src[:256],
                    severity   = "high",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "src":  src,
                        "host": host,
                        "risk": "cleartext_transport",
                    },
                ))

            if host and not self._is_trusted_cdn(src) and not integrity:
                findings.append(self._finding(
                    type       = "untrusted_external_script",
                    value      = src[:256],
                    severity   = "high",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_MEDIUM,
                    meta       = {
                        "src":             src,
                        "host":            host,
                        "has_integrity":   bool(integrity),
                        "has_nonce":       bool(nonce),
                        "is_trusted_cdn":  False,
                    },
                ))

            if self._is_trusted_cdn(src) and not integrity:
                findings.append(self._finding(
                    type       = "cdn_script_no_sri",
                    value      = src[:256],
                    severity   = "medium",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "src":            src,
                        "host":           host,
                        "has_integrity":  False,
                        "is_trusted_cdn": True,
                    },
                ))

        return findings

    def _run_sri_check(self, content: str) -> None:
        self.findings.extend(self.check_sri_attributes(content))

    def _run_csp_nonce_analysis(self, content: str) -> None:
        self.findings.extend(self.analyze_csp_nonces(content))

    def _run_script_source_audit(self, content: str) -> None:
        existing: set[str] = {f.value for f in self.findings}
        for f in self.audit_script_sources(content):
            if f.value not in existing:
                self.findings.append(f)

    @staticmethod
    def _is_external_src(src: str) -> bool:
        return src.startswith(("http://", "https://", "//"))

    @staticmethod
    def _is_trusted_cdn(src: str) -> bool:
        try:
            host = urlparse(src).netloc.lower()
            return host in TRUSTED_CDN_HOSTS
        except Exception:
            return False

    @staticmethod
    def _safe_parse_url(src: str):
        try:
            if src.startswith("//"):
                src = "https:" + src
            parsed = urlparse(src)
            return parsed if parsed.netloc else None
        except Exception:
            return None