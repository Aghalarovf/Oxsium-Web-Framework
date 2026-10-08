from __future__ import annotations

import re
from typing import Any

from modules.base import BaseJSModule, Finding


CLIENT_AUTH_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("role_check_from_localstorage",  "critical", re.compile(r"""localStorage\.getItem\s*\(\s*["'`](?:role|isAdmin|userType|permissions|access_level)["'`]\s*\)""")),
    ("role_check_from_sessionstorage","critical", re.compile(r"""sessionStorage\.getItem\s*\(\s*["'`](?:role|isAdmin|userType|permissions|access_level)["'`]\s*\)""")),
    ("isAdmin_boolean_flag",          "critical", re.compile(r"""(?:isAdmin|is_admin|isRoot|isSuperuser)\s*(?:===?|!==?)\s*(?:true|false|1|0)""")),
    ("role_string_comparison",        "high",     re.compile(r"""(?:role|userRole|user_role)\s*===?\s*["'`](?:admin|superuser|root|moderator|staff)["'`]""", re.IGNORECASE)),
    ("decoded_jwt_role_check",        "critical", re.compile(r"""(?:atob|decode|parseJwt|jwt_decode)\s*\([^)]+\)[^.]*\.(?:role|isAdmin|permissions)""")),
    ("hardcoded_uid_bypass",          "high",     re.compile(r"""(?:userId|user_id|uid)\s*===?\s*(?:0|1|["'`]\d+["'`])""")),
    ("frontend_only_redirect",        "high",     re.compile(r"""if\s*\([^)]*(?:isAdmin|role|auth)[^)]*\)\s*\{[^}]*(?:navigate|history\.push|location\.href|router\.push)""", re.DOTALL)),
    ("conditional_render_auth",       "medium",   re.compile(r"""\{[^}]*(?:isAdmin|isAuthenticated|hasRole)[^}]*&&\s*<""")),
    ("disabled_attr_auth",            "medium",   re.compile(r"""disabled\s*=\s*\{[^}]*(?:!isAdmin|!hasPermission|!isAuthenticated)""")),
    ("cookie_role_read",              "high",     re.compile(r"""document\.cookie[^;]*(?:role|isAdmin|admin|permissions)""", re.IGNORECASE)),
]

HARDCODED_CRYPTO_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aes_key_literal",           "critical", re.compile(r"""(?:CryptoJS|aes|AES)\.(?:encrypt|decrypt)\s*\([^,]+,\s*["'`]([A-Za-z0-9+/=]{8,})["'`]""")),
    ("hardcoded_iv",              "critical", re.compile(r"""iv\s*[:=]\s*["'`]([A-Fa-f0-9]{16,32})["'`]""")),
    ("hardcoded_salt",            "high",     re.compile(r"""salt\s*[:=]\s*["'`]([A-Za-z0-9+/=]{8,})["'`]""")),
    ("hardcoded_hmac_secret",     "critical", re.compile(r"""(?:hmac|HMAC|createHmac)\s*\([^,]+,\s*["'`]([A-Za-z0-9+/=\-_]{8,})["'`]""")),
    ("weak_hash_md5",             "high",     re.compile(r"""\bMD5\s*\(|CryptoJS\.MD5\s*\(|require\s*\(\s*["'`]md5["'`]\s*\)""")),
    ("weak_hash_sha1",            "medium",   re.compile(r"""\bsha1\s*\(|CryptoJS\.SHA1\s*\(|createHash\s*\(\s*["'`]sha1["'`]\s*\)""")),
    ("math_random_crypto",        "high",     re.compile(r"""Math\.random\s*\(\s*\).*(?:token|key|secret|nonce|salt|id)""", re.IGNORECASE | re.DOTALL)),
    ("fixed_nonce",               "critical", re.compile(r"""nonce\s*[:=]\s*["'`]([A-Fa-f0-9]{8,})["'`]""")),
    ("rsa_public_key_inline",     "medium",   re.compile(r"""-----BEGIN (?:RSA )?PUBLIC KEY-----""")),
    ("weak_symmetric_key_short",  "critical", re.compile(r"""(?:key|secret|password)\s*[:=]\s*["'`]([A-Za-z0-9]{1,15})["'`]""", re.IGNORECASE)),
    ("base64_encoded_key",        "high",     re.compile(r"""(?:key|secret)\s*[:=]\s*atob\s*\(\s*["'`]([A-Za-z0-9+/=]{20,})["'`]\s*\)""", re.IGNORECASE)),
    ("ecb_mode_usage",            "high",     re.compile(r"""CryptoJS\.AES\.(?:encrypt|decrypt)[^)]*mode\s*:\s*CryptoJS\.mode\.ECB""")),
]

INSECURE_STORAGE_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("token_in_localstorage",         "high",     re.compile(r"""localStorage\.setItem\s*\(\s*["'`](?:token|access_token|auth_token|jwt|id_token|refresh_token)["'`]""", re.IGNORECASE)),
    ("password_in_localstorage",      "critical", re.compile(r"""localStorage\.setItem\s*\(\s*["'`](?:password|passwd|pwd|secret)["'`]""", re.IGNORECASE)),
    ("pii_in_localstorage",           "high",     re.compile(r"""localStorage\.setItem\s*\(\s*["'`](?:ssn|credit_card|card_number|cvv|dob|date_of_birth|email|phone|address)["'`]""", re.IGNORECASE)),
    ("sensitive_in_sessionstorage",   "high",     re.compile(r"""sessionStorage\.setItem\s*\(\s*["'`](?:token|password|passwd|pwd|secret|credit_card|ssn)["'`]""", re.IGNORECASE)),
    ("token_in_cookie_no_flags",      "high",     re.compile(r"""document\.cookie\s*=\s*["'`](?:token|auth|jwt)[^;]*(?<!HttpOnly)(?<!Secure)["'`]""", re.IGNORECASE)),
    ("cookie_no_httponly",            "medium",   re.compile(r"""document\.cookie\s*=\s*[^;]+;(?![^;]*HttpOnly)""", re.IGNORECASE)),
    ("cookie_no_secure",              "medium",   re.compile(r"""document\.cookie\s*=\s*[^;]+;(?![^;]*Secure)""", re.IGNORECASE)),
    ("indexeddb_sensitive",           "medium",   re.compile(r"""indexedDB\.open[^;]*(?:token|password|secret|card)""", re.IGNORECASE)),
    ("sensitive_in_url_hash",         "high",     re.compile(r"""location\.hash\s*=.*(?:token|key|secret|password)""", re.IGNORECASE)),
    ("stringify_credentials",         "high",     re.compile(r"""JSON\.stringify\s*\([^)]*(?:password|secret|token|key)[^)]*\)\s*[^;]*(?:localStorage|sessionStorage)""", re.IGNORECASE | re.DOTALL)),
    ("redux_persist_sensitive",       "high",     re.compile(r"""redux-persist[^;]*(?:whitelist|blacklist)[^;]*["'`](?:auth|token|credentials|password)["'`]""", re.IGNORECASE)),
]

SENSITIVE_KEY_TERMS: frozenset[str] = frozenset([
    "token", "password", "passwd", "pwd", "secret", "key",
    "auth", "jwt", "ssn", "credit_card", "cvv", "pin",
    "private", "credential", "api_key",
])


class LogicVulnsModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        self._run_client_auth_scan(content)
        self._run_crypto_scan(content)
        self._run_storage_scan(content)

        return self.findings

    def detect_client_auth(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for auth_type, severity, pattern in CLIENT_AUTH_PATTERNS:
            for match in pattern.finditer(content):
                value       = match.group(0).strip()
                fingerprint = f"{auth_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = auth_type,
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "vuln_category": "client_side_authorization",
                        "auth_pattern":  auth_type,
                    },
                ))

        return findings

    def find_hardcoded_crypto(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for crypto_type, severity, pattern in HARDCODED_CRYPTO_PATTERNS:
            for match in pattern.finditer(content):
                groups      = match.groups()
                value       = groups[0] if groups else match.group(0)
                fingerprint = f"{crypto_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = crypto_type,
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "vuln_category": "hardcoded_cryptographic_material",
                        "crypto_type":   crypto_type,
                    },
                ))

        return findings

    def check_insecure_storage(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for storage_type, severity, pattern in INSECURE_STORAGE_PATTERNS:
            for match in pattern.finditer(content):
                value       = match.group(0).strip()
                fingerprint = f"{storage_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = storage_type,
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "vuln_category":  "insecure_storage",
                        "storage_type":   storage_type,
                        "storage_medium": self._classify_storage_medium(value),
                    },
                ))

        self._scan_generic_storage_keys(content, findings)

        return findings

    def _run_client_auth_scan(self, content: str) -> None:
        self.findings.extend(self.detect_client_auth(content))

    def _run_crypto_scan(self, content: str) -> None:
        existing_lines: set[int] = {f.line for f in self.findings}
        for f in self.find_hardcoded_crypto(content):
            if f.line not in existing_lines:
                self.findings.append(f)
                existing_lines.add(f.line)

    def _run_storage_scan(self, content: str) -> None:
        existing_lines: set[int] = {f.line for f in self.findings}
        for f in self.check_insecure_storage(content):
            if f.line not in existing_lines:
                self.findings.append(f)
                existing_lines.add(f.line)

    def _scan_generic_storage_keys(self, content: str, findings: list[Finding]) -> None:
        generic_set_pattern = re.compile(
            r"""(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`]([^"'`]+)["'`]""",
            re.IGNORECASE,
        )
        seen_generic: set[str] = set()

        for match in generic_set_pattern.finditer(content):
            key         = match.group(1).lower()
            fingerprint = f"generic_storage:{key}"
            if fingerprint in seen_generic:
                continue

            if any(term in key for term in SENSITIVE_KEY_TERMS):
                seen_generic.add(fingerprint)
                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = "sensitive_key_in_storage",
                    value      = match.group(0).strip()[:256],
                    severity   = "high",
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_MEDIUM,
                    meta       = {
                        "vuln_category":  "insecure_storage",
                        "storage_type":   "sensitive_key_in_storage",
                        "storage_medium": self._classify_storage_medium(match.group(0)),
                        "key_name":       match.group(1),
                    },
                ))

    @staticmethod
    def _classify_storage_medium(value: str) -> str:
        v = value.lower()
        if "localstorage" in v:
            return "localStorage"
        if "sessionstorage" in v:
            return "sessionStorage"
        if "cookie" in v:
            return "cookie"
        if "indexeddb" in v:
            return "indexedDB"
        return "unknown"