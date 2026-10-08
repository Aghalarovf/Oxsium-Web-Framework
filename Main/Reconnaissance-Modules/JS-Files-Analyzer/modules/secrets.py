from __future__ import annotations

import math
import re
from typing import Any

from modules.base import BaseJSModule, Finding


ENTROPY_THRESHOLD      = 4.2
MIN_SECRET_LENGTH      = 16
MAX_SECRET_LENGTH      = 512
ENTROPY_SAMPLE_MIN_LEN = 20

DB_CONNECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("mongodb",    re.compile(r"mongodb(?:\+srv)?://[^\s\"'`]+")),
    ("postgresql", re.compile(r"postgres(?:ql)?://[^\s\"'`]+")),
    ("mysql",      re.compile(r"mysql://[^\s\"'`]+")),
    ("redis",      re.compile(r"redis://[^\s\"'`]+")),
    ("mssql",      re.compile(r"mssql://[^\s\"'`]+")),
    ("jdbc",       re.compile(r"jdbc:[a-z]+://[^\s\"'`]+")),
]

OAUTH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("oauth_client_secret", re.compile(r"""client[_-]?secret\s*[:=]\s*["'`]([A-Za-z0-9\-_]{16,})["'`]""", re.IGNORECASE)),
    ("oauth_client_id",     re.compile(r"""client[_-]?id\s*[:=]\s*["'`]([A-Za-z0-9\-_.]{8,})["'`]""",    re.IGNORECASE)),
    ("oauth_token",         re.compile(r"""(?:oauth|access)[_-]?token\s*[:=]\s*["'`]([A-Za-z0-9\-_.]{16,})["'`]""", re.IGNORECASE)),
]

API_KEY_SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key",       "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",       "critical", re.compile(r"""aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]""", re.IGNORECASE)),
    ("gcp_api_key",          "critical", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("gcp_service_account",  "critical", re.compile(r'"type"\s*:\s*"service_account"')),
    ("azure_client_secret",  "critical", re.compile(r"""client[_-]?secret\s*[:=]\s*["'`]([A-Za-z0-9~.\-_]{34,})["'`]""", re.IGNORECASE)),
    ("azure_sas_token",      "high",     re.compile(r"sig=[A-Za-z0-9%+/]+=*&")),
    ("firebase_api_key",     "high",     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("stripe_secret_key",    "critical", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}")),
    ("stripe_publishable",   "low",      re.compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24,}")),
    ("stripe_webhook",       "high",     re.compile(r"whsec_[A-Za-z0-9]{32,}")),
    ("jwt_token",            "high",     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("sendgrid_key",         "high",     re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}")),
    ("twilio_account_sid",   "high",     re.compile(r"AC[a-f0-9]{32}")),
    ("twilio_auth_token",    "high",     re.compile(r"""twilio[^\n]{0,20}['"` ]([a-f0-9]{32})""", re.IGNORECASE)),
    ("slack_bot_token",      "high",     re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}")),
    ("slack_user_token",     "high",     re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}")),
    ("slack_webhook",        "medium",   re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("github_token",         "critical", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("github_fine_grained",  "critical", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("npm_token",            "high",     re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("gitlab_token",         "high",     re.compile(r"glpat-[A-Za-z0-9\-_]{20}")),
    ("mailgun_key",          "high",     re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("mailchimp_key",        "high",     re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}")),
    ("shopify_token",        "high",     re.compile(r"shpss_[A-Za-z0-9]{32}")),
    ("square_access_token",  "high",     re.compile(r"sq0atp-[A-Za-z0-9\-_]{22}")),
    ("paypal_client_id",     "medium",   re.compile(r'(?i)(?:paypal|client[_-]?id)[^\n]{0,40}A[A-Za-z0-9\-_]{79}|A[A-Za-z0-9\-_]{79}[^\n]{0,40}(?:paypal|client[_-]?id)')),
    ("okta_api_token",       "critical", re.compile(r'(?i)okta[^\n]{0,60}00[A-Za-z0-9\-_]{40}|00[A-Za-z0-9\-_]{40}[^\n]{0,60}okta')),
    ("datadog_api_key",      "high",     re.compile(r"[a-f0-9]{32}")),
    ("heroku_api_key",       "high",     re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("private_key_block",    "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("generic_secret",       "medium",   re.compile(r"""(?:secret|password|passwd|pwd)\s*[:=]\s*["'`]([A-Za-z0-9!@#$%^&*\-_+=]{8,})["'`]""", re.IGNORECASE)),
    ("bearer_token",         "high",     re.compile(r"""[Bb]earer\s+([A-Za-z0-9\-_.+/=]{20,})""")),
]

ENTROPY_CHARSET_PATTERNS: list[re.Pattern] = [
    re.compile(r"""["'`]([A-Za-z0-9+/]{""" + str(ENTROPY_SAMPLE_MIN_LEN) + r""",})={0,2}["'`]"""),
    re.compile(r"""["'`]([A-Fa-f0-9]{""" + str(ENTROPY_SAMPLE_MIN_LEN) + r""",})["'`]"""),
    re.compile(r"""["'`]([A-Za-z0-9\-_]{""" + str(ENTROPY_SAMPLE_MIN_LEN) + r""",})["'`]"""),
]

KNOWN_FALSE_POSITIVE_PREFIXES: set[str] = {
    "http", "https", "data:image", "application", "text/", "font/",
    "AAAA", "BBBB", "CCCC", "XXXX", "0000", "1111",
}


class SecretsModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        self._run_api_key_scan(content)
        self._run_entropy_scan(content)
        self._run_db_string_scan(content)
        self._run_oauth_scan(content)

        return self.findings

    def scan_high_entropy(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for pattern in ENTROPY_CHARSET_PATTERNS:
            for match in pattern.finditer(content):
                candidate = match.group(1)

                if candidate in seen:
                    continue
                if len(candidate) < MIN_SECRET_LENGTH or len(candidate) > MAX_SECRET_LENGTH:
                    continue
                if any(candidate.startswith(fp) for fp in KNOWN_FALSE_POSITIVE_PREFIXES):
                    continue

                entropy = self._shannon_entropy(candidate)
                if entropy < ENTROPY_THRESHOLD:
                    continue

                seen.add(candidate)
                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = "high_entropy_string",
                    value      = candidate[:128],
                    severity   = self.SEVERITY_MEDIUM,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_MEDIUM,
                    meta       = {"entropy": round(entropy, 4), "length": len(candidate)},
                ))

        return findings

    def match_api_keys(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for key_type, severity, pattern in API_KEY_SIGNATURES:
            for match in pattern.finditer(content):
                value = match.group(0)
                fingerprint = f"{key_type}:{value[:32]}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = key_type,
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {"pattern": key_type},
                ))

        return findings

    def extract_db_strings(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for db_type, pattern in DB_CONNECTION_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0)
                if value in seen:
                    continue
                seen.add(value)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = f"db_connection_string_{db_type}",
                    value      = value[:512],
                    severity   = self.SEVERITY_CRITICAL,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {"db_type": db_type},
                ))

        for label, pattern in OAUTH_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                value  = groups[0] if groups else match.group(0)
                if value in seen:
                    continue
                seen.add(value)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = label,
                    value      = value[:256],
                    severity   = self.SEVERITY_HIGH,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {"oauth_field": label},
                ))

        return findings

    def _run_api_key_scan(self, content: str) -> None:
        cleaned = self._strip_jwt_tokens(content)
        self.findings.extend(self.match_api_keys(cleaned))

    def _run_entropy_scan(self, content: str) -> None:
        api_key_values: set[str] = {f.value for f in self.findings}
        for f in self.scan_high_entropy(content):
            if not any(f.value in v or v in f.value for v in api_key_values):
                self.findings.append(f)

    def _run_db_string_scan(self, content: str) -> None:
        self.findings.extend(self.extract_db_strings(content))

    def _run_oauth_scan(self, content: str) -> None:
        pass

    @staticmethod
    def _strip_jwt_tokens(content: str) -> str:
        import re
        jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+'
        )
        return jwt_pattern.sub('[JWT_REDACTED]', content)

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())