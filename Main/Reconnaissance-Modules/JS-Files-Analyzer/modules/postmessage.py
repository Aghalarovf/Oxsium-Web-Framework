from __future__ import annotations

import re
from typing import Any

from modules.base import BaseJSModule, Finding


POSTMESSAGE_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("wildcard_target_origin",    "critical", re.compile(r"""\.postMessage\s*\([^,]+,\s*["'`]\*["'`]""")),
    ("variable_target_origin",    "high",     re.compile(r"""\.postMessage\s*\([^,]+,\s*(?!["'`](?:https?://|\*))[a-zA-Z_$][\w$]*\s*\)""")),
    ("postmessage_no_origin",     "medium",   re.compile(r"""\.postMessage\s*\(\s*[^,]+\s*\)(?!\s*,)""")),
    ("postmessage_http_origin",   "medium",   re.compile(r"""\.postMessage\s*\([^,]+,\s*["'`]http://[^"'`]+["'`]""")),
    ("postmessage_data_passthru", "high",     re.compile(r"""\.postMessage\s*\(\s*(?:event|e|msg)\.data\s*,""")),
    ("broadcast_channel_post",    "medium",   re.compile(r"""(?:new\s+BroadcastChannel\s*\([^)]*\))[^.]*\.postMessage\s*\(""")),
    ("shared_worker_post",        "medium",   re.compile(r"""\.postMessage\s*\([^)]*\)\s*;[^}]*(?:SharedWorker|Worker)""")),
]

LISTENER_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("message_listener_added",    "info",     re.compile(r"""(?:window|self|globalThis)\.addEventListener\s*\(\s*["'`]message["'`]""")),
    ("message_listener_short",    "info",     re.compile(r"""addEventListener\s*\(\s*["'`]message["'`]""")),
    ("onmessage_handler",         "info",     re.compile(r"""(?:window|self)\.onmessage\s*=""")),
    ("worker_onmessage",          "info",     re.compile(r"""(?:self|this)\.onmessage\s*=\s*(?:function|\(|[a-zA-Z])""")),
]

ORIGIN_CHECK_PATTERNS: list[re.Pattern] = [
    re.compile(r"""(?:event|e|msg|data)\.origin\s*(?:!==?|===?)\s*["'`]https?://"""),
    re.compile(r"""(?:event|e|msg|data)\.origin\s*(?:!==?|===?)\s*[a-zA-Z_$][\w$]*"""),
    re.compile(r"""(?:allowedOrigins?|trustedOrigins?|whitelist)\s*\.includes\s*\(\s*(?:event|e|msg|data)\.origin"""),
    re.compile(r"""if\s*\([^)]*\.origin[^)]*\)"""),
    re.compile(r"""\.origin\s*!==?\s*(?:window\.)?location\.origin"""),
]

SANITIZE_PATTERNS: list[re.Pattern] = [
    re.compile(r"""DOMPurify\.sanitize\s*\("""),
    re.compile(r"""sanitize(?:Html)?\s*\("""),
    re.compile(r"""escapeHtml\s*\("""),
    re.compile(r"""JSON\.parse\s*\("""),
]

DANGEROUS_DATA_USE_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("message_data_to_innerhtml",  "critical", re.compile(r"""(?:event|e|msg)\.data[^;]*\.innerHTML\s*=""")),
    ("message_data_to_eval",       "critical", re.compile(r"""eval\s*\([^)]*(?:event|e|msg)\.data""")),
    ("message_data_to_location",   "high",     re.compile(r"""(?:window\.)?location[^=]*=\s*[^;]*(?:event|e|msg)\.data""")),
    ("message_data_to_srcdoc",     "high",     re.compile(r"""\.srcdoc\s*=\s*[^;]*(?:event|e|msg)\.data""")),
    ("message_data_unvalidated",   "medium",   re.compile(r"""(?:event|e|msg)\.data\.(?:type|action|cmd)\s*===?\s*["'`]\w+["'`][^{]*\{(?!(?:[^}]|{[^}]*})*\.origin)""")),
]


class PostMessageModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        self._run_target_origin_scan(content)
        self._run_listener_audit(content)
        self._run_dangerous_data_scan(content)

        return self.findings

    def scan_target_origin(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for pm_type, severity, pattern in POSTMESSAGE_PATTERNS:
            for match in pattern.finditer(content):
                value       = match.group(0).strip()
                fingerprint = f"{pm_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = pm_type,
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "vuln_category": "postmessage_origin",
                        "pm_type":       pm_type,
                    },
                ))

        return findings

    def audit_message_listeners(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for listener_type, _, pattern in LISTENER_PATTERNS:
            for match in pattern.finditer(content):
                fingerprint = f"{listener_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line          = self._get_line_number(content, match.start())
                ctx           = self._get_context(content, match.start())
                handler_body  = self._extract_handler_body(content, match.end())
                has_origin    = self._has_origin_check(handler_body)
                has_sanitize  = self._has_sanitization(handler_body)

                if has_origin and has_sanitize:
                    severity   = "low"
                    confidence = self.CONFIDENCE_HIGH
                elif has_origin:
                    severity   = "medium"
                    confidence = self.CONFIDENCE_HIGH
                elif has_sanitize:
                    severity   = "high"
                    confidence = self.CONFIDENCE_HIGH
                else:
                    severity   = "high"
                    confidence = self.CONFIDENCE_MEDIUM

                findings.append(self._finding(
                    type       = f"message_listener_{listener_type}",
                    value      = match.group(0).strip()[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = confidence,
                    meta       = {
                        "vuln_category":    "postmessage_listener",
                        "has_origin_check": has_origin,
                        "has_sanitization": has_sanitize,
                        "listener_type":    listener_type,
                    },
                ))

        return findings

    def _run_target_origin_scan(self, content: str) -> None:
        self.findings.extend(self.scan_target_origin(content))

    def _run_listener_audit(self, content: str) -> None:
        self.findings.extend(self.audit_message_listeners(content))

    def _run_dangerous_data_scan(self, content: str) -> None:
        seen: set[str] = set()
        for data_type, severity, pattern in DANGEROUS_DATA_USE_PATTERNS:
            for match in pattern.finditer(content):
                value       = match.group(0).strip()
                fingerprint = f"{data_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                self.findings.append(self._finding(
                    type       = data_type,
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "vuln_category": "postmessage_data_flow",
                        "data_type":     data_type,
                    },
                ))

    @staticmethod
    def _extract_handler_body(content: str, pos: int, max_len: int = 800) -> str:
        snippet = content[pos: pos + max_len]
        depth   = 0
        start   = None
        for i, ch in enumerate(snippet):
            if ch == "{":
                if start is None:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    return snippet[start: i + 1]
        return snippet

    @staticmethod
    def _has_origin_check(body: str) -> bool:
        return any(p.search(body) for p in ORIGIN_CHECK_PATTERNS)

    @staticmethod
    def _has_sanitization(body: str) -> bool:
        return any(p.search(body) for p in SANITIZE_PATTERNS)