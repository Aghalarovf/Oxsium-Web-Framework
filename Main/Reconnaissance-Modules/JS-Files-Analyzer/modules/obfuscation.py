from __future__ import annotations

import math
import re
from typing import Any

from modules.base import BaseJSModule, Finding


JSFUCK_SIGNALS: list[tuple[str, str, re.Pattern]] = [
    ("jsfuck_core",          "high",     re.compile(r"""(?:\[\s*\]|\(\s*\)|\!\s*\[\s*\]|\!\s*\(\s*\)|\+\s*\[\s*\]){6,}""")),
    ("jsfuck_char_concat",   "high",     re.compile(r"""(?:\(!\[\]\+\[\]\)\[[\d+\[\]]+\]){3,}""")),
    ("aaencode_preamble",    "critical", re.compile(r"""ﾟωﾟ|ﾟДﾟ|ﾟΘﾟ|ﾟｰﾟ""")),
    ("aaencode_structure",   "critical", re.compile(r"""\(ﾟДﾟ\)\s*\[.+?\]\s*\(""")),
    ("jjencode_dollar",      "high",     re.compile(r"""\$\$\$\$\$\$\$\$\$\$(?:\$|\d){5,}""")),
    ("jjencode_structure",   "high",     re.compile(r"""\$=[~\[\]{}()!+"']+;""")),
    ("emoji_obfuscation",    "high",     re.compile(r"""[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]{4,}""")),
    ("unicode_escape_dense", "medium",   re.compile(r"""(?:\\u[0-9a-fA-F]{4}){6,}""")),
    ("hex_escape_dense",     "medium",   re.compile(r"""(?:\\x[0-9a-fA-F]{2}){6,}""")),
    ("zero_width_chars",     "high",     re.compile(r"""[\u200b\u200c\u200d\ufeff]{2,}""")),
    ("string_fromCharCode",  "medium",   re.compile(r"""String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}""")),
    ("charCode_array_exec",  "high",     re.compile(r"""eval\s*\(\s*String\.fromCharCode\s*\(""")),
]

HEX_VAR_PATTERN   = re.compile(r"""\b_0x[0-9a-fA-F]{2,6}\b""")
SHORT_VAR_PATTERN  = re.compile(r"""\b[a-zA-Z]{1,2}\d*\b""")
LONG_STRING_PATTERN = re.compile(r"""["'`]([A-Za-z0-9+/=\\]{100,})["'`]""")
ARRAY_ROTATE_PATTERN = re.compile(r"""(?:push|shift|unshift|splice)\s*\([^)]*\)\s*[;,]""")
SELF_DEFEND_PATTERN  = re.compile(r"""function\s*\w*\s*\([^)]*\)\s*\{[^}]*(?:debugger|toString\s*\(\s*\))[^}]*\}""")
PACKED_EVAL_PATTERN  = re.compile(r"""eval\s*\(\s*(?:function\s*\(p,a,c,k,e,(?:d|r)\)|unescape\s*\()""")
BASE64_EVAL_PATTERN  = re.compile(r"""(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(""")
CONTROL_FLOW_PATTERN = re.compile(r"""switch\s*\(\s*\w+\+\+\s*\)\s*\{(?:[^}]*case\s+["'`]\d+["'`]\s*:){4,}""")

READABILITY_PENALTIES: list[tuple[str, float, re.Pattern]] = [
    ("hex_vars",           0.30, HEX_VAR_PATTERN),
    ("packed_eval",        0.25, PACKED_EVAL_PATTERN),
    ("base64_eval",        0.20, BASE64_EVAL_PATTERN),
    ("control_flow_flat",  0.15, CONTROL_FLOW_PATTERN),
    ("self_defending",     0.10, SELF_DEFEND_PATTERN),
    ("long_strings",       0.10, LONG_STRING_PATTERN),
    ("array_rotators",     0.05, ARRAY_ROTATE_PATTERN),
]


class ObfuscationModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        self._run_jsfuck_scan(content)
        self._run_entropy_scan(content)
        self._run_score_scan(content)

        return self.findings

    def detect_jsfuck(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for sig_type, severity, pattern in JSFUCK_SIGNALS:
            for match in pattern.finditer(content):
                value       = match.group(0)
                fingerprint = f"{sig_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = sig_type,
                    value      = value[:128],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "obf_category": "encoding_obfuscation",
                        "technique":    sig_type,
                    },
                ))

        return findings

    def analyze_variable_entropy(self, content: str) -> list[Finding]:
        findings: list[Finding] = []

        hex_vars   = HEX_VAR_PATTERN.findall(content)
        total_vars = len(re.findall(r"""\b[a-zA-Z_$][a-zA-Z0-9_$]*\b""", content))

        if total_vars == 0:
            return findings

        hex_ratio  = len(hex_vars) / total_vars
        unique_hex = len(set(hex_vars))

        if hex_ratio > 0.15 or unique_hex > 20:
            severity = "critical" if hex_ratio > 0.50 else "high" if hex_ratio > 0.30 else "medium"

            findings.append(self._finding(
                type       = "hex_variable_obfuscation",
                value      = f"{unique_hex} unique _0x identifiers ({hex_ratio:.1%} of all vars)",
                severity   = severity,
                context    = "",
                line       = 0,
                confidence = self.CONFIDENCE_HIGH,
                meta       = {
                    "obf_category":   "variable_obfuscation",
                    "hex_var_count":  len(hex_vars),
                    "unique_hex":     unique_hex,
                    "hex_ratio":      round(hex_ratio, 4),
                    "total_vars":     total_vars,
                },
            ))

        string_array_pattern = re.compile(r"""(?:var|const|let)\s+\w+\s*=\s*\[(?:\s*["'][^"']{0,60}["']\s*,?\s*){10,}\]""")
        for match in string_array_pattern.finditer(content):
            line = self._get_line_number(content, match.start())
            findings.append(self._finding(
                type       = "string_array_obfuscation",
                value      = match.group(0)[:128],
                severity   = "high",
                context    = self._get_context(content, match.start()),
                line       = line,
                confidence = self.CONFIDENCE_HIGH,
                meta       = {
                    "obf_category": "string_array",
                    "technique":    "string_array_obfuscation",
                },
            ))

        short_ratio = len(SHORT_VAR_PATTERN.findall(content)) / max(total_vars, 1)
        if short_ratio > 0.70 and total_vars > 50:
            findings.append(self._finding(
                type       = "minifier_obfuscation",
                value      = f"Short identifier ratio: {short_ratio:.1%}",
                severity   = "low",
                context    = "",
                line       = 0,
                confidence = self.CONFIDENCE_MEDIUM,
                meta       = {
                    "obf_category": "minification",
                    "short_ratio":  round(short_ratio, 4),
                    "total_vars":   total_vars,
                },
            ))

        return findings

    def calculate_obf_score(self, content: str) -> list[Finding]:
        findings: list[Finding] = []

        if not content.strip():
            return findings

        score   = 1.0
        signals = {}

        for label, penalty, pattern in READABILITY_PENALTIES:
            matches = pattern.findall(content)
            if matches:
                count        = len(matches)
                adjusted     = penalty * min(count / 10, 1.0)
                score       -= adjusted
                signals[label] = count

        score = max(0.0, round(score, 4))

        avg_line_len = self._average_line_length(content)
        if avg_line_len > 500:
            score = max(0.0, score - 0.20)
            signals["long_lines"] = avg_line_len

        char_entropy = self._content_entropy(content)
        if char_entropy > 5.0:
            score = max(0.0, score - 0.10)
            signals["high_char_entropy"] = round(char_entropy, 4)

        if score < 0.3:
            severity   = "critical"
            confidence = self.CONFIDENCE_HIGH
        elif score < 0.5:
            severity   = "high"
            confidence = self.CONFIDENCE_HIGH
        elif score < 0.7:
            severity   = "medium"
            confidence = self.CONFIDENCE_MEDIUM
        else:
            return findings

        findings.append(self._finding(
            type       = "obfuscation_score",
            value      = f"Readability score: {score:.2f} / 1.00",
            severity   = severity,
            context    = "",
            line       = 0,
            confidence = confidence,
            meta       = {
                "obf_category":    "composite_score",
                "score":           score,
                "avg_line_length": round(avg_line_len, 1),
                "char_entropy":    round(char_entropy, 4),
                "signals":         signals,
            },
        ))

        return findings

    def _run_jsfuck_scan(self, content: str) -> None:
        self.findings.extend(self.detect_jsfuck(content))

    def _run_entropy_scan(self, content: str) -> None:
        self.findings.extend(self.analyze_variable_entropy(content))

    def _run_score_scan(self, content: str) -> None:
        self.findings.extend(self.calculate_obf_score(content))

    @staticmethod
    def _average_line_length(content: str) -> float:
        lines = content.splitlines()
        if not lines:
            return 0.0
        return sum(len(l) for l in lines) / len(lines)

    @staticmethod
    def _content_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq   = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())