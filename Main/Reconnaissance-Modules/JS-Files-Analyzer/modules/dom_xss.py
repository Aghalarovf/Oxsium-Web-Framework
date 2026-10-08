from __future__ import annotations

import re
from typing import Any

from modules.base import BaseJSModule, Finding


SOURCES: list[tuple[str, re.Pattern, str]] = [
    ("location.hash",        re.compile(r"location\.hash"),         "high"),
    ("location.search",      re.compile(r"location\.search"),       "high"),
    ("location.href",        re.compile(r"location\.href"),         "high"),
    ("location.pathname",    re.compile(r"location\.pathname"),     "medium"),
    ("document.URL",         re.compile(r"document\.URL"),          "high"),
    ("document.documentURI", re.compile(r"document\.documentURI"),  "high"),
    ("document.baseURI",     re.compile(r"document\.baseURI"),      "medium"),
    ("document.referrer",    re.compile(r"document\.referrer"),     "medium"),
    ("window.name",          re.compile(r"window\.name"),           "high"),
    ("document.cookie",      re.compile(r"document\.cookie"),       "medium"),
    ("localStorage",         re.compile(r"localStorage\b"),         "medium"),
    ("sessionStorage",       re.compile(r"sessionStorage\b"),       "medium"),
    ("event.data",           re.compile(r"event\.data\b"),          "high"),
    ("URLSearchParams",      re.compile(r"new\s+URLSearchParams"),  "medium"),
    ("history.state",        re.compile(r"history\.state"),         "medium"),
]

SINKS: list[tuple[str, re.Pattern, str, int]] = [
    ("innerHTML",          re.compile(r"(\w[\w.]*)\s*\.\s*innerHTML\s*=(?!=)"),        "high",   1),
    ("outerHTML",          re.compile(r"(\w[\w.]*)\s*\.\s*outerHTML\s*=(?!=)"),        "high",   1),
    ("document.write",     re.compile(r"document\.write(?:ln)?\s*\(([^)]{1,200})\)"), "high",   1),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\([^,]*,\s*([^)]+)\)"),  "high",   1),
    ("eval",               re.compile(r"\beval\s*\(([^)]{1,200})\)"),                 "high",   1),
    ("new_Function",       re.compile(r"\bnew\s+Function\s*\(([^)]{1,200})\)"),       "high",   1),
    ("setTimeout_str",     re.compile(r"setTimeout\s*\(\s*([^,)]{1,200})"),           "high",   1),
    ("setInterval_str",    re.compile(r"setInterval\s*\(\s*([^,)]{1,200})"),          "high",   1),
    ("location.href_set",  re.compile(r"location\.href\s*=(?!=)\s*([^\n;]{1,200})"),  "high",   1),
    ("location.assign",    re.compile(r"location\.assign\s*\(([^)]{1,200})\)"),       "medium", 1),
    ("location.replace",   re.compile(r"location\.replace\s*\(([^)]{1,200})\)"),      "medium", 1),
    ("window.open",        re.compile(r"window\.open\s*\(([^,)]{1,200})"),            "medium", 1),
    ("script.src",         re.compile(r"(\w[\w.]*)\s*\.\s*src\s*=(?!=)\s*([^\n;]{1,200})"), "medium", 2),
    ("jquery.html",        re.compile(r"\$\([^)]+\)\.html\s*\(([^)]{1,200})\)"),     "high",   1),
]

SANITIZE_PATTERN: re.Pattern = re.compile(
    r"\b(?:DOMPurify\.sanitize|sanitizeHtml?|escapeHtml|marked\.parseInline|xss\.process)\s*\(",
    re.IGNORECASE,
)

_LITERAL_PATTERN: re.Pattern = re.compile(
    r"""^[\s(]*(?:["'`][^"'`]*["'`]|[\d]+|true|false|null|undefined|function\s*[\w(]|\([^)]*\)\s*=>|\w+\s*=>)"""
)

_ASSIGN_RE: re.Pattern = re.compile(
    r"(?:var|let|const)\s+(\w[\w$]*)\s*=\s*(.+)"
)

_SHORT_VAR_RE: re.Pattern = re.compile(r"^[a-z]$")

_MAX_PROPAGATION_ITERATIONS: int = 15
_SANITIZE_WINDOW: int = 250
_SOURCE_WINDOW: int = 400


class DomXssTaintModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        tainted = self._build_taint_map(content)
        tainted = self._propagate_taint(content, tainted)
        chain_findings = self._run_taint_sink_scan(content, tainted)

        self.findings.extend(chain_findings)
        return self.findings

    def _build_taint_map(self, content: str) -> dict[str, dict[str, Any]]:
        lines    = content.splitlines()
        tainted: dict[str, dict[str, Any]] = {}

        for src_name, src_pat, sev in SOURCES:
            for match in src_pat.finditer(content):
                ln       = content[: match.start()].count("\n")
                line_txt = lines[ln].strip() if ln < len(lines) else ""

                assign_match = re.search(
                    r"(?:var|let|const)\s+(\w[\w$]*)\s*=\s*(?:.*?)?" + src_pat.pattern,
                    line_txt,
                )
                if assign_match:
                    var_name = assign_match.group(1)
                    if var_name not in tainted:
                        tainted[var_name] = {
                            "source":  src_name,
                            "sev":     sev,
                            "line":    ln + 1,
                            "snippet": line_txt,
                        }
                    continue

                prop_match = re.search(
                    r"(\w[\w$]*(?:\.\w[\w$]*)+)\s*=\s*(?:.*?)?" + src_pat.pattern,
                    line_txt,
                )
                if prop_match:
                    var_name = prop_match.group(1)
                    if var_name not in tainted:
                        tainted[var_name] = {
                            "source":  src_name,
                            "sev":     sev,
                            "line":    ln + 1,
                            "snippet": line_txt,
                        }

        return tainted

    def _propagate_taint(
        self,
        content: str,
        tainted: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        lines     = content.splitlines()
        changed   = True
        iteration = 0

        while changed and iteration < _MAX_PROPAGATION_ITERATIONS:
            changed   = False
            iteration += 1
            for ln_i, line_txt in enumerate(lines):
                m = _ASSIGN_RE.search(line_txt)
                if not m:
                    continue
                new_var = m.group(1)
                rhs     = m.group(2)
                if new_var in tainted:
                    continue
                for tv, info in list(tainted.items()):
                    if re.search(r"\b" + re.escape(tv) + r"\b", rhs):
                        tainted[new_var] = {
                            "source":  info["source"],
                            "sev":     info["sev"],
                            "line":    ln_i + 1,
                            "snippet": line_txt.strip(),
                            "via":     tv,
                        }
                        changed = True
                        break

        return tainted

    def _run_taint_sink_scan(
        self,
        content: str,
        tainted: dict[str, dict[str, Any]],
    ) -> list[Finding]:
        lines:    list[str]  = content.splitlines()
        findings: list[Finding] = []
        seen:     set[str]   = set()

        for sink_name, sink_pat, sink_sev, grp in SINKS:
            for match in sink_pat.finditer(content):
                ln       = content[: match.start()].count("\n")
                line_txt = lines[ln].strip() if ln < len(lines) else ""

                try:
                    sink_expr = match.group(grp).strip()
                except IndexError:
                    sink_expr = match.group(0)

                fingerprint = f"{sink_name}:{ln + 1}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                if self._is_literal_expression(sink_expr):
                    continue

                if self._is_safe_callback(sink_name, sink_expr):
                    continue

                if self._is_self_assignment(sink_name, line_txt):
                    continue

                sanitized     = self._has_sanitization_hint(content, match.start())
                matched_taint = self._match_tainted_var(sink_expr, tainted)
                direct_source = self._find_direct_source(sink_expr)

                if not matched_taint and not direct_source:
                    continue

                effective_sev = self._resolve_severity(
                    sink_sev,
                    matched_taint["sev"] if matched_taint else None,
                    direct_source[1]     if direct_source  else None,
                    sanitized,
                )

                findings.append(self._finding(
                    type       = f"taint_chain_{sink_name}",
                    value      = sink_expr[:256],
                    severity   = effective_sev,
                    context    = self._get_context(content, match.start()),
                    line       = ln + 1,
                    confidence = self.CONFIDENCE_LOW if sanitized else self.CONFIDENCE_HIGH,
                    meta       = self._build_chain_meta(
                        sink_name, sink_expr, matched_taint, direct_source, sanitized
                    ),
                ))

        return findings

    @staticmethod
    def _is_literal_expression(expr: str) -> bool:
        return bool(_LITERAL_PATTERN.match(expr))

    @staticmethod
    def _is_safe_callback(sink_name: str, expr: str) -> bool:
        if sink_name not in ("setTimeout_str", "setInterval_str"):
            return False
        stripped = expr.strip()
        return bool(re.match(
            r"(?:function\b|\([^)]*\)\s*=>|\w+\s*=>|\w[\w$.]*\s*(?:,|$))",
            stripped,
        ))

    @staticmethod
    def _is_self_assignment(sink_name: str, line_txt: str) -> bool:
        if sink_name == "location.href_set":
            if re.search(r"location\.href\s*=\s*location\.href", line_txt):
                return True
        if sink_name == "script.src":
            if re.search(r"(\w[\w.]*)\s*\.\s*src\s*=\s*\1\s*\.\s*src", line_txt):
                return True
        return False

    @staticmethod
    def _match_tainted_var(
        expr: str,
        tainted: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        candidates = re.findall(r"\b([a-zA-Z_$][a-zA-Z0-9_$]{1,})\b", expr)
        for v in candidates:
            if v in tainted and not _SHORT_VAR_RE.match(v):
                return tainted[v]
        return None

    @staticmethod
    def _find_direct_source(expr: str) -> tuple[str, str] | None:
        for src_name, src_pat, sev in SOURCES:
            if src_pat.search(expr):
                return (src_name, sev)
        return None

    @staticmethod
    def _resolve_severity(
        sink_sev:   str,
        taint_sev:  str | None,
        source_sev: str | None,
        sanitized:  bool,
    ) -> str:
        order      = ["low", "medium", "high", "critical"]
        candidates = [sink_sev]
        if taint_sev:
            candidates.append(taint_sev)
        if source_sev:
            candidates.append(source_sev)
        resolved = max(candidates, key=lambda s: order.index(s) if s in order else 0)
        if sanitized and resolved in ("high", "critical"):
            return "medium"
        return resolved

    @staticmethod
    def _build_chain_meta(
        sink_name:     str,
        sink_expr:     str,
        matched_taint: dict[str, Any] | None,
        direct_source: tuple[str, str] | None,
        sanitized:     bool,
    ) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "taint_category":        "confirmed_chain",
            "sink":                  sink_name,
            "sink_expr":             sink_expr[:128],
            "sanitization_detected": sanitized,
            "confirmed":             True,
        }
        if matched_taint:
            meta["source"]         = matched_taint["source"]
            meta["source_line"]    = matched_taint["line"]
            meta["source_snippet"] = matched_taint.get("snippet", "")[:128]
            if "via" in matched_taint:
                meta["propagated_via"] = matched_taint["via"]
        if direct_source:
            meta["direct_source"] = direct_source[0]
        return meta

    @staticmethod
    def _has_sanitization_hint(content: str, pos: int) -> bool:
        snippet = content[max(0, pos - _SANITIZE_WINDOW): pos + _SANITIZE_WINDOW]
        return bool(SANITIZE_PATTERN.search(snippet))


DomXssModule = DomXssTaintModule