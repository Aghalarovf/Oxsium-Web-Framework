from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, TextIO
from urllib.parse import urlparse

from modules.base import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high":     "\033[31m",
    "medium":   "\033[33m",
    "low":      "\033[34m",
    "info":     "\033[37m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
}


class Reporter:

    def __init__(self, use_color: bool = True, stream: TextIO = sys.stdout) -> None:
        self.use_color = use_color and stream.isatty()
        self.stream    = stream

    def to_json(
        self,
        findings:  list[Finding],
        target:    str,
        meta:      dict[str, Any] | None = None,
    ) -> str:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target":       target,
            "meta":         meta or {},
            "summary":      self._build_summary(findings),
            "findings":     [asdict(f) for f in self._sorted(findings)],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def to_console(self, findings: list[Finding], target: str) -> None:
        self._print_header(target, findings)
        for f in self._sorted(findings):
            self._print_finding(f)
        self._print_footer(findings)

    def to_console_grouped(
        self,
        results: list[Any],   # list[ScanResult]
        target:  str,
    ) -> None:
        """Print findings split into Internal and External JS sections."""
        target_host = self._host(target)

        internal: list[tuple[str, Finding]] = []
        external: list[tuple[str, Finding]] = []

        for r in results:
            if r.error or not r.findings:
                continue
            src_url  = r.target.value
            src_host = self._host(src_url)
            bucket   = internal if self._same_host(src_host, target_host) else external
            for f in r.findings:
                bucket.append((src_url, f))

        all_findings = [f for _, f in internal + external]

        b = SEVERITY_COLORS["bold"]  if self.use_color else ""
        d = SEVERITY_COLORS["dim"]   if self.use_color else ""
        r = SEVERITY_COLORS["reset"] if self.use_color else ""

        self._write(f"\n{b}Target:{r} {target}")
        self._write(f"{d}{'─' * 60}{r}")

        if internal:
            self._write(f"\n{b}[ Internal JS ]{r}")
            self._print_grouped_section(internal)
        else:
            self._write(f"\n{d}[ Internal JS ]  no findings{r}")

        if external:
            self._write(f"\n{b}[ External JS ]{r}")
            self._print_grouped_section(external)
        else:
            self._write(f"\n{d}[ External JS ]  no findings{r}")

        self._write("")
        self._print_footer(all_findings)

    def _print_grouped_section(self, items: list[tuple[str, Finding]]) -> None:
        """Group items by source URL and print compactly."""
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for src, f in items:
            grouped[src].append(f)

        d = SEVERITY_COLORS["dim"]   if self.use_color else ""
        r = SEVERITY_COLORS["reset"] if self.use_color else ""

        for src_url, findings in grouped.items():
            self._write(f"\n  {d}{src_url}{r}")
            for f in self._sorted(findings):
                self._print_finding(f)

    def save_json(self, findings: list[Finding], target: str, path: str, meta: dict[str, Any] | None = None) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json(findings, target, meta))

    def _build_summary(self, findings: list[Finding]) -> dict[str, Any]:
        by_severity: dict[str, int] = defaultdict(int)
        by_module:   dict[str, int] = defaultdict(int)
        by_type:     dict[str, int] = defaultdict(int)

        for f in findings:
            by_severity[f.severity] += 1
            by_module[f.module]     += 1
            by_type[f.type]         += 1

        return {
            "total":       len(findings),
            "by_severity": dict(by_severity),
            "by_module":   dict(by_module),
            "by_type":     dict(by_type),
        }

    def _print_header(self, target: str, findings: list[Finding]) -> None:
        b = SEVERITY_COLORS["bold"]   if self.use_color else ""
        r = SEVERITY_COLORS["reset"]  if self.use_color else ""
        d = SEVERITY_COLORS["dim"]    if self.use_color else ""

        self._write(f"\n{b}{'─' * 60}{r}")
        self._write(f"{b}  JS ANALYZER REPORT{r}")
        self._write(f"{d}  Target  : {target}{r}")
        self._write(f"{d}  Findings: {len(findings)}{r}")
        self._write(f"{b}{'─' * 60}{r}\n")

    # Badge labels per severity
    _BADGE: dict[str, str] = {
        "critical": "CRIT",
        "high":     "HIGH",
        "medium":   "WARN",
        "low":      "LOW ",
        "info":     " OK ",
    }

    def _print_finding(self, f: Finding) -> None:
        color = SEVERITY_COLORS.get(f.severity, "") if self.use_color else ""
        reset = SEVERITY_COLORS["reset"]             if self.use_color else ""
        bold  = SEVERITY_COLORS["bold"]              if self.use_color else ""
        badge = self._BADGE.get(f.severity, " ?? ")
        value = f.value[:80].split("\n")[0].strip()
        line  = f"  line {f.line}" if f.line else ""
        self._write(f"  {color}{bold}[{badge}]{reset}  {value}{color}{line}{reset}")

    def _print_footer(self, findings: list[Finding]) -> None:
        summary = self._build_summary(findings)
        d = SEVERITY_COLORS["dim"]   if self.use_color else ""
        r = SEVERITY_COLORS["reset"] if self.use_color else ""
        b = SEVERITY_COLORS["bold"]  if self.use_color else ""

        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = summary["by_severity"].get(sev, 0)
            if count:
                color = SEVERITY_COLORS.get(sev, "") if self.use_color else ""
                parts.append(f"{color}{sev.upper()} {count}{r}")

        self._write(f"{d}{'─' * 60}{r}")
        totals = "  ".join(parts) if parts else "no findings"
        self._write(f"{b}Total:{r} {summary['total']}   {totals}\n")

    def _sorted(self, findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.module, f.line))

    def _write(self, line: str) -> None:
        print(line, file=self.stream)

    @staticmethod
    def _host(url: str) -> str:
        try:
            return urlparse(url).netloc.lower().lstrip("www.")
        except Exception:
            return ""

    @staticmethod
    def _same_host(a: str, b: str) -> bool:
        if not a or not b:
            return False
        return a == b or a.endswith(f".{b}") or b.endswith(f".{a}")