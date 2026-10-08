"""
core/exporter.py - Report generation and output.

Collects per-module findings into a unified structure and writes them either
to stdout (pretty-printed) or to a JSON file, depending on --output.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logger import get_logger

log = get_logger("exporter")


# ── Severity constants (used as sortable strings) ─────────────────────────────
class Severity:
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    # Rank used for sorting findings from most to least severe
    _RANK: Dict[str, int] = {
        INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
    }

    @classmethod
    def rank(cls, severity: str) -> int:
        """Return the numeric rank of a severity label (higher = worse)."""
        return cls._RANK.get(severity.upper(), -1)


class Finding:
    """
    A single security observation produced by one module.

    Parameters
    ----------
    module   : Name of the module that raised this finding (e.g. "waf").
    title    : Short, human-readable title.
    severity : One of INFO / LOW / MEDIUM / HIGH / CRITICAL.
    detail   : Full explanation of what was found.
    evidence : Raw strings collected as evidence (headers, body fragments, …).
    """

    def __init__(
        self,
        module: str,
        title: str,
        severity: str,
        detail: str,
        evidence: Optional[List[str]] = None,
    ) -> None:
        self.module   = module
        self.title    = title
        self.severity = severity.upper()
        self.detail   = detail
        self.evidence = evidence or []

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict so the report JSON is self-contained."""
        return {
            "module":   self.module,
            "severity": self.severity,
            "title":    self.title,
            "detail":   self.detail,
            "evidence": self.evidence,
        }


class Report:
    """
    Accumulates findings from all modules and renders the final report.

    Usage
    -----
    report = Report(target="https://example.com")
    report.add(Finding(...))
    report.write(output_path=None)   # Print to stdout
    """

    def __init__(self, target: str) -> None:
        self.target   = target
        self.started  = datetime.now(timezone.utc)
        self._findings: List[Finding] = []

    # ── Mutation ──────────────────────────────────────────────────────────────

    def add(self, finding: Finding) -> None:
        """Append a single Finding to the report."""
        self._findings.append(finding)
        log.debug(
            f"[{finding.severity}] {finding.module} → {finding.title}"
        )

    def add_many(self, findings: List[Finding]) -> None:
        """Append multiple findings at once (convenience wrapper)."""
        for f in findings:
            self.add(f)

    # ── Queries ───────────────────────────────────────────────────────────────

    def findings_by_module(self, module: str) -> List[Finding]:
        """Return all findings produced by a specific module."""
        return [f for f in self._findings if f.module == module]

    @property
    def highest_severity(self) -> str:
        """Return the most critical severity across all findings."""
        if not self._findings:
            return Severity.INFO
        return max(
            self._findings,
            key=lambda f: Severity.rank(f.severity),
        ).severity

    # ── Serialisation ─────────────────────────────────────────────────────────

    def _to_dict(self) -> Dict[str, Any]:
        """Build the full report dictionary."""
        finished = datetime.now(timezone.utc)
        duration = (finished - self.started).total_seconds()

        # Sort findings: most severe first, then alphabetically by module/title
        sorted_findings = sorted(
            self._findings,
            key=lambda f: (-Severity.rank(f.severity), f.module, f.title),
        )

        return {
            "meta": {
                "tool":            "appsec",
                "target":          self.target,
                "started_utc":     self.started.isoformat(),
                "finished_utc":    finished.isoformat(),
                "duration_seconds": round(duration, 2),
                "total_findings":  len(self._findings),
                "highest_severity": self.highest_severity,
            },
            "findings": [f.to_dict() for f in sorted_findings],
        }

    # ── Output ────────────────────────────────────────────────────────────────

    def write(self, output_path: Optional[str] = None) -> None:
        """
        Write the report as formatted JSON.

        Parameters
        ----------
        output_path : File path to write to.  Pass None to print to stdout.
        """
        data   = self._to_dict()
        pretty = json.dumps(data, indent=2, ensure_ascii=False)

        if output_path is None:
            # Print a visual separator then the JSON block
            print("\n" + "=" * 60)
            print(f"  AppSec Report  ·  {self.target}")
            print("=" * 60)
            print(pretty)
            print("=" * 60 + "\n")
        else:
            path = Path(output_path)
            path.write_text(pretty, encoding="utf-8")
            log.info(f"Report written to {path.resolve()}")

        # Always print a brief summary to the terminal
        self._print_summary(data)

    def _print_summary(self, data: Dict[str, Any]) -> None:
        """Print a compact severity-grouped summary to stdout."""
        meta     = data["meta"]
        findings = data["findings"]

        print(f"\n{'─'*50}")
        print(f"  Target  : {meta['target']}")
        print(f"  Duration: {meta['duration_seconds']}s")
        print(f"  Total   : {meta['total_findings']} finding(s)  "
              f"[highest: {meta['highest_severity']}]")
        print(f"{'─'*50}")

        if not findings:
            print("  No findings recorded.")
        else:
            for sev in [Severity.CRITICAL, Severity.HIGH,
                        Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                group = [f for f in findings if f["severity"] == sev]
                if group:
                    print(f"\n  [{sev}]")
                    for f in group:
                        print(f"    • [{f['module']}] {f['title']}")

        print(f"{'─'*50}\n")