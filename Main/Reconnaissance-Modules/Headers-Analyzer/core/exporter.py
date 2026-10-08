import json
from html import escape
from typing import Dict, Any


class Exporter:
    def __init__(self, output_path: str, output_format: str):
        self.output_path = output_path
        self.output_format = output_format.lower()

    def export(self, scan_result: Dict[str, Any]):
        if self.output_format == "json":
            self._export_json(scan_result)
        elif self.output_format == "html":
            self._export_html(scan_result)
        else:
            self._export_txt(scan_result)

    def _export_json(self, data: Dict[str, Any]):
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)

    def _export_txt(self, data: Dict[str, Any]):
        lines = []
        lines.append("=" * 60)
        lines.append("HTTP HEADERS ANALYSIS REPORT (OFFLINE)")
        lines.append("=" * 60)
        lines.append(f"Intercept Files    : {', '.join(data.get('intercept_files', []))}")
        lines.append(f"Analysis Time      : {data.get('timestamp', 'N/A')}")
        lines.append(f"Records Read       : {data.get('records_read', 0)}")
        lines.append(f"Responses Analyzed : {data.get('responses_analyzed', 0)}")
        lines.append(f"Entries Shown      : {data.get('entries_with_unique_results', len(data.get('entries', [])))}")
        lines.append("")

        for entry in data.get("entries", []):
            lines.append("=" * 60)
            lines.append(f"[#{entry.get('id')}] {entry.get('method')} {entry.get('url')} -> {entry.get('status_code')}")
            lines.append("=" * 60)

            for module_name, module_data in entry.get("modules", {}).items():
                lines.append("-" * 60)
                lines.append(f"[MODULE] {module_name.upper()}")
                lines.append("-" * 60)
                if module_data.get("error"):
                    lines.append(f"  Module error: {module_data['error']}")
                findings = module_data.get("findings", [])
                if not findings and not module_data.get("error"):
                    lines.append("  No findings.")
                for finding in findings:
                    sev = finding.get("severity", "INFO")
                    header = finding.get("header", "")
                    detail = finding.get("detail", "")
                    lines.append(f"  [{sev}] {header}: {detail}")
                lines.append("")

            score_data = entry.get("score")
            if score_data:
                lines.append(f"SECURITY GRADE : {score_data.get('grade', 'N/A')}")
                lines.append(f"SECURITY SCORE : {score_data.get('score', 0)}/100")
                recs = score_data.get("recommendations", [])
                if recs:
                    lines.append("RECOMMENDATIONS:")
                    for r in recs:
                        lines.append(f"  - {r}")
                lines.append("")

        overview = data.get("websocket")
        if overview:
            totals = overview.get("totals", {})
            lines.append("=" * 60)
            lines.append("WEBSOCKET OVERVIEW")
            lines.append("=" * 60)
            lines.append(
                f"  Handshakes: {totals.get('handshakes', 0)} "
                f"(accepted={totals.get('accepted', 0)}, rejected={totals.get('rejected', 0)}); "
                f"other protocol switches: {totals.get('other_upgrades', 0)}"
            )
            for row in overview.get("endpoints", []):
                statuses = ", ".join(f"{code} x{count}" for code, count in sorted(row.get("statuses", {}).items()))
                lines.append(f"  {row.get('endpoint')}")
                lines.append(f"    Attempts       : {row.get('attempts')} (accepted={row.get('accepted')}, rejected={row.get('rejected')})")
                lines.append(f"    Statuses       : {statuses}")
                lines.append(f"    Worst severity : {row.get('worst_severity')}")
                if row.get("origins"):
                    lines.append(f"    Origins        : {'; '.join(row['origins'])}")
                if row.get("authentication"):
                    lines.append(f"    Authentication : {', '.join(row['authentication'])}")
                if row.get("subprotocols"):
                    lines.append(f"    Subprotocols   : {', '.join(row['subprotocols'])}")
                if row.get("extensions"):
                    lines.append(f"    Extensions     : {', '.join(row['extensions'])}")
                if row.get("frameworks"):
                    lines.append(f"    Fingerprint    : {', '.join(row['frameworks'])}")
                lines.append(f"    Entries        : {', '.join(str(i) for i in row.get('entry_ids', []))}")
            for note in overview.get("notes", []):
                lines.append(f"  Note: {note}")
            lines.append("")

        lines.append("=" * 60)
        lines.append("SUMMARY - UNIQUE FINDINGS")
        lines.append("=" * 60)
        summary = data.get("summary", [])
        if not summary:
            lines.append("  No findings.")
        for item in summary:
            ids = ", ".join(str(i) for i in item.get("entry_ids", []))
            more = item.get("entries_total", 0) - len(item.get("entry_ids", []))
            if more > 0:
                ids += f" (+{more} more)"
            lines.append(
                f"  [{item.get('severity')}] {item.get('header')}: {item.get('detail')} "
                f"(x{item.get('count')}; entries: {ids})"
            )

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _export_html(self, data: Dict[str, Any]):
        severity_colors = {
            "CRITICAL": "#ff4d94",
            "HIGH": "#e74c3c",
            "MEDIUM": "#e67e22",
            "LOW": "#3498db",
            "INFO": "#95a5a6",
            "OK": "#2ecc71",
        }
        grade_colors = {
            "A+": "#2ecc71", "A": "#27ae60", "B": "#f1c40f",
            "C": "#e67e22", "D": "#e74c3c", "F": "#c0392b",
        }

        def sev_cell(severity: str) -> str:
            color = severity_colors.get(str(severity).upper(), "#ccc")
            return f"<span style='color:{color};font-weight:bold'>{escape(str(severity))}</span>"

        entries_html = ""
        for entry in data.get("entries", []):
            modules_html = ""
            for module_name, module_data in entry.get("modules", {}).items():
                rows = ""
                if module_data.get("error"):
                    rows += f"<tr><td colspan='3'>Module error: {escape(str(module_data['error']))}</td></tr>"
                for f in module_data.get("findings", []):
                    rows += (
                        f"<tr>"
                        f"<td>{sev_cell(f.get('severity', 'INFO'))}</td>"
                        f"<td>{escape(str(f.get('header', '')))}</td>"
                        f"<td>{escape(str(f.get('detail', '')))}</td>"
                        f"</tr>"
                    )
                if not rows:
                    rows = "<tr><td colspan='3'>No findings</td></tr>"
                modules_html += f"""
                <h3>{escape(module_name)}</h3>
                <table>
                    <thead><tr><th>Severity</th><th>Header</th><th>Detail</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
                """

            score_html = ""
            score_data = entry.get("score")
            if score_data:
                grade = str(score_data.get("grade", "N/A"))
                color = grade_colors.get(grade, "#ccc")
                recs = "".join(f"<li>{escape(str(r))}</li>" for r in score_data.get("recommendations", []))
                score_html = f"""
                <p>Grade: <span style="color:{color};font-size:1.6em;font-weight:bold">{escape(grade)}</span>
                &nbsp;&nbsp; Score: <strong>{escape(str(score_data.get('score', 0)))}/100</strong></p>
                {'<ul>' + recs + '</ul>' if recs else ''}
                """

            entries_html += f"""
            <div class="module">
                <h2>#{escape(str(entry.get('id')))} {escape(str(entry.get('method')))}
                    {escape(str(entry.get('url')))} &rarr; {escape(str(entry.get('status_code')))}</h2>
                {modules_html}
                {score_html}
            </div>
            """

        summary_rows = ""
        for item in data.get("summary", []):
            ids = ", ".join(str(i) for i in item.get("entry_ids", []))
            more = item.get("entries_total", 0) - len(item.get("entry_ids", []))
            if more > 0:
                ids += f" (+{more} more)"
            summary_rows += (
                f"<tr><td>{sev_cell(item.get('severity', 'INFO'))}</td>"
                f"<td>{escape(str(item.get('header', '')))}</td>"
                f"<td>{escape(str(item.get('detail', '')))}</td>"
                f"<td>{escape(str(item.get('count', 0)))}</td>"
                f"<td>{escape(ids)}</td></tr>"
            )
        if not summary_rows:
            summary_rows = "<tr><td colspan='5'>No findings</td></tr>"

        ws_html = ""
        overview = data.get("websocket")
        if overview:
            ws_rows = ""
            for row in overview.get("endpoints", []):
                statuses = ", ".join(f"{code} x{count}" for code, count in sorted(row.get("statuses", {}).items()))
                details = "; ".join(filter(None, [
                    "Origins: " + ", ".join(row["origins"]) if row.get("origins") else "",
                    "Auth: " + ", ".join(row["authentication"]) if row.get("authentication") else "",
                    "Subprotocols: " + ", ".join(row["subprotocols"]) if row.get("subprotocols") else "",
                    "Extensions: " + ", ".join(row["extensions"]) if row.get("extensions") else "",
                    "Fingerprint: " + ", ".join(row["frameworks"]) if row.get("frameworks") else "",
                ]))
                ws_rows += (
                    f"<tr><td>{sev_cell(row.get('worst_severity', 'INFO'))}</td>"
                    f"<td>{escape(str(row.get('endpoint', '')))}</td>"
                    f"<td>{escape(str(row.get('attempts', 0)))} (ok={escape(str(row.get('accepted', 0)))}, "
                    f"rejected={escape(str(row.get('rejected', 0)))})</td>"
                    f"<td>{escape(statuses)}</td>"
                    f"<td>{escape(details)}</td></tr>"
                )
            if not ws_rows:
                ws_rows = "<tr><td colspan='5'>No WebSocket handshakes detected</td></tr>"
            ws_notes = "".join(f"<li>{escape(str(n))}</li>" for n in overview.get("notes", []))
            ws_html = f"""
    <div class="module">
        <h2>WebSocket Overview</h2>
        <table>
            <thead><tr><th>Worst</th><th>Endpoint</th><th>Attempts</th><th>Statuses</th><th>Details</th></tr></thead>
            <tbody>{ws_rows}</tbody>
        </table>
        <ul>{ws_notes}</ul>
    </div>"""

        files = escape(", ".join(data.get("intercept_files", [])))
        timestamp = escape(str(data.get("timestamp", "N/A")))
        analyzed = escape(str(data.get("responses_analyzed", 0)))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Headers Analysis Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
        h1 {{ color: #58a6ff; margin-bottom: 0.5rem; }}
        .meta {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }}
        .module {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1.5rem; padding: 1.5rem; }}
        h2 {{ color: #58a6ff; margin-bottom: 1rem; font-size: 1.05rem; word-break: break-all; }}
        h3 {{ color: #8b949e; margin: 1rem 0 0.5rem; font-size: 0.95rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #21262d; color: #8b949e; text-align: left; padding: 8px 12px; font-size: 0.85rem; }}
        td {{ padding: 8px 12px; border-top: 1px solid #30363d; font-size: 0.9rem; vertical-align: top; word-break: break-word; }}
        tr:hover td {{ background: #1c2128; }}
        ul {{ padding-left: 1.5rem; margin-top: 0.5rem; }}
        li {{ margin-bottom: 0.3rem; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <h1>HTTP Headers Analysis Report (Offline)</h1>
    <div class="meta">
        <span>Files: <strong>{files}</strong></span> &nbsp;|&nbsp;
        <span>Responses analyzed: <strong>{analyzed}</strong></span> &nbsp;|&nbsp;
        <span>Generated: {timestamp}</span>
    </div>
    <div class="module">
        <h2>Summary - Unique Findings</h2>
        <table>
            <thead><tr><th>Severity</th><th>Header</th><th>Detail</th><th>Count</th><th>Entries</th></tr></thead>
            <tbody>{summary_rows}</tbody>
        </table>
    </div>
    {ws_html}
    {entries_html}
</body>
</html>"""

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html)
