import csv
import json
import os
from datetime import datetime
from typing import Any


class Exporter:

    def __init__(self, results: dict) -> None:
        self._results = results
        self._generated_at = datetime.now().isoformat()

    def export(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        ext = os.path.splitext(filepath)[1].lower()
        dispatch = {
            ".json": self._export_json,
            ".csv": self._export_csv,
            ".html": self._export_html,
            ".txt": self._export_txt,
        }
        handler = dispatch.get(ext, self._export_txt)
        handler(filepath)

    def _export_json(self, filepath: str) -> None:
        payload = {
            "generated_at": self._generated_at,
            "results": self._results,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

    def _export_csv(self, filepath: str) -> None:
        rows: list[dict] = []
        for domain, modules in self._results.items():
            for module_name, data in modules.items():
                rows.append({
                    "domain": domain,
                    "module": module_name,
                    "data": json.dumps(data, default=str),
                })
        if not rows:
            return
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain", "module", "data"])
            writer.writeheader()
            writer.writerows(rows)

    def _export_html(self, filepath: str) -> None:
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "<title>Email Infrastructure Enumeration Report</title>",
            "<style>",
            "  body { font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 2rem; }",
            "  h1 { color: #58a6ff; }",
            "  h2 { color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 0.3rem; }",
            "  h3 { color: #56d364; }",
            "  pre { background: #161b22; padding: 1rem; border-radius: 6px; overflow-x: auto; }",
            "  .meta { color: #8b949e; font-size: 0.85rem; }",
            "  .domain-block { border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }",
            "</style>",
            "</head>",
            "<body>",
            "<h1>Email Infrastructure Enumeration Report</h1>",
            f"<p class='meta'>Generated: {self._generated_at}</p>",
        ]

        for domain, modules in self._results.items():
            html_parts.append(f"<div class='domain-block'>")
            html_parts.append(f"<h2>{domain}</h2>")
            for module_name, data in modules.items():
                html_parts.append(f"<h3>{module_name}</h3>")
                html_parts.append(f"<pre>{json.dumps(data, indent=2, default=str)}</pre>")
            html_parts.append("</div>")

        html_parts += ["</body>", "</html>"]
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))

    def _export_txt(self, filepath: str) -> None:
        lines: list[str] = [
            "EMAIL INFRASTRUCTURE ENUMERATION REPORT",
            f"Generated: {self._generated_at}",
            "=" * 60,
        ]
        for domain, modules in self._results.items():
            lines.append(f"\nDOMAIN: {domain}")
            lines.append("-" * 60)
            for module_name, data in modules.items():
                lines.append(f"\n[{module_name.upper()}]")
                lines.append(json.dumps(data, indent=2, default=str))
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))