import json
import csv
import os
from datetime import datetime
from typing import Optional


class Exporter:

    def export(
        self,
        results: list[dict],
        fmt: str,
        path: str,
        target: str,
    ):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

        dispatch = {
            "txt":  self._export_txt,
            "json": self._export_json,
            "csv":  self._export_csv,
            "html": self._export_html,
        }

        handler = dispatch.get(fmt)
        if handler is None:
            raise ValueError(f"Unsupported export format: {fmt}")

        handler(results=results, path=path, target=target)

    def _export_txt(self, results: list[dict], path: str, target: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"Dorking Report\n")
            fh.write(f"Target  : {target}\n")
            fh.write(f"Date    : {ts}\n")
            fh.write(f"Results : {len(results)}\n")
            fh.write("=" * 70 + "\n\n")

            for r in results:
                fh.write(f"[{r.get('module', '')}] {r.get('description', '')}\n")
                fh.write(f"  Dork : {r.get('dork', '')}\n")
                if r.get("url"):
                    fh.write(f"  URL  : {r.get('url')}\n")
                fh.write("\n")

    def _export_json(self, results: list[dict], path: str, target: str):
        payload = {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "total": len(results),
            "results": results,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    def _export_csv(self, results: list[dict], path: str, target: str):
        fieldnames = ["module", "category", "description", "dork", "url", "severity"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, "") for k in fieldnames})

    def _export_html(self, results: list[dict], path: str, target: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows = ""
        for r in results:
            severity = r.get("severity", "info")
            sev_class = {
                "critical": "sev-critical",
                "high":     "sev-high",
                "medium":   "sev-medium",
                "low":      "sev-low",
                "info":     "sev-info",
            }.get(severity, "sev-info")

            url_cell = (
                f'<a href="{r.get("url")}" target="_blank">{r.get("url")}</a>'
                if r.get("url") else "—"
            )

            rows += (
                f"<tr>"
                f"<td>{r.get('module', '')}</td>"
                f"<td>{r.get('category', '')}</td>"
                f"<td>{r.get('description', '')}</td>"
                f"<td><code>{r.get('dork', '')}</code></td>"
                f"<td>{url_cell}</td>"
                f"<td><span class='sev {sev_class}'>{severity}</span></td>"
                f"</tr>\n"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dorking Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; margin-bottom: 0.25rem; }}
  .meta {{ color: #8b949e; font-size: 0.875rem; margin-bottom: 2rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #161b22; color: #58a6ff; padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #30363d; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; color: #e6edf3; word-break: break-all; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .sev {{ padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .sev-critical {{ background: #3d1515; color: #ff7b72; }}
  .sev-high     {{ background: #3d2100; color: #ffa657; }}
  .sev-medium   {{ background: #2d2a00; color: #e3b341; }}
  .sev-low      {{ background: #0d2d13; color: #3fb950; }}
  .sev-info     {{ background: #0d1d30; color: #79c0ff; }}
</style>
</head>
<body>
  <h1>Dorking Report</h1>
  <p class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {ts} &nbsp;|&nbsp; Total: {len(results)}</p>
  <table>
    <thead>
      <tr>
        <th>Module</th>
        <th>Category</th>
        <th>Description</th>
        <th>Dork</th>
        <th>URL</th>
        <th>Severity</th>
      </tr>
    </thead>
    <tbody>
{rows}    </tbody>
  </table>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)