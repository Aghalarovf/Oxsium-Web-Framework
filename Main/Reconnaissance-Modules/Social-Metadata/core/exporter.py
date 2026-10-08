import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, BaseLoader


_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SMOSINT Report — {{ meta.target }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --green: #3fb950; --yellow: #d29922;
    --red: #f85149; --text: #c9d1d9; --muted: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }
  h1 { color: var(--accent); margin-bottom: .25rem; font-size: 1.6rem; }
  .meta { color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }
  .module { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  .module-header { padding: .75rem 1rem; background: #21262d; border-bottom: 1px solid var(--border); font-weight: 600; color: var(--accent); display: flex; justify-content: space-between; }
  .badge { font-size: .75rem; padding: .2rem .5rem; border-radius: 20px; background: var(--border); color: var(--muted); }
  .module-body { padding: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; }
  th { text-align: left; padding: .4rem .6rem; color: var(--muted); border-bottom: 1px solid var(--border); font-weight: 500; }
  td { padding: .4rem .6rem; border-bottom: 1px solid #21262d; word-break: break-all; }
  tr:last-child td { border-bottom: none; }
  .tag { display: inline-block; padding: .1rem .4rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }
  .tag-green { background: #1a3a2a; color: var(--green); }
  .tag-yellow { background: #3a2e1a; color: var(--yellow); }
  .tag-red { background: #3a1a1a; color: var(--red); }
  .empty { color: var(--muted); font-style: italic; padding: .5rem 0; }
  a { color: var(--accent); }
</style>
</head>
<body>
<h1>&#128270; SMOSINT Report</h1>
<p class="meta">
  Target: <strong>{{ meta.target }}</strong> &nbsp;|&nbsp;
  Generated: {{ meta.generated_at }} &nbsp;|&nbsp;
  Duration: {{ meta.duration_seconds }}s
</p>
{% for module_name, module_data in results.items() %}
<div class="module">
  <div class="module-header">
    {{ module_name | upper }}
    <span class="badge">{{ module_data | length }} items</span>
  </div>
  <div class="module-body">
    {% if module_data %}
    <table>
      <thead>
        <tr>
          {% for key in module_data[0].keys() %}
          <th>{{ key }}</th>
          {% endfor %}
        </tr>
      </thead>
      <tbody>
        {% for row in module_data %}
        <tr>
          {% for val in row.values() %}
          <td>{{ val }}</td>
          {% endfor %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="empty">No findings.</p>
    {% endif %}
  </div>
</div>
{% endfor %}
</body>
</html>
"""


class Exporter:
    def __init__(self, target: str):
        self._target = target
        self._start_time = datetime.now()
        self._results: dict[str, Any] = {}

    def add_module_result(self, module_name: str, data: Any):
        self._results[module_name] = data

    def _build_report(self) -> dict[str, Any]:
        elapsed = (datetime.now() - self._start_time).total_seconds()
        return {
            "meta": {
                "tool": "social_metadata_osint",
                "version": "1.0.0",
                "target": self._target,
                "generated_at": datetime.now().isoformat(),
                "duration_seconds": round(elapsed, 2),
            },
            "results": self._results,
        }

    def _clean_findings(self, report: dict) -> dict:
        import copy
        report = copy.deepcopy(report)
        results = report.get("results", {})

        for module_name, findings in results.items():
            if not isinstance(findings, list):
                continue

            cleaned = []
            for finding in findings:
                if not isinstance(finding, dict):
                    cleaned.append(finding)
                    continue

                if finding.get("source") == "dork_hint":
                    continue

                finding.pop("dorks", None)
                finding.pop("dork_count", None)
                finding.pop("domain", None)

                if module_name == "html_meta" and finding.get("source") == "link_rel":
                    continue

                cleaned.append(finding)

            results[module_name] = cleaned

        return report

    def to_json(self, path: Optional[str] = None, indent: int = 2,
                strip_dorks: bool = False) -> str:
        report = self._build_report()
        if strip_dorks:
            report = self._clean_findings(report)
        content = json.dumps(report, indent=indent, ensure_ascii=False, default=str)
        if path:
            Path(path).write_text(content, encoding="utf-8")
        return content

    def to_txt(self, path: Optional[str] = None) -> str:
        report = self._clean_findings(self._build_report())
        lines = [
            f"SMOSINT Report",
            f"Target   : {report['meta']['target']}",
            f"Generated: {report['meta']['generated_at']}",
            f"Duration : {report['meta']['duration_seconds']}s",
            "=" * 60,
        ]
        for module, data in report["results"].items():
            lines.append(f"\n[{module.upper()}]")
            if not data:
                lines.append("  No findings.")
                continue
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            lines.append(f"  {k}: {v}")
                        lines.append("")
                    else:
                        lines.append(f"  {item}")
            elif isinstance(data, dict):
                for k, v in data.items():
                    lines.append(f"  {k}: {v}")

        content = "\n".join(lines)
        if path:
            Path(path).write_text(content, encoding="utf-8")
        return content

    def to_html(self, path: Optional[str] = None) -> str:
        report = self._clean_findings(self._build_report())

        flat_results: dict[str, list[dict]] = {}
        for module, data in report["results"].items():
            if isinstance(data, list) and all(isinstance(i, dict) for i in data):
                flat_results[module] = data
            elif isinstance(data, dict):
                flat_results[module] = [{"key": k, "value": str(v)} for k, v in data.items()]
            else:
                flat_results[module] = [{"value": str(data)}]

        env = Environment(loader=BaseLoader())
        tmpl = env.from_string(_HTML_TEMPLATE)
        content = tmpl.render(meta=report["meta"], results=flat_results)

        if path:
            Path(path).write_text(content, encoding="utf-8")
        return content

    def export(self, fmt: str, path: Optional[str] = None) -> str:
        dispatch = {
            "json": self.to_json,
            "txt": self.to_txt,
            "html": self.to_html,
        }
        handler = dispatch.get(fmt)
        if not handler:
            raise ValueError(f"Unsupported export format: {fmt}")
        return handler(path)