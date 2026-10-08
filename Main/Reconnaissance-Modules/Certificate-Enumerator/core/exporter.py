import json
import datetime
from typing import Dict, Any, Optional


class Exporter:
    def __init__(self, domain: str, port: int, sni: str):
        self.domain = domain
        self.port = port
        self.sni = sni
        self._results: Dict[str, Any] = {}
        self._meta: Dict[str, Any] = {
            "scanner": "TLS Scanner v0.1",
            "target": f"{domain}:{port}",
            "sni": sni,
            "scan_time": datetime.datetime.utcnow().isoformat() + "Z",
        }

    def add_module_result(self, module_name: str, data: Dict[str, Any]) -> None:
        self._results[module_name] = data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": self._meta,
            "results": self._results,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=self._json_default)

    def save(self, filepath: str, as_json: bool = False) -> None:
        if as_json:
            content = self.to_json()
        else:
            content = self._to_text()

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    def _to_text(self) -> str:
        lines = []
        meta = self._meta
        lines.append("=" * 60)
        lines.append(f"  TLS Scanner Report")
        lines.append("=" * 60)
        lines.append(f"Target    : {meta['target']}")
        lines.append(f"SNI       : {meta['sni']}")
        lines.append(f"Scan Time : {meta['scan_time']}")
        lines.append("")

        for module_name, data in self._results.items():
            lines.append(f"[{module_name.upper()}]")
            lines.append("-" * 40)
            lines.append(self._flatten_dict(data))
            lines.append("")

        return "\n".join(lines)

    def _flatten_dict(self, d: Any, indent: int = 0) -> str:
        lines = []
        prefix = "  " * indent
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{prefix}{k}:")
                    lines.append(self._flatten_dict(v, indent + 1))
                else:
                    lines.append(f"{prefix}{k}: {v}")
        elif isinstance(d, list):
            for item in d:
                lines.append(self._flatten_dict(item, indent))
        else:
            lines.append(f"{prefix}{d}")
        return "\n".join(lines)

    @staticmethod
    def _json_default(obj: Any) -> Any:
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return str(obj)