import json
import csv
import os
from datetime import datetime
from pathlib import Path
from core.logger import Logger


class Exporter:

    SUPPORTED_FORMATS = ("json", "csv", "txt", "wordlist")

    def __init__(self, logger: Logger, output_path: str | None = None, fmt: str = "json"):
        self.logger = logger
        self.fmt = fmt.lower()
        self._base_path = output_path

        if self.fmt not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format: '{fmt}'. "
                f"Options: {self.SUPPORTED_FORMATS}"
            )

    def export(self, data: dict, label: str = "results") -> str:
        path = self._resolve_path(label)

        if self.fmt == "json":
            self._write_json(data, path)
        elif self.fmt == "csv":
            self._write_csv(data, path)
        elif self.fmt == "txt":
            self._write_txt(data, path)
        elif self.fmt == "wordlist":
            self._write_wordlist(data, path)

        self.logger.success(f"Export completed → {path}")
        return path

    def export_wordlist(self, params: list[str], path: str | None = None) -> str:
        out = path or self._resolve_path("wordlist", ext=".txt")
        lines = sorted(set(params))
        Path(out).write_text("\n".join(lines), encoding="utf-8")
        self.logger.success(f"Wordlist exported → {out}  ({len(lines)} parameters)")
        return out

    def _write_json(self, data: dict, path: str):
        payload = {
            "meta": {
                "tool": "WebArchive Scanner",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "format": "json",
            },
            "results": data,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def _write_csv(self, data: dict, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "value"])
            for section, items in data.items():
                if isinstance(items, list):
                    for item in items:
                        writer.writerow([section, item])
                elif isinstance(items, dict):
                    for k, v in items.items():
                        writer.writerow([f"{section}.{k}", v])
                else:
                    writer.writerow([section, items])

    def _write_txt(self, data: dict, path: str):
        lines: list[str] = []
        lines.append(f"# WebArchive Scanner — {datetime.utcnow().isoformat()}Z")
        lines.append("")

        for section, items in data.items():
            lines.append(f"## {section.upper()}")
            if isinstance(items, list):
                lines.extend(str(i) for i in items)
            elif isinstance(items, dict):
                for k, v in items.items():
                    lines.append(f"{k}: {v}")
            else:
                lines.append(str(items))
            lines.append("")

        Path(path).write_text("\n".join(lines), encoding="utf-8")

    def _write_wordlist(self, data: dict, path: str):
        params = data.get("params", data.get("parameters", []))
        if isinstance(params, dict):
            params = list(params.keys())
        lines = sorted(set(str(p) for p in params))
        Path(path).write_text("\n".join(lines), encoding="utf-8")

    def _resolve_path(self, label: str, ext: str | None = None) -> str:
        if ext is None:
            ext = {"json": ".json", "csv": ".csv", "txt": ".txt", "wordlist": ".txt"}[self.fmt]

        if self._base_path:
            base = self._base_path
            if not base.endswith(ext):
                base = f"{base}_{label}{ext}"
            return base

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"webarchive_{label}_{ts}{ext}"

    @staticmethod
    def print_summary(data: dict):
        for key, val in data.items():
            count = len(val) if isinstance(val, (list, dict)) else val
            print(f"  {key:<35} {count}")