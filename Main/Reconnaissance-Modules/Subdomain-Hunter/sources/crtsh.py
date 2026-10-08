from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class CrtSh(BaseSource):
    name = "crtsh"
    description = "crt.sh Certificate Transparency search (free, no key)"
    default_timeout = 30
    url = "https://crt.sh/?q=%25.{d}&output=json"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url.format(d=domain))
            rows = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"crtsh request failed: {exc}") from exc

        raw: list[str] = []
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    raw.append(str(row.get("name_value", "")))
        return clean_names(raw, domain)
