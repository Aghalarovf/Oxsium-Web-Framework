from __future__ import annotations

from core import BaseSource, SourceError, clean_names
from core.config import BROWSER_USER_AGENT


class Reconeer(BaseSource):
    name = "reconeer"
    description = "Reconeer subdomain API (key optional: reconeer)"
    default_timeout = 30
    url = "https://www.reconeer.com/api/domain/{d}"

    def fetch(self, domain: str) -> set[str]:
        headers = {"User-Agent": BROWSER_USER_AGENT, "Accept": "application/json"}
        if self.keys.get("reconeer"):
            headers["X-API-KEY"] = self.keys["reconeer"]

        try:
            resp = self.get(self.url.format(d=domain), headers=headers)
            if resp.status_code == 404:
                return set()
            if resp.status_code != 200:
                raise SourceError(f"reconeer returned HTTP {resp.status_code}")
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"reconeer request failed: {exc}") from exc

        entries = data.get("subdomains") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            return set()

        raw: list[str] = []
        for entry in entries:
            value = entry.get("subdomain") if isinstance(entry, dict) else entry
            if isinstance(value, str):
                raw.append(value)
        return clean_names(raw, domain)
