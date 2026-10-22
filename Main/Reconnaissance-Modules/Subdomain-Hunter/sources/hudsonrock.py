from __future__ import annotations

from urllib.parse import urlparse

from core import BaseSource, SourceError, clean_names


class HudsonRock(BaseSource):
    name = "hudsonrock"
    description = "Hudson Rock Cavalier OSINT URLs by domain (free, no key)"
    default_timeout = 30
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain"

    @staticmethod
    def _host(value: str) -> str:
        value = value.strip()
        if "://" not in value:
            value = "//" + value
        try:
            return (urlparse(value).hostname or "").lower()
        except ValueError:
            return ""

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url, params={"domain": domain})
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"hudsonrock request failed: {exc}") from exc

        payload = data.get("data") if isinstance(data, dict) else None
        if not isinstance(payload, dict):
            return set()

        raw: list[str] = []
        for key in ("employees_urls", "clients_urls"):
            entries = payload.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                value = entry.get("url") if isinstance(entry, dict) else entry
                if isinstance(value, str) and value:
                    host = self._host(value)
                    if host:
                        raw.append(host)
        return clean_names(raw, domain)
