from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class CrtName(BaseSource):
    name = "crtname"
    description = "crt.name CT subdomain index (free, no key; 1000 req/IP/day)"
    default_timeout = 30
    url = "https://crt.name/v1/search?apex={d}"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url.format(d=domain))
        except SourceError:
            raise
        raw = [line for line in resp.text.splitlines() if line.strip()]
        return clean_names(raw, domain)
