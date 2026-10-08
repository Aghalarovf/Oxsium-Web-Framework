from __future__ import annotations

from urllib.parse import urlparse

from core import BaseSource, SourceError, clean_names


class WaybackMachine(BaseSource):
    name = "wayback"
    description = "Wayback Machine CDX archive (free, no API key)"
    default_timeout = 60
    limit = 200000
    url = "https://web.archive.org/cdx/search/cdx"

    def fetch(self, domain: str) -> set[str]:
        params = {
            "url": domain,
            "matchType": "domain",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(self.limit),
        }
        try:
            resp = self.get(self.url, params=params)
            rows = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"wayback request failed: {exc}") from exc

        raw: list[str] = []
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, list) or not row or not isinstance(row[0], str):
                    continue
                url = row[0]
                if url.startswith(("http://", "https://")):
                    host = urlparse(url).netloc.split(":")[0].lower()
                    if host:
                        raw.append(host)
        return clean_names(raw, domain)
