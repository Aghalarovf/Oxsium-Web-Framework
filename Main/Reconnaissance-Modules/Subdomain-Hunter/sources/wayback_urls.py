from __future__ import annotations

from urllib.parse import urlparse

from core import BaseSource, SourceError, clean_names


class WaybackUrls(BaseSource):
    name = "wayback_urls"
    description = "Wayback Machine CDX — full URL list with higher page limit for broader subdomain coverage"
    default_timeout = 90
    limit = 100000

    _cdx_url = "https://web.archive.org/cdx/search/cdx"

    def fetch(self, domain: str) -> set[str]:
        params = {
            "url": f"*.{domain}",
            "matchType": "domain",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(self.limit),
        }

        try:
            resp = self.get(self._cdx_url, params=params)
            rows = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"[Wayback-URLs] Request failed: {exc}") from exc

        raw: list[str] = []
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, list) or not row or not isinstance(row[0], str):
                    continue
                entry = row[0]
                if entry.startswith(("http://", "https://")):
                    host = urlparse(entry).netloc.split(":")[0].lower()
                    if host:
                        raw.append(host)

        return clean_names(raw, domain)