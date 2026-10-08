from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlparse

from core import BaseSource, SourceError, clean_names


class CommonCrawl(BaseSource):
    name = "commoncrawl"
    description = "Common Crawl index (free, no key; latest crawl)"
    default_timeout = 60
    limit = 20000
    collinfo_url = "https://index.commoncrawl.org/collinfo.json"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.collinfo_url, timeout=15)
            indexes = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"commoncrawl: could not fetch index list: {exc}") from exc

        latest: Optional[str] = None
        if isinstance(indexes, list):
            for entry in indexes:
                if isinstance(entry, dict) and entry.get("cdx-api"):
                    latest = entry["cdx-api"]
                    break
        if not latest:
            raise SourceError("commoncrawl: no usable index found")

        params = {
            "url": domain,
            "matchType": "domain",
            "output": "json",
            "fl": "url",
            "collapse": "urlkey",
            "limit": str(self.limit),
        }
        try:
            resp = self.get(latest, params=params)
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"commoncrawl request failed: {exc}") from exc

        raw: list[str] = []
        for line in resp.text.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            url = item.get("url") if isinstance(item, dict) else None
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                host = urlparse(url).netloc.split(":")[0].lower()
                if host:
                    raw.append(host)
        return clean_names(raw, domain)
