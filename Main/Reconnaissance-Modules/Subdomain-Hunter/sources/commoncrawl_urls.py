from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlparse

from core import BaseSource, SourceError, clean_names


class CommonCrawlUrls(BaseSource):
    name = "commoncrawl_urls"
    description = "Common Crawl CDX — scans multiple recent crawl indexes for broader URL coverage"
    default_timeout = 90
    limit = 50000
    max_indexes = 3

    _collinfo_url = "https://index.commoncrawl.org/collinfo.json"

    def _fetch_index_list(self) -> list[str]:
        try:
            resp = self.get(self._collinfo_url, timeout=15)
            indexes = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"[CC-URLs] Could not fetch index list: {exc}") from exc

        cdx_urls: list[str] = []
        if isinstance(indexes, list):
            for entry in indexes:
                if isinstance(entry, dict) and entry.get("cdx-api"):
                    cdx_urls.append(entry["cdx-api"])
                    if len(cdx_urls) >= self.max_indexes:
                        break

        if not cdx_urls:
            raise SourceError("[CC-URLs] No usable indexes found.")

        return cdx_urls

    def _query_index(self, cdx_api: str, domain: str) -> list[str]:
        params = {
            "url": f"*.{domain}",
            "matchType": "domain",
            "output": "json",
            "fl": "url",
            "collapse": "urlkey",
            "limit": str(self.limit),
        }
        try:
            resp = self.get(cdx_api, params=params)
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"[CC-URLs] Query failed for {cdx_api}: {exc}") from exc

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

        return raw

    def fetch(self, domain: str) -> set[str]:
        cdx_apis = self._fetch_index_list()
        self.log(f"Querying {len(cdx_apis)} Common Crawl index(es)")

        all_raw: list[str] = []
        for api_url in cdx_apis:
            try:
                raw = self._query_index(api_url, domain)
                all_raw.extend(raw)
                self.log(f"  {api_url} → {len(raw)} URLs")
            except SourceError as exc:
                self.log(f"  Skipping index {api_url}: {exc}")

        return clean_names(all_raw, domain)