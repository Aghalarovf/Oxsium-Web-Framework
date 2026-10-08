from __future__ import annotations

from urllib.parse import urlparse
from typing import Optional

from core import BaseSource, SourceError, clean_names


class UrlScanUrls(BaseSource):
    name = "urlscan_urls"
    description = "URLScan.io URL results — extracts subdomains from full URL list (key optional: urlscan)"
    default_timeout = 30
    max_pages = 100

    _search_url = "https://urlscan.io/api/v1/search/"

    def fetch(self, domain: str) -> set[str]:
        headers = {}
        if self.keys.get("urlscan"):
            headers["api-key"] = self.keys["urlscan"]

        names: set[str] = set()
        search_after: Optional[str] = None

        for _ in range(self.max_pages):
            params: dict = {"q": f"domain:{domain}", "size": 100}
            if search_after:
                params["search_after"] = search_after

            try:
                resp = self.get(self._search_url, params=params, headers=headers)
                data = resp.json()
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"[URLScan-URLs] Request failed: {exc}") from exc

            if not isinstance(data, dict):
                break

            results = data.get("results") or []
            for item in results:
                if not isinstance(item, dict):
                    continue

                page = item.get("page")
                if isinstance(page, dict):
                    for field in ("url", "domain"):
                        val = page.get(field)
                        if not isinstance(val, str):
                            continue
                        if field == "url" and val.startswith(("http://", "https://")):
                            host = urlparse(val).netloc.split(":")[0].lower()
                            if host:
                                names.update(clean_names([host], domain))
                        elif field == "domain":
                            names.update(clean_names([val], domain))

                task = item.get("task")
                if isinstance(task, dict):
                    task_url = task.get("url")
                    if isinstance(task_url, str) and task_url.startswith(("http://", "https://")):
                        host = urlparse(task_url).netloc.split(":")[0].lower()
                        if host:
                            names.update(clean_names([host], domain))

            if not results or not data.get("has_more"):
                break

            last = results[-1]
            if not isinstance(last, dict) or not last.get("sort"):
                break
            search_after = last["sort"]

        return names