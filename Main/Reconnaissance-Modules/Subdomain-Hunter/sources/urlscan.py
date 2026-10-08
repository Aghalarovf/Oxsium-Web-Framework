from __future__ import annotations

from typing import Optional

from core import BaseSource, SourceError, clean_names


class UrlScan(BaseSource):
    name = "urlscan"
    description = "URLScan.io search (key optional: urlscan; anonymous quota limited)"
    default_timeout = 30
    max_pages = 100
    url = "https://urlscan.io/api/v1/search/"

    def fetch(self, domain: str) -> set[str]:
        headers = {}
        if self.keys.get("urlscan"):
            headers["api-key"] = self.keys["urlscan"]

        search_after: Optional[str] = None
        names: set[str] = set()

        for _ in range(self.max_pages):
            params = {"q": f"domain:{domain}", "size": 100}
            if search_after:
                params["search_after"] = search_after
            try:
                resp = self.get(self.url, params=params, headers=headers)
                data = resp.json()
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"urlscan request failed: {exc}") from exc

            if not isinstance(data, dict):
                break
            results = data.get("results") or []
            for item in results:
                page = item.get("page") if isinstance(item, dict) else None
                d = page.get("domain") if isinstance(page, dict) else None
                if isinstance(d, str):
                    names.add(d)

            if not results or not data.get("has_more"):
                break
            last = results[-1]
            if not isinstance(last, dict) or not last.get("sort"):
                break
            search_after = last["sort"]

        return clean_names(names, domain)
