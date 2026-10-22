from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class SubdomainCenter(BaseSource):
    name = "subdomaincenter"
    description = "subdomain.center database (key optional: subdomaincenter; anonymous returns a capped sample)"
    default_timeout = 60
    max_pages = 20
    page_size = 10000
    url = "https://api.subdomain.center/"

    def fetch(self, domain: str) -> set[str]:
        key = (self.keys.get("subdomaincenter") or "").strip()
        crawl = False
        if key.endswith(":crawl"):
            key = key[: -len(":crawl")]
            crawl = True

        headers = {"X-API-Key": key} if key else {}
        raw: list[str] = []
        offset = 0

        for page in range(self.max_pages):
            params = {"domain": domain, "engine": "cuttlefish"}
            if key:
                params["limit"] = self.page_size
                params["offset"] = offset
                if crawl and page == 0:
                    params["crawl"] = "true"

            try:
                resp = self.get(self.url, headers=headers, params=params)
                if resp.status_code == 404:
                    break
                if resp.status_code != 200:
                    raise SourceError(f"subdomaincenter returned HTTP {resp.status_code}")
                data = resp.json()
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"subdomaincenter request failed: {exc}") from exc

            if not isinstance(data, list):
                break
            batch = [n for n in data if isinstance(n, str)]
            raw.extend(batch)

            if not key:
                break
            truncated = resp.headers.get("X-Truncated", "").strip().lower() == "true"
            if not truncated or not batch:
                break
            try:
                next_offset = int(resp.headers.get("X-Next-Offset", ""))
            except ValueError:
                next_offset = 0
            offset = next_offset if next_offset > offset else offset + len(batch)

        return clean_names(raw, domain)
