from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class MerkleMap(BaseSource):
    name = "merklemap"
    description = "Merkle Map certificate transparency search (key: merklemap)"
    requires_api_key = True
    required_keys = ("merklemap",)
    default_timeout = 60
    max_pages = 200
    url = "https://api.merklemap.com/v1/search"

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.keys['merklemap']}",
        }

        raw: list[str] = []
        total = None
        collected = 0

        for page in range(self.max_pages):
            params = {"query": f"*.{domain}", "page": page}
            try:
                resp = self.get(self.url, headers=headers, params=params)
                if resp.status_code != 200:
                    raise SourceError(f"merklemap returned HTTP {resp.status_code}")
                data = resp.json()
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"merklemap request failed: {exc}") from exc

            if not isinstance(data, dict):
                break
            if total is None and isinstance(data.get("count"), int):
                total = data["count"]

            results = data.get("results")
            if not isinstance(results, list) or not results:
                break

            for item in results:
                if isinstance(item, dict) and isinstance(item.get("hostname"), str):
                    raw.append(item["hostname"])
            collected += len(results)

            if total is not None and collected >= total:
                break

        return clean_names(raw, domain)
