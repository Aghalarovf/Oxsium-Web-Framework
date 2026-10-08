from __future__ import annotations

import time

from core import BaseSource, SourceError, clean_names


class VirusTotal(BaseSource):
    name = "virustotal"
    description = "VirusTotal domain subdomains (key: virustotal)"
    requires_api_key = True
    required_keys = ("virustotal",)
    default_timeout = 30
    max_pages = 5
    url = "https://www.virustotal.com/api/v3/domains/{}/subdomains"

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        headers = {"x-apikey": self.keys["virustotal"]}
        url = self.url.format(domain) + "?limit=40"
        names: set[str] = set()

        for _ in range(self.max_pages):
            try:
                resp = self.get(url, headers=headers)
                data = resp.json()
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"virustotal request failed: {exc}") from exc

            if not isinstance(data, dict):
                break
            for item in data.get("data", []):
                sub = item.get("id") if isinstance(item, dict) else None
                if isinstance(sub, str):
                    names.add(sub)

            next_link = (data.get("links") or {}).get("next")
            if not next_link or not data.get("data"):
                break
            url = next_link
            time.sleep(2)

        return clean_names(names, domain)
