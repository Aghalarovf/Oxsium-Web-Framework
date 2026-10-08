from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class HackerTarget(BaseSource):
    name = "hackertarget"
    description = "HackerTarget hostsearch (key optional: hackertarget; free ~50/day)"
    default_timeout = 30
    url = "https://api.hackertarget.com/hostsearch/"

    def fetch(self, domain: str) -> set[str]:
        params = {"q": domain}
        if self.keys.get("hackertarget"):
            params["apikey"] = self.keys["hackertarget"]
        try:
            resp = self.get(self.url, params=params)
        except SourceError:
            raise

        raw: list[str] = []
        for line in resp.text.splitlines():
            host = line.split(",")[0].strip().lower() if line.strip() else ""
            if host:
                raw.append(host)
        return clean_names(raw, domain)
