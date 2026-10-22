from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class DNSRepo(BaseSource):
    name = "dnsrepo"
    description = "DNSArchive/DNSRepo API (key: dnsrepo, format token:apikey)"
    requires_api_key = True
    required_keys = ("dnsrepo",)
    default_timeout = 30
    url = "https://dnsarchive.net/api/"

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        parts = self.keys["dnsrepo"].split(":")
        if len(parts) != 2 or not all(parts):
            raise SourceError("dnsrepo key must be in 'token:apikey' format")
        token, apikey = parts

        try:
            resp = self.get(
                self.url,
                headers={"X-API-Access": token},
                params={"apikey": apikey, "search": domain},
            )
            if resp.status_code != 200:
                raise SourceError(f"dnsrepo returned HTTP {resp.status_code}")
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"dnsrepo request failed: {exc}") from exc

        if not isinstance(data, list):
            return set()
        raw = [
            e.get("domain").rstrip(".")
            for e in data
            if isinstance(e, dict) and isinstance(e.get("domain"), str)
        ]
        return clean_names(raw, domain)
