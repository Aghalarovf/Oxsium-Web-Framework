from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class MySSL(BaseSource):
    name = "myssl"
    description = "MySSL subdomain discovery (free, no key)"
    default_timeout = 30
    url = "https://myssl.com/api/v1/discover_sub_domain"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url, params={"domain": domain})
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"myssl request failed: {exc}") from exc

        entries = data.get("data") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return set()

        raw = [
            e.get("domain")
            for e in entries
            if isinstance(e, dict) and isinstance(e.get("domain"), str)
        ]
        return clean_names(raw, domain)
