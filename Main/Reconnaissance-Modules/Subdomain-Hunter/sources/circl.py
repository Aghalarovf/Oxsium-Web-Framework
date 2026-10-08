from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class CirclPDNS(BaseSource):
    name = "circl"
    description = "CIRCL Passive DNS (restricted; key: circl_user + circl_pass)"
    requires_api_key = True
    required_keys = ("circl_user", "circl_pass")
    default_timeout = 30
    url = "https://circl.lu/pdns/query/"

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        auth = (self.keys["circl_user"], self.keys["circl_pass"])
        try:
            resp = self.get(self.url + domain, auth=auth)
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"circl request failed: {exc}") from exc

        if not isinstance(data, list):
            raise SourceError("circl returned an unexpected payload")
        raw = [
            r.get("rrname")
            for r in data
            if isinstance(r, dict) and isinstance(r.get("rrname"), str)
        ]
        return clean_names(raw, domain)
