from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class Shodan(BaseSource):
    name = "shodan"
    description = "Shodan DNS domain data (key: shodan; 1 query credit)"
    requires_api_key = True
    required_keys = ("shodan",)
    default_timeout = 30
    url = "https://api.shodan.io/dns/domain/{}"

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        params = {"key": self.keys["shodan"]}
        try:
            resp = self.get(self.url.format(domain), params=params)
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"shodan request failed: {exc}") from exc

        if not isinstance(data, dict):
            raise SourceError("shodan returned an unexpected payload")

        labels: set[str] = set()
        for rec in data.get("data", []):
            sub = rec.get("subdomain") if isinstance(rec, dict) else None
            if isinstance(sub, str) and sub and sub != domain:
                labels.add(sub)
        for sub in data.get("subdomains", []):
            if isinstance(sub, str) and sub:
                labels.add(sub)

        raw = [f"{label}.{domain}" for label in labels]
        return clean_names(raw, domain)
