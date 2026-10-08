from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class SecurityTrails(BaseSource):
    name = "securitytrails"
    description = "SecurityTrails subdomains (key: securitytrails)"
    requires_api_key = True
    required_keys = ("securitytrails",)
    default_timeout = 30
    url = "https://api.securitytrails.com/v1/domain/{}/subdomains"

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        headers = {"APIKEY": self.keys["securitytrails"], "Accept": "application/json"}
        try:
            resp = self.get(
                self.url.format(domain),
                headers=headers,
                params={"include_inactive": "true"},
            )
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"securitytrails request failed: {exc}") from exc

        labels = data.get("subdomains") if isinstance(data, dict) else None
        if not isinstance(labels, list):
            return set()
        raw = [f"{label}.{domain}" for label in labels if isinstance(label, str) and label]
        return clean_names(raw, domain)
