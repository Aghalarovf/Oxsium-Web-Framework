from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class CertSpotter(BaseSource):
    name = "certspotter"
    description = "CertSpotter / SSLMate CT monitoring (free, no key)"
    default_timeout = 30
    url = "https://api.certspotter.com/v1/issuances"

    def fetch(self, domain: str) -> set[str]:
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        try:
            resp = self.get(self.url, params=params)
            rows = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"certspotter request failed: {exc}") from exc

        raw: list[str] = []
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("dns_names"), list):
                    raw.extend(n for n in row["dns_names"] if isinstance(n, str))
        return clean_names(raw, domain)
