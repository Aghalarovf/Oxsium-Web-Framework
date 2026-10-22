from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class ThreatMiner(BaseSource):
    name = "threatminer"
    description = "ThreatMiner domain subdomains (free, no key; often unstable)"
    default_timeout = 30
    url = "https://api.threatminer.org/v2/domain.php"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url, params={"q": domain, "rt": 5})
            if resp.status_code != 200:
                raise SourceError(f"threatminer returned HTTP {resp.status_code}")
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"threatminer request failed: {exc}") from exc

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return set()
        return clean_names([r for r in results if isinstance(r, str)], domain)
