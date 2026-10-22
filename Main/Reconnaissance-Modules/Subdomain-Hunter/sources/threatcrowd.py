from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class ThreatCrowd(BaseSource):
    name = "threatcrowd"
    enabled = False
    description = "ThreatCrowd domain report (DISCONTINUED - host no longer resolves; disabled)"
    default_timeout = 30
    url = "http://ci-www.threatcrowd.org/searchApi/v2/domain/report/"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url, params={"domain": domain})
            if resp.status_code != 200:
                raise SourceError(f"threatcrowd returned HTTP {resp.status_code}")
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"threatcrowd request failed: {exc}") from exc

        subs = data.get("subdomains") if isinstance(data, dict) else None
        if not isinstance(subs, list):
            return set()
        return clean_names([s for s in subs if isinstance(s, str)], domain)
