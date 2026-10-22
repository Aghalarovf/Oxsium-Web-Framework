from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class ShodanCT(BaseSource):
    name = "shodanct"
    description = "Shodan CT hostnames (free, no key)"
    default_timeout = 30
    url = "https://ctl.shodan.io/api/v1/domain/{d}/hostnames"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url.format(d=domain))
            if resp.status_code == 404:
                return set()
            if resp.status_code != 200:
                raise SourceError(f"shodanct returned HTTP {resp.status_code}")
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"shodanct request failed: {exc}") from exc

        if not isinstance(data, list):
            raise SourceError("shodanct returned an unexpected payload")
        return clean_names([n for n in data if isinstance(n, str)], domain)
