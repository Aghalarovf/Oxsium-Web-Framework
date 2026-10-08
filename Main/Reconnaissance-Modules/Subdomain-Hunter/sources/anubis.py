from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class Anubis(BaseSource):
    name = "anubis"
    description = "Anubis (jldc.me) subdomain database (free, no key)"
    default_timeout = 20
    url = "https://jldc.me/anubis/subdomains/{d}"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(self.url.format(d=domain))
            data = resp.json()
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"anubis request failed: {exc}") from exc

        if not isinstance(data, list):
            raise SourceError("anubis returned an unexpected payload")
        return clean_names([n for n in data if isinstance(n, str)], domain)
