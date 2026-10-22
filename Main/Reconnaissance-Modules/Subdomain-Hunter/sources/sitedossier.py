from __future__ import annotations

import re
import time

from core import BaseSource, SourceError, clean_names


class SiteDossier(BaseSource):
    name = "sitedossier"
    description = "SiteDossier parent domain listing (free, no key; HTML scrape)"
    default_timeout = 30
    max_pages = 25
    page_delay = 1.0
    base = "http://www.sitedossier.com"
    url = base + "/parentdomain/{d}"
    _next_re = re.compile(r'<a href="([A-Za-z0-9/.]+)"><b>')

    def fetch(self, domain: str) -> set[str]:
        host_re = re.compile(r"[a-z0-9][a-z0-9._-]*\." + re.escape(domain), re.I)
        found: set[str] = set()
        seen_urls: set[str] = set()
        url = self.url.format(d=domain)

        for _ in range(self.max_pages):
            if url in seen_urls:
                break
            seen_urls.add(url)

            try:
                resp = self.get(url)
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"sitedossier request failed: {exc}") from exc

            if resp.status_code != 200:
                if not found:
                    raise SourceError(f"sitedossier returned HTTP {resp.status_code}")
                break

            found.update(clean_names(host_re.findall(resp.text), domain))

            match = self._next_re.search(resp.text)
            if not match:
                break
            url = self.base + match.group(1)
            time.sleep(self.page_delay)

        return found
