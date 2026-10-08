from __future__ import annotations

import re

from core import BaseSource, SourceError, clean_names


class RapidDNS(BaseSource):
    name = "rapiddns"
    description = "RapidDNS.io subdomain database (free, no key; HTML scrape)"
    default_timeout = 30
    max_pages = 5
    url = "https://rapiddns.io/subdomain/{d}?full=1"
    _cell_re = re.compile(r"<td>\s*(?:<a[^>]*>)?\s*([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")

    def fetch(self, domain: str) -> set[str]:
        found: set[str] = set()
        for page in range(1, self.max_pages + 1):
            url = self.url.format(d=domain)
            if page > 1:
                url += f"&page={page}"
            try:
                resp = self.get(url)
            except SourceError:
                raise

            page_subs: set[str] = set()
            for cell in self._cell_re.findall(resp.text):
                name = cell.strip().lower()
                if name.endswith("." + domain):
                    page_subs.add(name)

            if not page_subs:
                break
            before = len(found)
            found.update(clean_names(page_subs, domain))
            if len(found) == before:
                break
        return found
