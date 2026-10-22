from __future__ import annotations

import re

from core import BaseSource, SourceError, clean_names
from core.config import BROWSER_USER_AGENT


class Digitorus(BaseSource):
    name = "digitorus"
    description = "Digitorus certificate details (free, no key)"
    default_timeout = 30
    url = "https://certificatedetails.com/{d}"

    def fetch(self, domain: str) -> set[str]:
        try:
            resp = self.get(
                self.url.format(d=domain),
                headers={"User-Agent": BROWSER_USER_AGENT, "Accept": "text/html,*/*"},
            )
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"digitorus request failed: {exc}") from exc

        pattern = re.compile(r"[a-z0-9][a-z0-9._-]*\." + re.escape(domain), re.I)
        return clean_names(pattern.findall(resp.text), domain)
