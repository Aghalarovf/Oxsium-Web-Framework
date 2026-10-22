from __future__ import annotations

from core import BaseSource, SourceError, clean_names, request_with_retry


class THC(BaseSource):
    name = "thc"
    description = "THC ip.thc.org subdomain lookup (free, no key)"
    default_timeout = 30
    max_pages = 50
    url = "https://ip.thc.org/api/v1/lookup/subdomains"

    def fetch(self, domain: str) -> set[str]:
        raw: list[str] = []
        page_state = ""

        for _ in range(self.max_pages):
            body = {"domain": domain, "page_state": page_state, "limit": 1000}
            try:
                resp = request_with_retry(
                    self.session, "POST", self.url, json=body, timeout=self.timeout
                )
                if resp.status_code != 200:
                    raise SourceError(f"thc returned HTTP {resp.status_code}")
                data = resp.json()
            except SourceError:
                raise
            except Exception as exc:
                raise SourceError(f"thc request failed: {exc}") from exc

            if not isinstance(data, dict):
                break
            for item in data.get("domains") or []:
                value = item.get("domain") if isinstance(item, dict) else item
                if isinstance(value, str):
                    raw.append(value)

            next_state = data.get("next_page_state")
            if not next_state or next_state == page_state:
                break
            page_state = next_state

        return clean_names(raw, domain)
