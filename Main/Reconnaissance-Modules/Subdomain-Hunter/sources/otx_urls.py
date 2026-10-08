from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

from core import BaseSource, SourceError, clean_names


class AlienVaultOTXUrls(BaseSource):
    name = "otx_urls"
    description = "AlienVault OTX URL list (key optional: otx)"
    default_timeout = 30

    _base_url = "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list"
    _max_retries = 4
    _base_delay = 10
    _max_pages = 20

    def fetch(self, domain: str) -> set[str]:
        headers = {}
        if self.keys.get("otx"):
            headers["X-OTX-API-KEY"] = self.keys["otx"]

        names: set[str] = set()
        page = 1

        while page <= self._max_pages:
            url = self._base_url.format(domain)
            params = {"limit": 100, "page": page}

            for attempt in range(1, self._max_retries + 1):
                try:
                    resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
                except requests.RequestException as exc:
                    raise SourceError(f"[OTX-URLs] Connection failed: {exc}") from exc

                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    delay = int(retry_after) if retry_after and retry_after.isdigit() \
                        else self._base_delay * (2 ** (attempt - 1))
                    if attempt < self._max_retries:
                        self.log(f"Rate limited. Waiting {delay}s ({attempt}/{self._max_retries - 1})")
                        time.sleep(delay)
                        continue
                    raise SourceError(f"[OTX-URLs] Rate limit exceeded after {self._max_retries - 1} retries.")

                if resp.status_code in (401, 403):
                    raise SourceError(
                        "[OTX-URLs] Authentication failed.\n"
                        "  > Add a valid 'otx' API key to api_keys.json.\n"
                        "  > Get your key at: https://otx.alienvault.com/api"
                    )

                try:
                    resp.raise_for_status()
                except requests.HTTPError as exc:
                    raise SourceError(f"[OTX-URLs] HTTP {resp.status_code}: {exc}") from exc

                try:
                    data = resp.json()
                except ValueError as exc:
                    raise SourceError(f"[OTX-URLs] Invalid JSON: {exc}") from exc

                break
            else:
                raise SourceError("[OTX-URLs] Max retries reached.")

            url_list = data.get("url_list") if isinstance(data, dict) else None
            if not isinstance(url_list, list) or not url_list:
                break

            raw: list[str] = []
            for entry in url_list:
                if not isinstance(entry, dict):
                    continue
                raw_url = entry.get("url")
                if isinstance(raw_url, str) and raw_url.startswith(("http://", "https://")):
                    host = urlparse(raw_url).netloc.split(":")[0].lower()
                    if host:
                        raw.append(host)

            names.update(clean_names(raw, domain))

            if not data.get("has_next"):
                break
            page += 1

        return names