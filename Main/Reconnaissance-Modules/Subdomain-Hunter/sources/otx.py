from __future__ import annotations

import time

import requests

from core import BaseSource, SourceError, clean_names


class AlienVaultOTX(BaseSource):
    name = "otx"
    description = "AlienVault OTX passive DNS (key optional: otx)"
    default_timeout = 30
    url = "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list"

    _max_retries = 4
    _base_delay = 10  # seconds

    def fetch(self, domain: str) -> set[str]:
        headers = {}
        if self.keys.get("otx"):
            headers["X-OTX-API-KEY"] = self.keys["otx"]

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self.session.get(
                    self.url.format(domain),
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                raise SourceError(f"[OTX] Connection failed: {exc}") from exc

            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                delay = int(retry_after) if retry_after and retry_after.isdigit() \
                    else self._base_delay * (2 ** (attempt - 1))

                if attempt < self._max_retries:
                    self.log(
                        f"Rate limited (429). Waiting {delay}s before retry "
                        f"({attempt}/{self._max_retries - 1})..."
                    )
                    time.sleep(delay)
                    continue
                else:
                    raise SourceError(
                        f"[OTX] Rate limit exceeded after {self._max_retries - 1} retries.\n"
                        "  > Wait a few minutes and try again.\n"
                        "  > Or add an API key 'otx' to api_keys.json for a higher quota:\n"
                        "    https://otx.alienvault.com/api"
                    )

            if resp.status_code in (401, 403):
                raise SourceError(
                    "[OTX] Authentication failed.\n"
                    "  > Add a valid 'otx' API key to api_keys.json.\n"
                    "  > Get your key at: https://otx.alienvault.com/api"
                )

            try:
                resp.raise_for_status()
            except requests.HTTPError as exc:
                raise SourceError(f"[OTX] Request failed (HTTP {resp.status_code}): {exc}") from exc

            try:
                data = resp.json()
            except ValueError as exc:
                raise SourceError(f"[OTX] Invalid JSON response: {exc}") from exc

            records = data.get("passive_dns") if isinstance(data, dict) else None
            if not isinstance(records, list):
                return set()

            raw = [
                r.get("hostname")
                for r in records
                if isinstance(r, dict) and isinstance(r.get("hostname"), str)
            ]
            return clean_names(raw, domain)

        raise SourceError("[OTX] Max retries reached.")