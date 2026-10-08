from __future__ import annotations

import os
import time

import requests

from core import BaseSource, SourceError, clean_names


class Censys(BaseSource):
    name = "censys"
    description = "Censys certificate search (key: censys_id + censys_secret)"
    requires_api_key = True
    required_keys: tuple[str, ...] = ("censys_id", "censys_secret")
    default_timeout = 30
    max_pages = 3
    url = "https://search.censys.io/api/v2/certificates/search"

    def _credentials(self) -> tuple[str, str]:
        cid = self.keys.get("censys_id") or os.environ.get("CENSYS_API_ID")
        secret = self.keys.get("censys_secret") or os.environ.get("CENSYS_API_SECRET")
        if not cid and not secret:
            raise SourceError(
                "[Censys] API keys are missing: 'censys_id' and 'censys_secret' not found.\n"
                "  > Add them to your api_keys.json:\n"
                "    { \"censys_id\": \"<your-id>\", \"censys_secret\": \"<your-secret>\" }\n"
                "  > Or set environment variables: CENSYS_API_ID, CENSYS_API_SECRET\n"
                "  > Get your keys at: https://search.censys.io/account/api"
            )
        if not cid:
            raise SourceError(
                "[Censys] API key 'censys_id' is missing.\n"
                "  > Add it to your api_keys.json: { \"censys_id\": \"<your-id>\" }\n"
                "  > Or set environment variable: CENSYS_API_ID"
            )
        if not secret:
            raise SourceError(
                "[Censys] API key 'censys_secret' is missing.\n"
                "  > Add it to your api_keys.json: { \"censys_secret\": \"<your-secret>\" }\n"
                "  > Or set environment variable: CENSYS_API_SECRET"
            )
        return cid, secret

    def _verify_auth(self, cid: str, secret: str) -> None:
        """Send a lightweight request to verify credentials before scanning."""
        try:
            resp = self.session.get(
                "https://search.censys.io/api/v2/account",
                auth=(cid, secret),
                timeout=self.timeout,
            )
        except requests.ConnectionError as exc:
            raise SourceError(f"[Censys] Could not connect to Censys API: {exc}") from exc
        except requests.Timeout as exc:
            raise SourceError(f"[Censys] Connection timed out: {exc}") from exc
        except requests.RequestException as exc:
            raise SourceError(f"[Censys] Connection failed: {exc}") from exc

        if resp.status_code == 401:
            raise SourceError(
                "[Censys] Authentication failed (401 Unauthorized).\n"
                "  > Your 'censys_id' or 'censys_secret' is incorrect.\n"
                "  > Double-check your keys at: https://search.censys.io/account/api"
            )
        if resp.status_code == 403:
            raise SourceError(
                "[Censys] Access denied (403 Forbidden).\n"
                "  > Your API key does not have permission for this endpoint.\n"
                "  > Check your account plan at: https://search.censys.io/account"
            )

    def fetch(self, domain: str) -> set[str]:
        cid, secret = self._credentials()
        self._verify_auth(cid, secret)

        body = {"q": f'names: "{domain}"', "per_page": 100, "fields": ["names"]}
        url: str = self.url
        names: set[str] = set()

        for _ in range(self.max_pages):
            try:
                resp = self.session.post(
                    url,
                    json=(body if _ == 0 else {}),
                    auth=(cid, secret),
                    timeout=self.timeout,
                )
            except requests.ConnectionError as exc:
                raise SourceError(f"[Censys] Could not connect to Censys API: {exc}") from exc
            except requests.Timeout as exc:
                raise SourceError(f"[Censys] Connection timed out: {exc}") from exc
            except requests.RequestException as exc:
                raise SourceError(f"[Censys] Request failed: {exc}") from exc

            if resp.status_code == 401:
                raise SourceError(
                    "[Censys] Authentication failed (401 Unauthorized).\n"
                    "  > Your 'censys_id' or 'censys_secret' is incorrect.\n"
                    "  > Double-check your keys at: https://search.censys.io/account/api"
                )
            if resp.status_code == 403:
                raise SourceError(
                    "[Censys] Access denied (403 Forbidden).\n"
                    "  > Your API key does not have permission for this endpoint.\n"
                    "  > Check your account plan at: https://search.censys.io/account"
                )
            if resp.status_code == 429:
                time.sleep(5)
                continue
            try:
                resp.raise_for_status()
            except requests.HTTPError as exc:
                raise SourceError(f"[Censys] Request failed (HTTP {resp.status_code}): {exc}") from exc
            try:
                data = resp.json()
            except ValueError as exc:
                raise SourceError(f"[Censys] Invalid JSON response: {exc}") from exc

            result = data.get("result") if isinstance(data, dict) else None
            hits = result.get("hits") if isinstance(result, dict) else None
            if isinstance(hits, list):
                for hit in hits:
                    if isinstance(hit, dict):
                        names.update(n for n in hit.get("names", []) if isinstance(n, str))
            links = result.get("links") if isinstance(result, dict) else None
            next_link = links.get("next") if isinstance(links, dict) else None
            if not next_link or not hits:
                break
            url = next_link

        return clean_names(names, domain)