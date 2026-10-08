from __future__ import annotations

import requests

from core import BaseSource, SourceError, clean_names


class Chaos(BaseSource):
    name = "chaos"
    description = "ProjectDiscovery Chaos subdomain DB (key: chaos_key — free at cloud.projectdiscovery.io)"
    requires_api_key = True
    required_keys: tuple[str, ...] = ("chaos_key",)
    default_timeout = 30
    url = "https://dns.projectdiscovery.io/dns/{}/subdomains"

    def fetch(self, domain: str) -> set[str]:
        headers = {"Authorization": self.keys["chaos_key"]}
        try:
            resp = self.session.get(
                self.url.format(domain),
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SourceError(f"[Chaos] Connection failed: {exc}") from exc

        if resp.status_code == 401:
            raise SourceError(
                "[Chaos] Authentication failed (401 Unauthorized).\n"
                "  > Your 'chaos_key' is incorrect.\n"
                "  > Get your free key at: https://cloud.projectdiscovery.io"
            )
        if resp.status_code == 403:
            raise SourceError(
                "[Chaos] Access denied (403 Forbidden).\n"
                "  > Your 'chaos_key' may not have access.\n"
                "  > Get your free key at: https://cloud.projectdiscovery.io"
            )
        if resp.status_code == 404:
            return set()

        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            raise SourceError(f"[Chaos] Request failed (HTTP {resp.status_code}): {exc}") from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise SourceError(f"[Chaos] Invalid JSON response: {exc}") from exc

        subdomains = data.get("subdomains") if isinstance(data, dict) else None
        if not isinstance(subdomains, list):
            return set()

        raw = [f"{s}.{domain}" for s in subdomains if isinstance(s, str)]
        return clean_names(raw, domain)