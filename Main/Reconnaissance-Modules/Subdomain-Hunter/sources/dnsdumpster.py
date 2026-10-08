from __future__ import annotations

import re

import requests

from core import BaseSource, SourceError, clean_names

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


class DNSDumpster(BaseSource):
    name = "dnsdumpster"
    description = "DNSDumpster subdomain discovery via scraping (no key required)"
    requires_api_key = False
    default_timeout = 30
    base_url = "https://dnsdumpster.com/"

    def fetch(self, domain: str) -> set[str]:
        if not _BS4_AVAILABLE:
            raise SourceError(
                "[DNSDumpster] 'beautifulsoup4' is not installed.\n"
                "  > Run: pip install beautifulsoup4"
            )

        # Step 1: GET to obtain CSRF token
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise SourceError(f"[DNSDumpster] Connection failed: {exc}") from exc

        # Extract CSRF token from HTML
        csrf_token = None
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        if csrf_input:
            csrf_token = csrf_input.get("value")

        if not csrf_token:
            # Fallback: regex
            match = re.search(r'csrfmiddlewaretoken["\s]+value=["\s]+([a-zA-Z0-9]+)', resp.text)
            if match:
                csrf_token = match.group(1)

        if not csrf_token:
            raise SourceError("[DNSDumpster] Could not extract CSRF token.")

        # Step 2: POST with domain
        cookies = resp.cookies
        headers = {
            "Referer": self.base_url,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "csrfmiddlewaretoken": csrf_token,
            "targetip": domain,
            "user": "free",
        }

        try:
            resp = self.session.post(
                self.base_url,
                data=data,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise SourceError(f"[DNSDumpster] Request failed: {exc}") from exc

        # Step 3: Parse HTML for subdomains
        soup = BeautifulSoup(resp.text, "html.parser")
        names: set[str] = set()

        # Subdomains appear in tables with class "table"
        for table in soup.find_all("table", class_="table"):
            for td in table.find_all("td"):
                text = td.get_text(separator="\n").strip()
                for line in text.splitlines():
                    line = line.strip().lower()
                    if line.endswith(f".{domain}") or line == domain:
                        names.add(line)

        return clean_names(names, domain)