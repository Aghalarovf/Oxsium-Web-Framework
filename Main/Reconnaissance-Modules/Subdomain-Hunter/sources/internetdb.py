from __future__ import annotations

import socket

from core import BaseSource, SourceError, clean_names


class ShodanInternetDB(BaseSource):
    name = "internetdb"
    description = "Shodan InternetDB hostnames for the apex domain IPs (free, no key)"
    default_timeout = 20
    max_ips = 20
    url = "https://internetdb.shodan.io/{ip}"

    def _resolve(self, domain: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(domain, None)
        except OSError:
            return []
        return sorted({item[4][0] for item in infos})[: self.max_ips]

    def fetch(self, domain: str) -> set[str]:
        ips = self._resolve(domain)
        if not ips:
            return set()

        raw: list[str] = []
        failures = 0
        for ip in ips:
            try:
                resp = self.get(self.url.format(ip=ip))
                if resp.status_code == 404:
                    continue
                if resp.status_code != 200:
                    failures += 1
                    continue
                data = resp.json()
            except SourceError:
                raise
            except Exception:
                failures += 1
                continue

            hostnames = data.get("hostnames") if isinstance(data, dict) else None
            if isinstance(hostnames, list):
                raw.extend(h for h in hostnames if isinstance(h, str))

        if failures == len(ips):
            raise SourceError("internetdb request failed for all resolved IPs")
        return clean_names(raw, domain)
