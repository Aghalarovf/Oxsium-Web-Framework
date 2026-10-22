from __future__ import annotations

from core import BaseSource, SourceError, clean_names


class Driftnet(BaseSource):
    name = "driftnet"
    description = "Driftnet host summaries (key: driftnet)"
    requires_api_key = True
    required_keys = ("driftnet",)
    default_timeout = 60
    summary_limit = 10000
    base = "https://api.driftnet.io/v1/"
    endpoints = (
        ("ct/log", "field", "cert-dns-name"),
        ("scan/protocols", "field", "cert-dns-name"),
        ("scan/domains", "field", "cert-dns-name"),
        ("domain/rdns", "host", "dns-ptr"),
    )

    def fetch(self, domain: str) -> set[str]:
        self._ensure_keys()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.keys['driftnet']}",
        }

        raw: list[str] = []
        errors: list[str] = []
        succeeded = 0

        for path, param, context in self.endpoints:
            params = {
                param: f"host:{domain}" if param == "field" else domain,
                "summarize": "host",
                "summary_context": context,
                "summary_limit": self.summary_limit,
            }
            try:
                resp = self.get(self.base + path, headers=headers, params=params)
                if resp.status_code == 204:
                    succeeded += 1
                    continue
                if resp.status_code != 200:
                    errors.append(f"{path}: HTTP {resp.status_code}")
                    continue
                data = resp.json()
            except SourceError as exc:
                errors.append(f"{path}: {exc}")
                continue
            except Exception as exc:
                errors.append(f"{path}: {exc}")
                continue

            succeeded += 1
            summary = data.get("summary") if isinstance(data, dict) else None
            values = summary.get("values") if isinstance(summary, dict) else None
            if isinstance(values, dict):
                raw.extend(k for k in values if isinstance(k, str))

        if not succeeded and errors:
            raise SourceError("driftnet request failed: " + "; ".join(errors))
        return clean_names(raw, domain)
