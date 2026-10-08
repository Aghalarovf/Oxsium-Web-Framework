import json
import urllib.parse
from typing import Any

from .base import BaseEmailModule


HUDSONROCK_DOMAIN_EP = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"


class ExchangeReconModule(BaseEmailModule):

    NAME        = "exchange_recon"
    DESCRIPTION = "Exchange & Webmail Recon — HudsonRock stealer exposure, compromised credentials, exposed URLs"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._findings: list[dict[str, Any]] = []

    def _add_finding(self, **finding: Any) -> None:
        self._findings.append(finding)

    async def run(self, domain: str) -> dict:
        self._findings = []
        self._domain = domain
        self._logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        await self._hudsonrock_domain()

        return {"findings": self._findings}

    async def _hudsonrock_domain(self) -> None:
        url = HUDSONROCK_DOMAIN_EP.format(domain=urllib.parse.quote(self._domain))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})

        if not res or not res.ok:
            status = res.status if res else 0
            self._logger.warning(f"[HudsonRock] HTTP {status} — skipped")
            return

        try:
            data = json.loads(res.text)
        except Exception:
            self._logger.error("[HudsonRock] Failed to parse response")
            return

        if not isinstance(data, dict):
            self._logger.warning("[HudsonRock] Unexpected response format")
            return

        stats           = data.get("stats", {})
        total_stealers  = data.get("totalStealers", 0)
        total_employees = stats.get("totalEmployees", 0)
        total_users     = stats.get("totalUsers", 0)
        total_records   = data.get("total", 0)

        all_urls_raw = data.get("data", {}).get("all_urls", [])
        seen_urls: set[str] = set()
        unique_urls: list[dict] = []
        for entry in all_urls_raw:
            u = entry.get("url", "").strip()
            if u and u not in seen_urls:
                seen_urls.add(u)
                unique_urls.append(entry)

        if not unique_urls:
            for u in stats.get("employees_urls", []):
                if u not in seen_urls:
                    seen_urls.add(u)
                    unique_urls.append({"url": u, "type": "Employee", "occurrence": 0})
            for u in stats.get("clients_urls", []):
                if u not in seen_urls:
                    seen_urls.add(u)
                    unique_urls.append({"url": u, "type": "User", "occurrence": 0})

        if not (total_records or total_employees or total_users):
            self._logger.info(f"[HudsonRock] {self._domain} → no stealer results")
            return

        self._add_finding(
            source="hudsonrock_domain",
            domain=self._domain,
            total_stealers=total_stealers,
            total_employees=total_employees,
            total_users=total_users,
            exposed_urls=[e["url"] for e in unique_urls],
            severity="critical",
        )

        self._logger.info(
            f"[HudsonRock] {self._domain} → "
            f"{total_stealers:,} stealer record(s) | "
            f"{total_employees} employee(s) | "
            f"{total_users} user(s) compromised | "
            f"{len(unique_urls)} unique URL(s) exposed"
        )

        for entry in unique_urls:
            tag = "Employee" if entry.get("type") == "Employee" else "User   "
            occ = entry.get("occurrence", 0)
            self._logger.info(f"[HudsonRock]   [{tag}] ({occ:>3}x) {entry['url']}")