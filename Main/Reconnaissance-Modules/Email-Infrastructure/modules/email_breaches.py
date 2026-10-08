import asyncio
import html as _html_mod
import hashlib
import os
import re
import urllib.parse
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseEmailModule


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# HIBP v3 (key required)
HIBP_BASE        = "https://haveibeenpwned.com/api/v3"
HIBP_BREACH_EP   = HIBP_BASE + "/breachedaccount/{email}?truncateResponse=false&includeUnverified=true"
HIBP_PASTE_EP    = HIBP_BASE + "/pasteaccount/{email}"
HIBP_DOMAIN_EP   = HIBP_BASE + "/breacheddomain/{domain}"

# ---- key-free / public sources ----

# Scylla.sh  (public JSON API — no key)
SCYLLA_EMAIL  = "https://scylla.sh/search?q={email}&size=20"
SCYLLA_DOMAIN = "https://scylla.sh/search?q=domain%3A{domain}&size=50"

# LeakCheck public endpoint
LEAKCHECK_URL = "https://leakcheck.io/api/public?check={query}"

# Proxynova combo-list search (public, no key)
PROXYNOVA_URL = "https://api.proxynova.com/comb?query={query}&start=0&limit=100"

# BreachDirectory via RapidAPI free tier
BREACHDIR_URL = "https://breachdirectory.p.rapidapi.com/?func=auto&term={email}"

# IntelX public hint (no API — just generate link)
INTELX_HINT   = "https://intelx.io/?s={query}"

HUDSONROCK_EMAIL_EP  = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
HUDSONROCK_DOMAIN_EP = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"

XON_CHECK_EP     = "https://api.xposedornot.com/v1/check-email/{email}"
XON_ANALYTICS_EP = "https://api.xposedornot.com/v1/breach-analytics?email={email}"

# Paste-site paths to probe for credential leaks on target itself
PASTE_PROBE_PATHS = [
    "/humans.txt", "/security.txt", "/.well-known/security.txt",
    "/.env", "/config.js", "/config.json", "/robots.txt", "/sitemap.xml",
    "/wp-config.php.bak", "/backup.sql", "/.git/config",
]

# Google / Bing dork templates
DORK_TEMPLATES = [
    'site:pastebin.com "{target}"',
    'site:pastebin.com "{target}" password',
    'site:pastebin.com "{target}" email',
    'site:ghostbin.com "{target}"',
    'site:rentry.co "{target}"',
    'site:gist.github.com "{target}"',
    'site:hastebin.com "{target}"',
    '"{target}" filetype:txt password',
    '"{target}" filetype:csv email',
    'intext:"{target}" "credential" site:github.com',
    'intext:"{target}" "api_key" OR "apikey" site:github.com',
    '"{target}" intext:"@" intext:"password" -site:{target}',
    'site:pastebin.com intext:"{target}" intext:"@"',
]

# Regex
EMAIL_RE = re.compile(r'[\w+\-.]+@[\w\-.]+\.[a-zA-Z]{2,}', re.IGNORECASE)
CRED_RE  = re.compile(r'[\w+\-.]+@[\w\-.]+\.[a-zA-Z]{2,}\s*[;:,\t|]\s*\S+', re.IGNORECASE)

CRITICAL_DC = {"Passwords","Password hints","Credit cards","Bank account numbers",
               "Social security numbers","Passport numbers","Private messages","Auth tokens"}
HIGH_DC     = {"Email addresses","Usernames","Phone numbers","Physical addresses",
               "IP addresses","Security questions and answers","Biometric data"}

LARGE_BREACH = 1_000_000


def _severity(data_classes: list[str]) -> str:
    dc = set(data_classes)
    if dc & CRITICAL_DC: return "critical"
    if dc & HIGH_DC:     return "high"
    if dc:               return "medium"
    return "low"


class BreachesModule(BaseEmailModule):
    NAME        = "breaches"
    DESCRIPTION = "Email Data Breach Check & Exposure Analysis — HIBP (optional), Scylla, ProxyNova, LeakCheck, HudsonRock, XposedOrNot, credential scan"

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._findings: list[dict[str, Any]] = []

    def _add_finding(self, **finding: Any) -> None:
        self._findings.append(finding)

    def _log_finding(self, category: str, message: str) -> None:
        self._logger.info(f"[{category}] {message}")

    async def run(self, domain: str, harvested_emails: Optional[list[str]] = None) -> dict:
        self._findings = []
        self.domain = domain
        self.target = f"https://{domain}"
        self._logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        self._hibp_key: Optional[str] = os.getenv("HIBP_API_KEY")
        self._has_hibp  = bool(self._hibp_key)
        self._lc_lock   = asyncio.Lock()

        if self._has_hibp:
            self._logger.info("HIBP API key detected — full HIBP check enabled.")
        else:
            self._logger.warning(
                "No HIBP key — using open sources: "
                "ProxyNova, LeakCheck, XposedOrNot, HudsonRock."
            )

        # Step 1: Pull leaked emails from ProxyNova domain search
        proxynova_emails = await self._proxynova_domain_emails()

        # Step 2: Collect emails from prior session findings
        session_emails = self._collect_emails(harvested_emails)

        # Step 3: Merge both sources, deduplicated
        all_emails = sorted(set(session_emails) | set(proxynova_emails))

        if not all_emails:
            self._logger.warning("No email addresses found to check.")
        else:
            self._logger.info(
                f"Running breach checks on {len(all_emails)} address(es) "
                f"({len(proxynova_emails)} from ProxyNova, "
                f"{len(session_emails)} from session) ..."
            )
            # Step 4: Per-email breach checks for all discovered addresses
            await asyncio.gather(*[self._check_email(e) for e in all_emails])

        # Step 5: Other domain-level passive checks (parallel)
        await asyncio.gather(
            self._scylla_domain(),
            self._dehashed_scrape(),
            self._credential_scan(),
        )

        # Step 6: HudsonRock domain — stealer stats + unique exposed URLs
        await self._hudsonrock_domain()

        self._findings = self._dedup(self._findings)
        self._print_summary()
        return {"findings": self._findings}

    # ------------------------------------------------------------------ #
    #  Email collection                                                    #
    # ------------------------------------------------------------------ #

    def _collect_emails(self, harvested_emails: Optional[list[str]] = None) -> list[str]:
        emails: set[str] = set()

        for email in harvested_emails or []:
            if email:
                emails.add(email.lower().strip())

        # Prior emails-module findings (same session)
        for f in getattr(self, "session_findings", []):
            if f.get("module") == "emails" and f.get("email"):
                emails.add(f["email"].lower().strip())

        # Fallback — role addresses for domain
        if not emails and self.domain:
            for pfx in ("admin", "info", "contact", "security", "webmaster", "support"):
                emails.add(f"{pfx}@{self.domain}")

        return sorted(emails)

    # ------------------------------------------------------------------ #
    #  Per-email pipeline                                                  #
    # ------------------------------------------------------------------ #

    async def _check_email(self, email: str):
        tasks = [
            self._scylla_email(email),
            self._proxynova_email(email),
            self._leakcheck_email(email),
            self._hudsonrock_email(email),
            self._xon_email(email),
        ]
        if self._has_hibp:
            tasks += [self._hibp_breaches(email), self._hibp_pastes(email)]
        await asyncio.gather(*tasks)

    # ------------------------------------------------------------------ #
    #  HIBP (key required)                                                 #
    # ------------------------------------------------------------------ #

    def _hibp_headers(self) -> dict:
        return {
            "hibp-api-key":   self._hibp_key,
            "hibp-api-version": "3",
            "User-Agent":     "SMR-OSINT/1.0",
        }

    async def _hibp_breaches(self, email: str):
        url = HIBP_BREACH_EP.format(email=urllib.parse.quote(email))
        res = await self._requester.get(url, extra_headers=self._hibp_headers())
        if res.status == 404:
            self._log_finding("HIBP", f"{email} → ✓ clean")
            return
        if res.status == 429:
            await asyncio.sleep(1.6)
            res = await self._requester.get(url, extra_headers=self._hibp_headers())
        if not res.ok:
            self._logger.error(f"HIBP HTTP {res.status} for {email}")
            return
        import json as _j
        try:
            breaches = _j.loads(res.text)
        except Exception:
            return
        for b in breaches:
            dc  = b.get("DataClasses", [])
            sev = _severity(dc)
            self._add_finding(
                source="hibp_breach", email=email, status="breached",
                breach_name=b.get("Name",""), breach_title=b.get("Title",""),
                breach_domain=b.get("Domain",""), breach_date=b.get("BreachDate",""),
                pwn_count=b.get("PwnCount",0), data_classes=tuple(dc),
                severity=sev,
                is_verified=not b.get("IsUnverified",False),
                is_sensitive=b.get("IsSensitive",False),
                is_large=b.get("PwnCount",0) >= LARGE_BREACH,
            )
            self._log_finding("HIBP breach",
                f"{email} → [{sev.upper()}] {b.get('Title','')} "
                f"({b.get('BreachDate','')}) | {b.get('PwnCount',0):,} records")

    async def _hibp_pastes(self, email: str):
        url = HIBP_PASTE_EP.format(email=urllib.parse.quote(email))
        res = await self._requester.get(url, extra_headers=self._hibp_headers())
        if res.status in (404, 401, 403):
            return
        if res.status == 429:
            await asyncio.sleep(1.6)
            res = await self._requester.get(url, extra_headers=self._hibp_headers())
        if not res.ok:
            return
        import json as _j
        try:
            pastes = _j.loads(res.text)
        except Exception:
            return
        for p in pastes:
            sid = p.get("Source","")
            pid = p.get("Id","")
            self._add_finding(
                source="hibp_paste", email=email,
                paste_source=sid, paste_id=pid,
                paste_url=f"https://pastebin.com/{pid}" if sid == "Pastebin" else pid,
                paste_date=(p.get("Date","")[:10] if p.get("Date") else "unknown"),
                email_count=p.get("EmailCount",0),
                severity="high",
            )
            self._log_finding("HIBP paste", f"{email} → {sid}/{pid}")

    # ------------------------------------------------------------------ #
    #  Scylla.sh  (open)                                                   #
    # ------------------------------------------------------------------ #

    async def _scylla_email(self, email: str):
        url = SCYLLA_EMAIL.format(email=urllib.parse.quote(email))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
        if not res.ok:
            return
        import json as _j
        try:
            data = _j.loads(res.text)
        except Exception:
            return
        hits = data if isinstance(data, list) else data.get("hits", {}).get("hits", [])
        for hit in hits[:20]:
            src = hit.get("_source", hit)
            em  = (src.get("email") or "").lower()
            if em and EMAIL_RE.fullmatch(em):
                breach = src.get("domain","") or src.get("source","scylla")
                has_pw = bool(src.get("password"))
                self._add_finding(
                    source="scylla_email", email=em,
                    breach_name=breach,
                    username=src.get("username",""),
                    password_hash=src.get("password","")[:80] if has_pw else "",
                    severity="critical" if has_pw else "high",
                )
                self._log_finding("Scylla",
                    f"{em} — {breach}" + (" | pw hash present" if has_pw else ""))

    async def _scylla_domain(self):
        if not self.domain:
            return
        url = SCYLLA_DOMAIN.format(domain=urllib.parse.quote(self.domain))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
        if not res.ok:
            self._log_finding("Scylla domain", f"HTTP {res.status} — skipped")
            return
        import json as _j
        try:
            data = _j.loads(res.text)
        except Exception:
            return
        hits = data if isinstance(data, list) else data.get("hits", {}).get("hits", [])
        found: set[str] = set()
        for hit in hits[:50]:
            src = hit.get("_source", hit)
            em  = (src.get("email") or "").lower()
            if em and EMAIL_RE.fullmatch(em):
                found.add(em)
                self._add_finding(
                    source="scylla_domain", email=em, domain=self.domain,
                    breach_name=src.get("source",""),
                    password_hash=src.get("password","")[:80] if src.get("password") else "",
                    severity="critical" if src.get("password") else "high",
                )
        msg = f"{self.domain} → {len(found)} address(es)" if found else f"{self.domain} → no results"
        self._log_finding("Scylla domain", msg)

    # ------------------------------------------------------------------ #
    #  ProxyNova combo-list search  (open, no key)                         #
    # ------------------------------------------------------------------ #

    async def _proxynova_email(self, email: str):
        # Query must be full email — ProxyNova does substring match,
        # filter results strictly to lines containing this exact email.
        url = PROXYNOVA_URL.format(query=urllib.parse.quote(email))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
        if not res.ok:
            return
        import json as _j
        try:
            data = _j.loads(res.text)
        except Exception:
            return
        lines = data.get("lines", [])
        for line in lines[:20]:
            line = line.strip()
            if not line:
                continue
            # STRICT: only accept lines that actually contain the queried email
            if email.lower() not in line.lower():
                continue
            em_m = EMAIL_RE.match(line)
            if not em_m:
                continue
            em = em_m.group(0).lower()
            self._add_finding(
                source="proxynova", email=em,
                combo_line=line[:150],
                severity="critical",
            )
            self._log_finding("ProxyNova", f"{em} — combo line found")

    async def _proxynova_domain_emails(self) -> list[str]:
        if not self.domain:
            return []
        url = PROXYNOVA_URL.format(query=urllib.parse.quote(f"@{self.domain}"))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
        if not res.ok:
            self._log_finding("ProxyNova domain", f"HTTP {res.status} — skipped")
            return []
        import json as _j
        try:
            data = _j.loads(res.text)
        except Exception:
            return []
        lines = data.get("lines", [])
        count = data.get("count", len(lines))
        found: set[str] = set()
        for line in lines:
            line = line.strip()
            em_m = EMAIL_RE.search(line)
            if em_m:
                em = em_m.group(0).lower()
                if self.domain in em:
                    found.add(em)
                    self._add_finding(
                        source="proxynova_domain", email=em,
                        domain=self.domain,
                        combo_line=line[:150],
                        severity="critical",
                    )
                    self._log_finding("ProxyNova", f"{em} — combo line found")
        if found or count:
            self._log_finding(
                "ProxyNova domain",
                f"{self.domain} → {count} total combo line(s) | {len(found)} unique email(s) — "
                f"queuing all for breach check ...",
            )
        else:
            self._log_finding("ProxyNova domain", f"{self.domain} → no results")
        return sorted(found)

    # ------------------------------------------------------------------ #
    #  LeakCheck  (open public endpoint)                                   #
    # ------------------------------------------------------------------ #

    async def _leakcheck_email(self, email: str):
        async with self._lc_lock:
            await asyncio.sleep(1.1)
            import json as _j
            url = LEAKCHECK_URL.format(query=urllib.parse.quote(email))
            res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
            if not res.ok:
                return
            try:
                data = _j.loads(res.text)
            except Exception:
                return
            if not data.get("success"):
                self._log_finding("LeakCheck", f"{email} → clean")
                return
            fields = data.get("fields", [])
            has_pw = any(f in ("password", "passwords") for f in fields)
            sev    = "critical" if has_pw else "high" if fields else "medium"
            for src in data.get("sources", []):
                self._add_finding(
                    source="leakcheck_email",
                    email=email,
                    breach_name=src.get("name", ""),
                    breach_date=src.get("date", ""),
                    exposed_fields=tuple(fields),
                    severity=sev,
                )
                self._log_finding("LeakCheck",
                    f"{email} — {src.get('name', '?')} ({src.get('date', '?')})")

    # ------------------------------------------------------------------ #
    #  DeHashed HTML scrape  (open, no key)                                #
    # ------------------------------------------------------------------ #

    async def _dehashed_scrape(self):
        if not self.domain:
            return
        url = f"https://dehashed.com/search?query=domain%3A{urllib.parse.quote(self.domain)}"
        res = await self._requester.get(url, extra_headers={
            "User-Agent": "Mozilla/5.0 (compatible; OSINT/1.0)",
            "Accept": "text/html",
        })
        if not res.ok:
            self._log_finding("DeHashed", f"HTTP {res.status} — skipped (login may be required)")
            return
        body = _html_mod.unescape(res.text or "")
        found: set[str] = set()
        for m in EMAIL_RE.finditer(body):
            em = m.group(0).lower()
            if self.domain in em:
                found.add(em)
                self._add_finding(
                    source="dehashed", email=em, domain=self.domain, severity="high")
        msg = f"{self.domain} → {len(found)} address(es)" if found else f"{self.domain} → no results (likely behind login)"
        self._log_finding("DeHashed scrape", msg)

    # ------------------------------------------------------------------ #
    #  Hudson Rock Cavalier  (open, no key)                                #
    # ------------------------------------------------------------------ #

    async def _hudsonrock_email(self, email: str):
        url = HUDSONROCK_EMAIL_EP.format(email=urllib.parse.quote(email))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
        if not res.ok:
            return
        import json as _j
        try:
            data = _j.loads(res.text)
        except Exception:
            return
        stealers = data.get("stealers", []) if isinstance(data, dict) else []
        for s in stealers[:20]:
            self._add_finding(
                source="hudsonrock_email",
                email=email,
                stealer_family=s.get("stealer_family", ""),
                computer_name=s.get("computer_name", ""),
                operating_system=s.get("operating_system", ""),
                date_uploaded=s.get("date_uploaded", ""),
                severity="critical",
            )
            self._log_finding("HudsonRock",
                f"{email} — stealer: {s.get('stealer_family', '?')} | {s.get('date_uploaded', '?')}")
        if not stealers:
            self._log_finding("HudsonRock email", f"{email} → no stealer results")

    async def _hudsonrock_domain(self):
        if not self.domain:
            return
        url = HUDSONROCK_DOMAIN_EP.format(domain=urllib.parse.quote(self.domain))
        res = await self._requester.get(url, extra_headers={"Accept": "application/json"})
        if not res.ok:
            self._log_finding("HudsonRock domain", f"HTTP {res.status} — skipped")
            return
        import json as _j
        try:
            data = _j.loads(res.text)
        except Exception:
            return

        if not isinstance(data, dict):
            self._log_finding("HudsonRock domain", f"{self.domain} → unexpected response format")
            return

        total_employees = data.get("stats", {}).get("totalEmployees", 0)
        total_users     = data.get("stats", {}).get("totalUsers", 0)
        total_stealers  = data.get("totalStealers", 0)
        total_records   = data.get("total", 0)

        # Collect all unique URLs from all_urls list (preserves type info)
        all_urls_raw = data.get("data", {}).get("all_urls", [])
        seen_urls: set[str] = set()
        unique_urls: list[dict] = []
        for entry in all_urls_raw:
            u = entry.get("url", "").strip()
            if u and u not in seen_urls:
                seen_urls.add(u)
                unique_urls.append(entry)

        # Fallback to stats lists if data.all_urls is absent
        if not unique_urls:
            employee_urls = data.get("stats", {}).get("employees_urls", [])
            client_urls   = data.get("stats", {}).get("clients_urls", [])
            for u in employee_urls:
                if u not in seen_urls:
                    seen_urls.add(u)
                    unique_urls.append({"url": u, "type": "Employee", "occurrence": 0})
            for u in client_urls:
                if u not in seen_urls:
                    seen_urls.add(u)
                    unique_urls.append({"url": u, "type": "User", "occurrence": 0})

        if total_records or total_employees or total_users:
            self._add_finding(
                source="hudsonrock_domain",
                domain=self.domain,
                total_stealers=total_stealers,
                total_employees=total_employees,
                total_users=total_users,
                exposed_urls=[e["url"] for e in unique_urls],
                severity="critical",
            )
            self._log_finding(
                "HudsonRock domain",
                f"{self.domain} → {total_stealers:,} stealer records | "
                f"{total_employees} employee(s) | {total_users} user(s) compromised | "
                f"{len(unique_urls)} unique URL(s) exposed",
            )
            for entry in unique_urls:
                tag = "Employee" if entry.get("type") == "Employee" else "User   "
                occ = entry.get("occurrence", 0)
                self._log_finding(
                    "HudsonRock domain",
                    f"  [{tag}] ({occ:>3}x) {entry['url']}",
                )
        else:
            self._log_finding("HudsonRock domain", f"{self.domain} → no stealer results")

    # ------------------------------------------------------------------ #
    #  XposedOrNot  (open, no key)                                         #
    # ------------------------------------------------------------------ #

    async def _xon_email(self, email: str):
        import json as _j

        check_url = XON_CHECK_EP.format(email=urllib.parse.quote(email))
        res = await self._requester.get(check_url, extra_headers={"Accept": "application/json"})
        if res.status == 404:
            self._log_finding("XposedOrNot", f"{email} → not found in any breach")
            return
        if not res.ok:
            return
        try:
            check_data = _j.loads(res.text)
        except Exception:
            return

        # Handle rate-limit / violation drop response
        if isinstance(check_data, dict) and "detail" in check_data:
            detail = check_data["detail"]
            if isinstance(detail, dict) and "error" in detail:
                self._log_finding(
                    "XposedOrNot",
                    f"{email} → rate-limited: {detail.get('error','')} "
                    f"(violations: {detail.get('violation_count', '?')}, "
                    f"drop: {detail.get('drop_percentage', '?')})",
                )
                return

        raw_breaches = check_data.get("breaches", []) if isinstance(check_data, dict) else []
        breaches_found: list[str] = []

        def collect_breach_names(value: Any):
            if isinstance(value, str):
                if value:
                    breaches_found.append(value)
            elif isinstance(value, dict):
                for key in ("Name", "name", "BreachName", "breach_name"):
                    name = value.get(key)
                    if isinstance(name, str) and name:
                        breaches_found.append(name)
                        break
            elif isinstance(value, list):
                for item in value:
                    collect_breach_names(item)

        collect_breach_names(raw_breaches)
        if not breaches_found:
            self._log_finding("XposedOrNot", f"{email} → clean")
            return

        analytics_url = XON_ANALYTICS_EP.format(email=urllib.parse.quote(email))
        ares = await self._requester.get(analytics_url, extra_headers={"Accept": "application/json"})
        analytics: dict = {}
        if ares.ok:
            try:
                analytics = _j.loads(ares.text)
            except Exception:
                pass

        breach_details: list[dict] = []
        if isinstance(analytics, dict):
            for item in analytics.get("BreachMetrics", {}).get("Breaches_Details", []):
                breach_details.append(item)

        detail_map = {
            b.get("Name", ""): b
            for b in breach_details
            if isinstance(b, dict) and isinstance(b.get("Name", ""), str)
        }

        for name in breaches_found:
            detail = detail_map.get(name, {})
            dc     = detail.get("DataClasses", []) if isinstance(detail.get("DataClasses"), list) else []
            sev    = _severity(dc) if dc else "high"
            self._add_finding(
                source="xon_email",
                email=email,
                breach_name=name,
                breach_date=detail.get("BreachDate", ""),
                pwn_count=detail.get("PwnCount", 0),
                data_classes=tuple(dc),
                severity=sev,
            )
            self._log_finding("XposedOrNot",
                f"{email} → [{sev.upper()}] {name} ({detail.get('BreachDate', '?')})")

    # ------------------------------------------------------------------ #
    #  Dork generation                                                     #
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    #  Credential pattern scan (passive — target's own files)              #
    # ------------------------------------------------------------------ #

    async def _credential_scan(self):
        probe_urls = [self.target] + [urljoin(self.target, p) for p in PASTE_PROBE_PATHS]
        results = await self._requester.fetch_many(probe_urls)
        for res in results:
            if not res.ok:
                continue
            body = res.text or ""
            path = urlparse(res.url).path
            for m in CRED_RE.finditer(body):
                raw  = m.group(0).strip()
                em_m = EMAIL_RE.match(raw)
                if not em_m:
                    continue
                em = em_m.group(0).lower()
                self._add_finding(
                    source="credential_pattern", email=em,
                    credential_hint=raw[:150], found_at=path,
                    severity="critical",
                )
                self._log_finding("cred leak", f"[CRITICAL] {path} → {raw[:80]}")

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _dedup(self, findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        out:  list[dict] = []
        for f in findings:
            key = "|".join(str(f.get(k,"")).lower() for k in
                           ("source","email","domain","breach_name","paste_id","dork","combo_line"))
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    # ------------------------------------------------------------------ #
    #  Summary                                                             #
    # ------------------------------------------------------------------ #

    def _print_summary(self):
        if not self._findings:
            self._logger.warning("No breach data found.")
            return

        def _by(*srcs): return [f for f in self._findings if f.get("source") in srcs]

        hibp_b    = _by("hibp_breach")
        hibp_p    = _by("hibp_paste")
        scylla    = _by("scylla_email","scylla_domain")
        proxyn    = _by("proxynova","proxynova_domain")
        leakchk   = _by("leakcheck_email")
        dehash    = _by("dehashed")
        hudsonrck = _by("hudsonrock_email","hudsonrock_domain")
        xon       = _by("xon_email")
        creds     = _by("credential_pattern")

        for f in hibp_b:
            self._log_finding("HIBP breach",
                f"{f.get('email','')} → [{f.get('severity','').upper()}] "
                f"{f.get('breach_title','')} ({f.get('breach_date','')}) | {f.get('pwn_count',0):,} records")

        for f in hibp_p:
            self._log_finding("HIBP paste",
                f"{f.get('email','')} → {f.get('paste_source','')}/{f.get('paste_id','')}")

        for f in scylla:
            pw = " | pw hash present" if f.get("password_hash") else ""
            self._log_finding("Scylla",
                f"{f.get('email','')} — {f.get('breach_name','')}{pw}")

        for f in proxyn:
            self._log_finding("ProxyNova",
                f"{f.get('email','')} — {f.get('combo_line','')[:80]}")

        for f in leakchk:
            self._log_finding("LeakCheck",
                f"{f.get('email','')} — {f.get('breach_name','')}")

        for f in dehash:
            self._log_finding("DeHashed", f.get("email",""))

        for f in hudsonrck:
            if f.get("source") == "hudsonrock_email":
                self._log_finding("HudsonRock",
                    f"{f.get('email','')} — stealer: {f.get('stealer_family','')} | {f.get('date_uploaded','')}")
            else:
                self._log_finding("HudsonRock domain",
                    f"{f.get('domain','')} → {f.get('total_stealers',0):,} stealer records | "
                    f"{f.get('total_employees',0)} employee(s) | {f.get('total_users',0)} user(s)")

        for f in xon:
            self._log_finding("XposedOrNot",
                f"{f.get('email','')} → [{f.get('severity','').upper()}] {f.get('breach_name','')}")

        for f in creds:
            self._log_finding("cred leak",
                f"[CRITICAL] {f.get('found_at','')} → {f.get('credential_hint','')[:80]}")

        if creds:
            self._logger.warning(f"⚠ CRITICAL: {len(creds)} credential pattern(s) on target!")
        large = [f for f in hibp_b if f.get("is_large")]
        if large:
            self._logger.warning(f"⚠ {len(large)} breach(es) >1M records")

        self._logger.table(
            ["Source", "Count"],
            [
                ["HIBP breaches",       str(len(hibp_b))],
                ["HIBP pastes",         str(len(hibp_p))],
                ["Scylla",              str(len(scylla))],
                ["ProxyNova",           str(len(proxyn))],
                ["LeakCheck",           str(len(leakchk))],
                ["DeHashed",            str(len(dehash))],
                ["HudsonRock",          str(len(hudsonrck))],
                ["XposedOrNot",         str(len(xon))],
                ["Credential patterns", str(len(creds))],
            ],
        )

        sev: dict[str,int] = {}
        for f in self._findings:
            s = f.get("severity","low")
            sev[s] = sev.get(s,0) + 1
        self._logger.table(
            ["Severity","Count"],
            [[k.upper(), str(v)] for k,v in sorted(sev.items())]
        )

        dc_count: dict[str,int] = {}
        for f in hibp_b:
            for dc in f.get("data_classes",[]):
                dc_count[dc] = dc_count.get(dc,0) + 1
        if dc_count:
            top = sorted(dc_count.items(), key=lambda x: -x[1])[:10]
            self._logger.table(
                ["Exposed Data Class","Breach Count"],
                [[dc, str(n)] for dc,n in top]
            )