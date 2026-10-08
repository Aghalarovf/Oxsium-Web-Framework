import asyncio
import json as _json
import re
from collections import Counter
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .base import BaseEmailModule


INTERNAL_LINK_SKIP = re.compile(
    r"^(mailto:|tel:|javascript:|#|data:)",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"""(?<![=\w@.])
        ([\w+\-.]+
        @
        [\w\-.]+
        \.
        [a-zA-Z]{2,})
        (?![.\w])
    """,
    re.VERBOSE | re.IGNORECASE,
)

EMAIL_RE = re.compile(r"[\w+\-.]+@[\w\-.]+\.[a-zA-Z]{2,}", re.IGNORECASE)

MAILTO_PATTERN = re.compile(r'href=["\']mailto:([^"\'?\s]+)', re.IGNORECASE)

OBFUSCATED_AT = re.compile(
    r"([\w+\-.]+)\s*(?:\[at\]|\(at\)|＠|&#64;|%40|\bat\b)\s*([\w\-.]+)\s*(?:\[dot\]|\(dot\)|\bdot\b|\.)\s*([a-zA-Z]{2,})",
    re.IGNORECASE,
)

ENTITY_EMAIL_PATTERN = re.compile(
    r"([\w+\-.]+)\s*(?:&#64;|&#x40;|&commat;)\s*([\w\-.]+\.(?:[a-zA-Z]{2,}))",
    re.IGNORECASE,
)

JS_CONCAT_PATTERN = re.compile(
    r"""["\']([^"\'@\s]{1,64})["\']\s*\+\s*["\']@["\']\s*\+\s*["\']([^"\'@\s]{1,128})["\']""",
    re.IGNORECASE,
)

DATA_EMAIL_ATTR  = re.compile(r'data-(?:email|mail)=["\']([^"\']+)["\']', re.IGNORECASE)
DATA_USER_ATTR   = re.compile(r'data-(?:user|name|local)=["\']([^"\']+)["\']', re.IGNORECASE)
DATA_DOMAIN_ATTR = re.compile(r'data-(?:domain|host|site)=["\']([^"\'@\s]+)["\']', re.IGNORECASE)

SCHEMA_EMAIL_KEY = re.compile(r'"email"\s*:\s*"([^"]+)"', re.IGNORECASE)

SENSITIVE_JS_KEYS = re.compile(
    r"(?i)(email|mail|contact|reply[_\-]?to|from[_\-]?address|notification)"
)

JS_VAR_PATTERN = re.compile(
    r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']{6,})["\']',
    re.MULTILINE,
)

COMMENT_EMAIL_KEYWORDS = [
    "email", "mail", "contact", "author", "admin", "support",
    "todo", "fixme", "webmaster", "reply", "from",
]

ROLE_PREFIXES = {
    "admin", "administrator", "webmaster", "hostmaster", "postmaster",
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "info", "contact", "support", "help", "sales", "marketing",
    "security", "abuse", "privacy", "legal", "billing",
    "hello", "hi", "team", "press", "media", "career", "jobs",
    "newsletter", "noc", "devnull", "mailer-daemon",
}

COMMON_EMAIL_PREFIXES = [
    "admin", "administrator", "support", "help", "info", "contact",
    "hello", "hi", "team", "mail", "email", "office", "hr", "jobs",
    "careers", "sales", "marketing", "billing", "accounts", "finance",
    "legal", "privacy", "security", "abuse", "postmaster", "webmaster",
    "noreply", "no-reply", "donotreply", "feedback", "press", "media",
    "partners", "invest", "investor", "compliance", "it", "devops",
]

FORMAT_PATTERNS = {
    "first.last": "{first}.{last}",
    "firstlast":  "{first}{last}",
    "first_last": "{first}_{last}",
    "flast":      "{f}{last}",
    "firstl":     "{first}{l}",
    "last.first": "{last}.{first}",
    "first":      "{first}",
    "f.last":     "{f}.{last}",
}

EMAIL_PROBE_PATHS = [
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/contact",
    "/contact-us",
    "/about",
    "/about-us",
    "/team",
    "/staff",
    "/authors",
    "/sitemap.xml",
    "/robots.txt",
    "/ads.txt",
    "/app-ads.txt",
]

CRAWL_URLS = [
    "https://{domain}",
    "https://www.{domain}",
    "https://{domain}/contact",
    "https://{domain}/about",
    "https://{domain}/team",
    "https://{domain}/contact-us",
    "https://{domain}/about-us",
    "https://{domain}/careers",
    "https://{domain}/staff",
]


def _is_role_based(email: str) -> bool:
    local = email.split("@")[0].lower().strip("+.-_")
    return local in ROLE_PREFIXES


def _normalise_email(email: str) -> str:
    return email.strip().lower()


class HarvestReconModule(BaseEmailModule):
    NAME = "harvest_recon"
    DESCRIPTION = (
        "Email OSINT: web harvest, obfuscation bypass, social pattern analysis, "
        "email format detection, and conventional address checks"
    )

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    async def run(self, domain: str) -> dict:
        self._logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        harvested       = await self._harvest_all(domain)
        social_patterns = await self._extract_social_patterns(domain)
        format_patterns = self._guess_email_format_patterns(harvested)
        conventional    = await self._enumerate_conventional_emails(domain)

        return {
            "harvested_emails":    harvested,
            "social_patterns":     social_patterns,
            "email_format_patterns": format_patterns,
            "conventional_emails": conventional,
        }

    async def _harvest_all(self, domain: str) -> list[str]:
        found: set[str] = set()

        target_url = f"https://{domain}"
        html_result = await self._requester.get(target_url)
        if not html_result or not html_result.ok:
            self._logger.warning(f"Failed to fetch {target_url}")
            return []

        html = html_result.text
        soup = BeautifulSoup(html, "lxml")

        email_sets = await asyncio.gather(
            self._extract_mailto_hrefs(soup),
            self._extract_plain_text_emails(soup),
            self._extract_obfuscated_at(html),
            self._extract_entity_encoded(html),
            self._extract_js_concat(soup),
            self._extract_data_attributes(soup),
            self._extract_schema_org_emails(soup),
            self._extract_hcard_emails(soup),
            self._extract_js_variable_leaks(soup),
            self._extract_html_comment_emails(html),
            self._probe_well_known_paths(domain),
        )

        for s in email_sets:
            found.update(s)

        found = {e for e in found if domain.lower() in e.lower()}

        await self._crawl_first_level(soup, domain, found)

        raw_crawl_urls = [u.format(domain=domain) for u in CRAWL_URLS]
        for url in raw_crawl_urls:
            text = await self._requester.get_text(url)
            if not text:
                continue
            for email in EMAIL_RE.findall(text):
                email_lower = email.lower()
                if domain.lower() in email_lower:
                    found.add(email_lower)

        for email in sorted(found):
            self._logger.finding("HARVEST", "Email found", email, confidence=0.9)

        return sorted(found)

    async def _crawl_first_level(self, root_soup: BeautifulSoup, domain: str, found: set[str]):
        endpoints = self._collect_internal_links(root_soup, domain)
        if not endpoints:
            return

        self._logger.section(f"[CRAWL] {len(endpoints)} first-level endpoint(s)")
        semaphore = asyncio.Semaphore(10)

        async def scan_endpoint(url: str):
            async with semaphore:
                result = await self._requester.get(url)
                if not result or not result.ok:
                    return
                ep_html = result.text
                ep_soup = BeautifulSoup(ep_html, "lxml")

                sets = await asyncio.gather(
                    self._extract_mailto_hrefs(ep_soup),
                    self._extract_plain_text_emails(ep_soup),
                    self._extract_obfuscated_at(ep_html),
                    self._extract_entity_encoded(ep_html),
                    self._extract_js_concat(ep_soup),
                    self._extract_data_attributes(ep_soup),
                    self._extract_schema_org_emails(ep_soup),
                    self._extract_hcard_emails(ep_soup),
                    self._extract_js_variable_leaks(ep_soup),
                    self._extract_html_comment_emails(ep_html),
                )
                for s in sets:
                    found.update(e for e in s if domain.lower() in e.lower())

        await asyncio.gather(*[scan_endpoint(u) for u in endpoints])

    def _collect_internal_links(self, soup: BeautifulSoup, domain: str) -> list[str]:
        seen: set[str] = set()
        links: list[str] = []

        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if not href or INTERNAL_LINK_SKIP.match(href):
                continue

            if href.startswith("http"):
                parsed = urlparse(href)
                host = (parsed.hostname or "").lower().lstrip("www.")
                if host != domain and not host.endswith(f".{domain}"):
                    continue
                full = href
            elif href.startswith("//"):
                full = f"https:{href}"
            else:
                full = urljoin(f"https://{domain}", href)

            canonical = self._canonical_url(full)
            base      = self._canonical_url(f"https://{domain}")
            if canonical and canonical not in seen and canonical != base:
                seen.add(canonical)
                links.append(canonical)

        return links

    @staticmethod
    def _canonical_url(url: str) -> str:
        url = url.strip()
        if not url:
            return ""
        if url.startswith("//"):
            url = "https:" + url
        if not url.startswith("http"):
            return url
        try:
            parsed = urlparse(url)
            host   = parsed.netloc.lower().lstrip("www.")
            path   = parsed.path.rstrip("/")
            return f"{parsed.scheme}://{host}{path}"
        except Exception:
            return url

    async def _extract_mailto_hrefs(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        for tag in soup.find_all("a", href=re.compile(r"^mailto:", re.I)):
            match = MAILTO_PATTERN.search(tag.get("href", ""))
            if not match:
                continue
            email = _normalise_email(match.group(1).split("?")[0])
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)
        return found

    async def _extract_plain_text_emails(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        for tag in soup.find_all(["body", "main", "footer", "section", "article", "p", "span", "li", "td"]):
            for match in EMAIL_PATTERN.finditer(tag.get_text(separator=" ")):
                found.add(_normalise_email(match.group(0)))
        return found

    async def _extract_obfuscated_at(self, html: str) -> set[str]:
        found: set[str] = set()
        for match in OBFUSCATED_AT.finditer(html):
            email = _normalise_email(f"{match.group(1)}@{match.group(2)}.{match.group(3)}")
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)
                self._logger.finding("OBFUSCATED", "email", email, confidence=0.7)
        return found

    async def _extract_entity_encoded(self, html: str) -> set[str]:
        found: set[str] = set()
        for match in ENTITY_EMAIL_PATTERN.finditer(html):
            email = _normalise_email(f"{match.group(1)}@{match.group(2)}")
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)
        return found

    async def _extract_js_concat(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        inline_js = "\n".join(
            s.get_text() for s in soup.find_all("script")
            if not s.get("src") and s.get_text()
        )
        for match in JS_CONCAT_PATTERN.finditer(inline_js):
            email = _normalise_email(f"{match.group(1)}@{match.group(2)}")
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)
        return found

    async def _extract_data_attributes(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        for tag in soup.find_all(True):
            attrs = " ".join(f'{k}="{v}"' for k, v in tag.attrs.items() if isinstance(v, str))
            dm = DATA_EMAIL_ATTR.search(attrs)
            if dm:
                email = _normalise_email(dm.group(1))
                if EMAIL_PATTERN.fullmatch(email):
                    found.add(email)
            um  = DATA_USER_ATTR.search(attrs)
            ddm = DATA_DOMAIN_ATTR.search(attrs)
            if um and ddm:
                email = _normalise_email(f"{um.group(1)}@{ddm.group(1)}")
                if EMAIL_PATTERN.fullmatch(email):
                    found.add(email)
        return found

    async def _extract_schema_org_emails(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        for script in soup.find_all("script", type="application/ld+json"):
            raw = script.get_text(strip=True)
            for match in SCHEMA_EMAIL_KEY.finditer(raw):
                email = _normalise_email(match.group(1).strip())
                if EMAIL_PATTERN.fullmatch(email):
                    found.add(email)
            try:
                self._walk_json_for_emails(_json.loads(raw), found)
            except Exception:
                pass
        return found

    def _walk_json_for_emails(self, node: Any, found: set[str], depth: int = 0):
        if depth > 6:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                if key.lower() in ("email", "mail", "contactpoint", "author"):
                    if isinstance(val, str):
                        email = _normalise_email(val)
                        if EMAIL_PATTERN.fullmatch(email):
                            found.add(email)
                else:
                    self._walk_json_for_emails(val, found, depth + 1)
        elif isinstance(node, list):
            for item in node:
                self._walk_json_for_emails(item, found, depth + 1)
        elif isinstance(node, str):
            email = _normalise_email(node)
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)

    async def _extract_hcard_emails(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        for tag in soup.find_all(class_=re.compile(r"\bemail\b", re.I)):
            href = tag.get("href", "")
            if href.startswith("mailto:"):
                email = _normalise_email(href[7:].split("?")[0])
            else:
                email = _normalise_email(tag.get_text(strip=True))
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)
        return found

    async def _extract_js_variable_leaks(self, soup: BeautifulSoup) -> set[str]:
        found: set[str] = set()
        inline_js = "\n".join(
            s.get_text() for s in soup.find_all("script")
            if not s.get("src") and s.get_text()
        )
        for match in JS_VAR_PATTERN.finditer(inline_js):
            var_name, var_value = match.group(1), match.group(2)
            if not SENSITIVE_JS_KEYS.search(var_name):
                continue
            email = _normalise_email(var_value)
            if EMAIL_PATTERN.fullmatch(email):
                found.add(email)
        return found

    async def _extract_html_comment_emails(self, html: str) -> set[str]:
        found: set[str] = set()
        for match in re.finditer(r"<!--(.*?)-->", html, re.DOTALL):
            comment = match.group(1)
            if not any(kw in comment.lower() for kw in COMMENT_EMAIL_KEYWORDS):
                if not EMAIL_PATTERN.search(comment):
                    continue
            for em in EMAIL_PATTERN.finditer(comment):
                found.add(_normalise_email(em.group(0)))
        return found

    async def _probe_well_known_paths(self, domain: str) -> set[str]:
        found: set[str] = set()
        probe_urls = [urljoin(f"https://{domain}", p) for p in EMAIL_PROBE_PATHS]
        results = await self._requester.fetch_many(probe_urls)
        for res in results:
            if not res.ok:
                continue
            body = res.text
            for match in EMAIL_PATTERN.finditer(body):
                found.add(_normalise_email(match.group(0)))
        return found

    async def _extract_social_patterns(self, domain: str) -> dict:
        if not self._requester:
            return {"linkedin_found": False, "github_found": False, "patterns": []}

        patterns_found: list[str] = []
        linkedin_found = False
        github_found   = False

        li_text = await self._requester.get_text(
            f"https://www.linkedin.com/company/{domain.split('.')[0]}/people"
        )
        if li_text and "linkedin" in li_text.lower():
            linkedin_found = True
            for email in EMAIL_RE.findall(li_text):
                if domain.lower() in email.lower():
                    patterns_found.append(email.lower())

        gh_text = await self._requester.get_text(
            f"https://api.github.com/search/users?q={domain}&type=Users",
            headers={"Accept": "application/vnd.github+json"},
        )
        if gh_text and "login" in gh_text:
            github_found = True

        return {
            "linkedin_found": linkedin_found,
            "github_found":   github_found,
            "patterns":       list(set(patterns_found)),
        }

    def _guess_email_format_patterns(self, emails: list[str]) -> dict:
        if not emails:
            return {"detected_patterns": [], "confidence": 0.0, "sample_count": 0}

        local_parts = [
            email.split("@")[0]
            for email in emails
            if email.split("@")[0] not in COMMON_EMAIL_PREFIXES
        ]

        if not local_parts:
            return {"detected_patterns": [], "confidence": 0.0, "sample_count": 0}

        pattern_votes: Counter = Counter()
        for local in local_parts:
            if "." in local:
                parts = local.split(".", 1)
                if len(parts[0]) == 1:
                    pattern_votes["f.last"] += 1
                elif len(parts[0]) > 1 and len(parts[1]) > 1:
                    pattern_votes["first.last"] += 1
            elif "_" in local:
                pattern_votes["first_last"] += 1
            elif re.match(r"^[a-z]{1}[a-z]+$", local):
                pattern_votes["firstlast" if len(local) > 5 else "flast"] += 1

        if not pattern_votes:
            return {"detected_patterns": [], "confidence": 0.0, "sample_count": len(local_parts)}

        total = sum(pattern_votes.values())
        top_patterns = [
            {
                "pattern":   name,
                "template":  FORMAT_PATTERNS.get(name, name),
                "frequency": count,
                "confidence": round(count / total, 2),
            }
            for name, count in pattern_votes.most_common(3)
        ]

        best = top_patterns[0]
        self._logger.finding("FORMAT", "Email pattern", best["template"], confidence=best["confidence"])

        return {
            "detected_patterns": top_patterns,
            "confidence":        best["confidence"],
            "sample_count":      len(local_parts),
        }

    async def _enumerate_conventional_emails(self, domain: str) -> list[dict]:
        if not self._requester:
            return []

        results: list[dict] = []
        page_text = await self._requester.get_text(f"https://{domain}")

        for prefix in COMMON_EMAIL_PREFIXES[:20]:
            address = f"{prefix}@{domain}"
            if page_text and address.lower() in page_text.lower():
                self._logger.finding("CONVENTIONAL", "Confirmed address", address, confidence=0.95)
                results.append({"address": address, "status": "confirmed", "confidence": 0.95})
            else:
                results.append({"address": address, "status": "guessed", "confidence": 0.3})

        return results

