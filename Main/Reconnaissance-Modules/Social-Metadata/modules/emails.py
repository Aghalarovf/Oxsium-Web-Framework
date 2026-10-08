import json
import re
from typing import Any
from urllib.parse import unquote

from bs4 import BeautifulSoup

from core.traffic import Entry
from .base import BaseModule


EMAIL_PATTERN = re.compile(
    r"""(?<![=\w@.])
        ([\w+\-.]+
        @
        [\w\-]+(?:\.[\w\-]+)*
        \.
        [a-zA-Z]{2,})
        (?![.\w@])
    """,
    re.VERBOSE | re.IGNORECASE,
)

RAW_EMAIL_PATTERN = re.compile(
    r"""(?<![\w@.])
        ([\w+\-.]+
        @
        [\w\-]+(?:\.[\w\-]+)*
        \.
        [a-zA-Z]{2,})
        (?![.\w@])
    """,
    re.VERBOSE | re.IGNORECASE,
)

MAILTO_PATTERN = re.compile(r"mailto:([^\"'?\s<>]+)", re.IGNORECASE)

OBFUSCATED_AT = re.compile(
    r"([\w+\-.]+)\s*(?:\[at\]|\(at\)|\{at\}|＠|\[@\]|\(@\))\s*([\w\-.]+)\s*(?:\[dot\]|\(dot\)|\{dot\}|\.)\s*([a-zA-Z]{2,})",
    re.IGNORECASE,
)

ENTITY_EMAIL_PATTERN = re.compile(
    r"([\w+\-.]+)\s*(?:&#64;|&#x40;|&commat;|\\u0040|\\x40)\s*([\w\-.]+\.(?:[a-zA-Z]{2,}))",
    re.IGNORECASE,
)

JS_CONCAT_PATTERN = re.compile(
    r"""["']([^"'@\s]{1,64})["']\s*\+\s*["']@["']\s*\+\s*["']([^"'@\s]{1,128})["']""",
    re.IGNORECASE,
)

JS_REVERSED_PATTERN = re.compile(
    r"""["']([A-Za-z]{2,}(?:\.[\w\-]+)+@[\w+\-.]+)["']\s*\.split\(\s*["']{2}\s*\)\s*\.reverse""",
    re.IGNORECASE,
)

DATA_EMAIL_ATTR = re.compile(r"data-(?:email|mail)=[\"']([^\"']+)[\"']", re.IGNORECASE)
DATA_USER_ATTR = re.compile(r"data-(?:user|name|local)=[\"']([^\"']+)[\"']", re.IGNORECASE)
DATA_DOMAIN_ATTR = re.compile(r"data-(?:domain|host|site)=[\"']([^\"'@\s]+)[\"']", re.IGNORECASE)

SCHEMA_EMAIL_KEY = re.compile(r'"email"\s*:\s*"([^"]+)"', re.IGNORECASE)

SENSITIVE_JS_KEYS = re.compile(
    r"(?i)(email|mail|contact|reply[_\-]?to|from[_\-]?address|notification)",
)

JS_VAR_PATTERN = re.compile(
    r"""(?:var|let|const)\s+(\w+)\s*=\s*["']([^"']{6,})["']""",
    re.MULTILINE,
)

JS_KEY_VALUE_PATTERN = re.compile(
    r"""["']?(\w*(?:email|mail|contact|reply_?to|from_?address)\w*)["']?\s*[:=]\s*["']([^"'\s]{6,})["']""",
    re.IGNORECASE,
)

COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)

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

FILE_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "tif", "tiff", "ico", "avif", "heic",
    "mp4", "mp3", "mov", "avi", "mkv", "webm", "ogg", "wav", "woff", "woff2", "ttf", "otf", "eot",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "tar", "gz", "rar", "7z",
    "css", "js", "mjs", "json", "xml", "html", "htm", "php", "asp", "aspx", "map", "txt", "md",
    "min", "img", "thumb", "preview", "webmanifest",
}

_SUSPICIOUS_LOCAL = re.compile(r"(?:\.(?:%s)$|^\d+$|^[\d.]+$)" % "|".join(sorted(FILE_EXTENSIONS)), re.IGNORECASE)
_RETINA_LOCAL = re.compile(r"(?:^|[-_.])\d+x$", re.IGNORECASE)

HIGH_CONFIDENCE_SOURCES = {"mailto_href", "data_attr", "schema_org", "hcard"}


def _is_role_based(email: str) -> bool:
    local = email.split("@")[0].lower().strip("+.-_")
    return local in ROLE_PREFIXES


def _normalise_email(email: str) -> str:
    return email.strip().strip(".,;:()<>[]\"'").lower()


def _is_false_positive_email(email: str) -> bool:
    if email.count("@") != 1:
        return True
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain:
        return True
    if _SUSPICIOUS_LOCAL.search(local) or _RETINA_LOCAL.search(local):
        return True
    labels = domain.split(".")
    if labels[-1] in FILE_EXTENSIONS:
        return True
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return True
    if all(label.isdigit() for label in labels[:-1]):
        return True
    return False


class EmailsModule(BaseModule):
    NAME = "emails"
    DESCRIPTION = "Multi-source email pattern extraction from captured traffic (offline)"

    async def run(self) -> list[dict[str, Any]]:
        self.logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        self._emails: dict[str, dict[str, Any]] = {}

        entries = self.traffic.texts()
        self.logger.info(f"Scanning {len(entries)} captured text response(s)")

        for entry in entries:
            self._scan_entry(entry)

        for item in self._emails.values():
            self._findings.append(item)

        self._print_summary()
        return self._findings

    def _scan_entry(self, entry: Entry) -> None:
        text = entry.body
        page = entry.url
        soup = BeautifulSoup(text, "lxml") if entry.is_html else None

        if soup is not None:
            self._extract_mailto_hrefs(soup, page)
            self._extract_plain_text_emails(soup, page)
            self._extract_data_attributes(soup, page)
            self._extract_hcard_emails(soup, page)
            self._extract_schema_org_emails(soup, page)
            scripts = "\n".join(
                s.get_text() for s in soup.find_all("script")
                if not s.get("src") and s.get_text() and (s.get("type") or "").lower() != "application/ld+json"
            )
            self._extract_html_comment_emails(text, page)
        else:
            scripts = text
            self._extract_mailto_from_text(text, page)
            self._extract_plain_text_from_raw(text, page)
            self._extract_json_body(text, page)

        self._extract_obfuscated_at(text, page)
        self._extract_entity_encoded(text, page)
        self._extract_js_concat(scripts, page)
        self._extract_js_variable_leaks(scripts, page)

    def _extract_mailto_hrefs(self, soup: BeautifulSoup, page: str):
        for tag in soup.find_all("a", href=re.compile(r"^\s*mailto:", re.I)):
            match = MAILTO_PATTERN.search(tag.get("href", ""))
            if not match:
                continue
            for part in unquote(match.group(1)).split(","):
                email = _normalise_email(part.split("?")[0])
                if not EMAIL_PATTERN.fullmatch(email):
                    continue
                self._add_email_finding(
                    page,
                    source="mailto_href",
                    email=email,
                    anchor_text=tag.get_text(strip=True)[:120] or None,
                    confidence="high",
                )

    def _extract_mailto_from_text(self, text: str, page: str):
        for match in MAILTO_PATTERN.finditer(text):
            for part in unquote(match.group(1)).split(","):
                email = _normalise_email(part.split("?")[0])
                if EMAIL_PATTERN.fullmatch(email):
                    self._add_email_finding(page, source="mailto_href", email=email, confidence="high")

    def _extract_plain_text_emails(self, soup: BeautifulSoup, page: str):
        body = soup.find("body") or soup
        visible = body.get_text(separator=" ")
        for match in EMAIL_PATTERN.finditer(visible):
            email = _normalise_email(match.group(0))
            self._add_email_finding(page, source="plaintext", email=email, confidence="high")

    def _extract_plain_text_from_raw(self, text: str, page: str):
        for match in RAW_EMAIL_PATTERN.finditer(text):
            email = _normalise_email(match.group(0))
            self._add_email_finding(page, source="plaintext", email=email, confidence="medium")

    def _extract_json_body(self, text: str, page: str):
        stripped = text.lstrip()
        if not stripped.startswith(("{", "[")):
            return
        try:
            data = json.loads(stripped)
        except ValueError:
            return
        self._walk_json_for_emails(data, "json_body", page)

    def _extract_obfuscated_at(self, text: str, page: str):
        for match in OBFUSCATED_AT.finditer(text):
            local, domain_part, tld = match.group(1), match.group(2), match.group(3)
            email = _normalise_email(f"{local}@{domain_part}.{tld}")
            if not EMAIL_PATTERN.fullmatch(email):
                continue
            self._add_email_finding(
                page,
                source="obfuscated_at",
                email=email,
                raw=match.group(0)[:120],
                confidence="medium",
            )

    def _extract_entity_encoded(self, text: str, page: str):
        for match in ENTITY_EMAIL_PATTERN.finditer(text):
            email = _normalise_email(f"{match.group(1)}@{match.group(2)}")
            if not EMAIL_PATTERN.fullmatch(email):
                continue
            self._add_email_finding(page, source="entity_encoded", email=email, confidence="medium")

    def _extract_js_concat(self, scripts: str, page: str):
        for match in JS_CONCAT_PATTERN.finditer(scripts):
            email = _normalise_email(f"{match.group(1)}@{match.group(2)}")
            if not EMAIL_PATTERN.fullmatch(email):
                continue
            self._add_email_finding(
                page,
                source="js_concat",
                email=email,
                raw=match.group(0)[:120],
                confidence="medium",
            )
        for match in JS_REVERSED_PATTERN.finditer(scripts):
            email = _normalise_email(match.group(1)[::-1])
            if not EMAIL_PATTERN.fullmatch(email):
                continue
            self._add_email_finding(
                page,
                source="js_reversed",
                email=email,
                raw=match.group(0)[:120],
                confidence="medium",
            )

    def _extract_data_attributes(self, soup: BeautifulSoup, page: str):
        for tag in soup.find_all(True):
            attrs = " ".join(f'{k}="{v}"' for k, v in tag.attrs.items() if isinstance(v, str))
            if "data-" not in attrs:
                continue

            direct = DATA_EMAIL_ATTR.search(attrs)
            if direct:
                email = _normalise_email(direct.group(1))
                if EMAIL_PATTERN.fullmatch(email):
                    self._add_email_finding(
                        page,
                        source="data_attr",
                        email=email,
                        attr="data-email",
                        confidence="high",
                    )

            user = DATA_USER_ATTR.search(attrs)
            domain = DATA_DOMAIN_ATTR.search(attrs)
            if user and domain:
                email = _normalise_email(f"{user.group(1)}@{domain.group(1)}")
                if EMAIL_PATTERN.fullmatch(email):
                    self._add_email_finding(
                        page,
                        source="data_attr_composite",
                        email=email,
                        attr="data-user+data-domain",
                        confidence="medium",
                    )

    def _extract_schema_org_emails(self, soup: BeautifulSoup, page: str):
        for script in soup.find_all("script", type="application/ld+json"):
            raw = script.get_text(strip=True)
            for match in SCHEMA_EMAIL_KEY.finditer(raw):
                email = _normalise_email(match.group(1).replace("mailto:", ""))
                if EMAIL_PATTERN.fullmatch(email):
                    self._add_email_finding(page, source="schema_org", email=email, confidence="high")
            try:
                data = json.loads(raw)
            except ValueError:
                continue
            self._walk_json_for_emails(data, "schema_org", page)

    def _walk_json_for_emails(self, node: Any, source: str, page: str, depth: int = 0):
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                if isinstance(val, str):
                    email = _normalise_email(val.replace("mailto:", ""))
                    if EMAIL_PATTERN.fullmatch(email):
                        self._add_email_finding(
                            page,
                            source=source,
                            email=email,
                            json_key=key,
                            confidence="high" if key.lower() in ("email", "mail") else "medium",
                        )
                else:
                    self._walk_json_for_emails(val, source, page, depth + 1)
        elif isinstance(node, list):
            for item in node:
                self._walk_json_for_emails(item, source, page, depth + 1)
        elif isinstance(node, str):
            email = _normalise_email(node)
            if EMAIL_PATTERN.fullmatch(email):
                self._add_email_finding(page, source=source, email=email, confidence="medium")

    def _extract_hcard_emails(self, soup: BeautifulSoup, page: str):
        for tag in soup.find_all(class_=re.compile(r"\bemail\b", re.I)):
            href = tag.get("href", "")
            if href.startswith("mailto:"):
                email = _normalise_email(unquote(href[7:]).split("?")[0])
            else:
                email = _normalise_email(tag.get_text(strip=True))
            if EMAIL_PATTERN.fullmatch(email):
                self._add_email_finding(page, source="hcard", email=email, confidence="high")

    def _extract_js_variable_leaks(self, scripts: str, page: str):
        seen: set[tuple[str, str]] = set()
        for pattern in (JS_VAR_PATTERN, JS_KEY_VALUE_PATTERN):
            for match in pattern.finditer(scripts):
                name, value = match.group(1), match.group(2)
                if not SENSITIVE_JS_KEYS.search(name) or (name, value) in seen:
                    continue
                seen.add((name, value))
                email = _normalise_email(value)
                if EMAIL_PATTERN.fullmatch(email):
                    self._add_email_finding(
                        page,
                        source="js_variable",
                        email=email,
                        variable=name,
                        value=value[:200],
                        confidence="medium",
                    )

    def _extract_html_comment_emails(self, html: str, page: str):
        for match in COMMENT_PATTERN.finditer(html):
            comment = match.group(1)
            if not EMAIL_PATTERN.search(comment):
                continue
            for em in EMAIL_PATTERN.finditer(comment):
                email = _normalise_email(em.group(0))
                self._add_email_finding(
                    page,
                    source="html_comment",
                    email=email,
                    raw=comment.strip()[:200],
                    confidence="medium",
                )

    def _add_email_finding(self, page: str, *, source: str, email: str, **extra):
        if not email or "@" not in email:
            return
        if source not in HIGH_CONFIDENCE_SOURCES and _is_false_positive_email(email):
            self.logger.debug(f"[{source}] false-positive skipped: {email}")
            return
        if source in HIGH_CONFIDENCE_SOURCES and email.count("@") != 1:
            return
        slot = self._emails.get(email)
        if slot is None:
            entry = {k: v for k, v in extra.items() if v not in (None, "", [], {})}
            slot = {
                "source": source,
                "email": email,
                "role_based": _is_role_based(email),
                "own_domain": self._is_own_domain(email),
                **entry,
                "sources": [source],
                "found_on": [page],
            }
            self._emails[email] = slot
            return
        if source not in slot["sources"]:
            slot["sources"].append(source)
        if page not in slot["found_on"]:
            slot["found_on"].append(page)

    def _is_own_domain(self, email: str) -> bool:
        email_domain = email.split("@")[-1].lower()
        if email_domain.startswith("www."):
            email_domain = email_domain[4:]
        return email_domain == self.domain or email_domain.endswith(f".{self.domain}")

    def _print_summary(self):
        if not self._findings:
            self.logger.warning("No email addresses discovered.")
            return

        labels = {
            "mailto_href": "mailto href", "plaintext": "plaintext", "obfuscated_at": "obfuscated [at]",
            "entity_encoded": "entity/escaped @", "js_concat": "JS concat", "js_reversed": "JS reversed",
            "data_attr": "data-attr", "data_attr_composite": "data-attr", "schema_org": "schema.org",
            "hcard": "hCard", "js_variable": "JS variable", "html_comment": "HTML comment",
            "json_body": "JSON body",
        }
        for f in self._findings:
            label = labels.get(f["source"], f["source"])
            role = "role" if f.get("role_based") else "personal"
            self._log_finding(label, f"{f['email']}  [{f.get('confidence', '')}] {role}")

        by_source: dict[str, int] = {}
        role_count = 0
        for f in self._findings:
            for src in f["sources"]:
                by_source[src] = by_source.get(src, 0) + 1
            if f.get("role_based"):
                role_count += 1

        self.logger.table(
            ["Source", "Count"],
            [[src, str(cnt)] for src, cnt in sorted(by_source.items())],
        )
        total = len(self._findings)
        self.logger.info(
            f"Total unique emails: {total}  |  Role-based: {role_count}  |  Personal: {total - role_count}"
        )
