import re
from typing import Any

from bs4 import BeautifulSoup

from core.traffic import Entry
from .base import BaseModule


STANDARD_META_TAGS = [
    "description",
    "keywords",
    "author",
    "viewport",
    "robots",
    "googlebot",
    "bingbot",
    "referrer",
    "theme-color",
    "application-name",
    "rating",
    "revisit-after",
    "language",
    "copyright",
    "reply-to",
    "web_author",
    "category",
    "coverage",
    "distribution",
    "target",
    "HandheldFriendly",
    "MobileOptimized",
    "format-detection",
    "apple-mobile-web-app-capable",
    "apple-mobile-web-app-status-bar-style",
    "apple-mobile-web-app-title",
    "msapplication-TileColor",
    "msapplication-TileImage",
    "msapplication-config",
    "msapplication-navbutton-color",
    "msapplication-starturl",
]

OPEN_GRAPH_PREFIXES = [
    "og:",
    "music:",
    "video:",
    "article:",
    "book:",
    "profile:",
    "website:",
]

TWITTER_CARD_NAMES = [
    "twitter:card",
    "twitter:site",
    "twitter:site:id",
    "twitter:creator",
    "twitter:creator:id",
    "twitter:title",
    "twitter:description",
    "twitter:image",
    "twitter:image:alt",
    "twitter:player",
    "twitter:player:width",
    "twitter:player:height",
    "twitter:player:stream",
    "twitter:app:name:iphone",
    "twitter:app:id:iphone",
    "twitter:app:url:iphone",
    "twitter:app:name:ipad",
    "twitter:app:id:ipad",
    "twitter:app:url:ipad",
    "twitter:app:name:googleplay",
    "twitter:app:id:googleplay",
    "twitter:app:url:googleplay",
]

LINK_REL_TAGS = [
    "canonical",
    "alternate",
    "amphtml",
    "shortlink",
    "manifest",
    "apple-touch-icon",
    "icon",
    "shortcut icon",
    "mask-icon",
    "preconnect",
    "dns-prefetch",
    "stylesheet",
    "pingback",
    "search",
]

HTTP_EQUIV_TAGS = [
    "content-type",
    "content-language",
    "content-security-policy",
    "x-ua-compatible",
    "refresh",
    "pragma",
    "cache-control",
    "expires",
    "set-cookie",
    "default-style",
]

SENSITIVE_META_NAMES = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|apikey|auth|client[_-]?id"
    r"|access[_-]?key|private[_-]?key|app[_-]?id|app[_-]?secret|fb[_-]?app"
    r"|ga[_-]?tracking|gtm[_-]?id|sentry|datadog|mixpanel|segment[_-]?key"
    r"|amplitude|hotjar|intercom|hubspot|recaptcha|captcha)",
)

COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)

JS_VAR_PATTERN = re.compile(
    r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']{8,})["\']',
    re.MULTILINE,
)

INTERESTING_JS_KEYS = re.compile(
    r'(?i)(api[_-]?key|token|secret|password|passwd|apikey|auth|client[_-]?id|access[_-]?key)',
)

HIDDEN_FIELD_PATTERNS = [
    re.compile(
        r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        re.IGNORECASE,
    ),
    re.compile(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
        re.IGNORECASE,
    ),
]

CSP_DIRECTIVE_PATTERN = re.compile(r"([\w-]+)\s+([^;]+)")

TWITTER_CARD_TYPES = {"summary", "summary_large_image", "app", "player"}


class HtmlMetaModule(BaseModule):
    NAME = "html_meta"
    DESCRIPTION = "Standard Meta, Open Graph, Twitter Cards & HTML Leak Detection from captured traffic (offline)"

    async def run(self) -> list[dict[str, Any]]:
        self.logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        pages = self.traffic.pages()
        self.logger.info(f"Analysing {len(pages)} captured HTML page(s)")
        if not pages:
            self.logger.warning("No captured HTML pages (2xx) to analyse.")
            return self._findings

        for entry in pages:
            self._analyse_page(entry)

        self._findings = self._deduplicate(self._findings)
        self._print_summary()
        return self._findings

    def _analyse_page(self, entry: Entry):
        self._page = entry.url
        self.logger.info(f"Analysing captured page: {entry.url}")
        html = entry.body
        soup = BeautifulSoup(html, "lxml")

        self._extract_standard_meta(soup)
        self._extract_open_graph(soup)
        self._extract_twitter_cards(soup)
        self._extract_link_relations(soup)
        self._extract_http_equiv(soup)
        self._extract_sensitive_meta(soup)
        self._extract_html_comments(html)
        self._extract_hidden_fields(html)
        self._extract_js_leaks(soup)
        self._analyze_csp(soup)
        self._extract_charset(soup)

    def _extract_standard_meta(self, soup: BeautifulSoup):
        for name in STANDARD_META_TAGS:
            tag = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.I)})
            if not tag:
                continue
            content = tag.get("content", "").strip()
            if not content:
                continue
            self._add_finding(
                source="standard_meta",
                category="Standard",
                name=name.lower(),
                value=content,
                url=self._page,
            )
            self._log_finding("meta", f"{name} = {content[:80]}")

    def _extract_open_graph(self, soup: BeautifulSoup):
        og_tags = soup.find_all(
            "meta",
            property=lambda p: p and any(p.startswith(pfx) for pfx in OPEN_GRAPH_PREFIXES),
        )

        if not og_tags:
            og_tags = soup.find_all(
                "meta",
                attrs={"name": lambda n: n and any(n.startswith(pfx) for pfx in OPEN_GRAPH_PREFIXES)},
            )

        og_required = {"og:title", "og:type", "og:image", "og:url"}
        found_props: set[str] = set()

        for tag in og_tags:
            prop = (tag.get("property") or tag.get("name") or "").strip().lower()
            content = tag.get("content", "").strip()
            if not prop or not content:
                continue
            found_props.add(prop)
            self._add_finding(
                source="open_graph",
                category="OpenGraph",
                name=prop,
                value=content,
                url=self._page,
            )
            self._log_finding("og", f"{prop} = {content[:80]}")

        missing = og_required - found_props
        for prop in sorted(missing):
            self._add_finding(
                source="open_graph_missing",
                category="OpenGraph",
                name=prop,
                value="MISSING",
                url=self._page,
                severity="warn",
            )
            self._log_finding("og missing", prop)

    def _extract_twitter_cards(self, soup: BeautifulSoup):
        twitter_tags = soup.find_all(
            "meta",
            attrs={"name": lambda n: n and n.lower().startswith("twitter:")},
        )

        if not twitter_tags:
            twitter_tags = soup.find_all(
                "meta",
                property=lambda p: p and p.lower().startswith("twitter:"),
            )

        card_type: str = ""

        for tag in twitter_tags:
            name = (tag.get("name") or tag.get("property") or "").strip().lower()
            content = tag.get("content", "").strip()
            if not name or not content:
                continue
            if name == "twitter:card":
                card_type = content.lower()
                if card_type not in TWITTER_CARD_TYPES:
                    self._add_finding(
                        source="twitter_card",
                        category="TwitterCard",
                        name=name,
                        value=content,
                        url=self._page,
                        severity="warn",
                        note=f"Unrecognised card type: {content}",
                    )
                    self._log_finding("twitter warn", f"unknown card type: {content}")
                    continue
            self._add_finding(
                source="twitter_card",
                category="TwitterCard",
                name=name,
                value=content,
                url=self._page,
            )
            self._log_finding("twitter", f"{name} = {content[:80]}")

        if twitter_tags and not card_type:
            self._add_finding(
                source="twitter_card",
                category="TwitterCard",
                name="twitter:card",
                value="MISSING",
                url=self._page,
                severity="warn",
            )
            self._log_finding("twitter missing", "twitter:card not declared")

    def _extract_link_relations(self, soup: BeautifulSoup):
        for rel_value in LINK_REL_TAGS:
            tags = soup.find_all(
                "link",
                rel=lambda r: r and rel_value in (r if isinstance(r, list) else r.split()),
            )
            for tag in tags:
                href = tag.get("href", "").strip()
                if not href:
                    continue
                extra: dict[str, Any] = {}
                for attr in ("type", "hreflang", "media", "sizes", "title", "color"):
                    val = tag.get(attr)
                    if val:
                        extra[attr] = val
                self._add_finding(
                    source="link_rel",
                    category="LinkRel",
                    name=rel_value,
                    value=href,
                    url=self._page,
                    **extra,
                )
                self._log_finding("link rel", f"{rel_value} -> {href[:80]}")

    def _extract_http_equiv(self, soup: BeautifulSoup):
        for tag in soup.find_all("meta", attrs={"http-equiv": True}):
            equiv = tag.get("http-equiv", "").strip().lower()
            content = tag.get("content", "").strip()
            if not equiv:
                continue
            self._add_finding(
                source="http_equiv",
                category="HttpEquiv",
                name=equiv,
                value=content,
                url=self._page,
            )
            self._log_finding("http-equiv", f"{equiv} = {content[:80]}")

    def _extract_sensitive_meta(self, soup: BeautifulSoup):
        for tag in soup.find_all("meta", attrs={"name": True}):
            name = tag.get("name", "").strip()
            content = tag.get("content", "").strip()
            if not name or not content:
                continue
            if SENSITIVE_META_NAMES.search(name):
                self._add_finding(
                    source="sensitive_meta",
                    category="Leak",
                    name=name,
                    value=content[:200],
                    url=self._page,
                    severity="high",
                )
                self._log_finding("sensitive meta", f"{name} = {content[:60]}")

        for tag in soup.find_all("meta", property=True):
            prop = tag.get("property", "").strip()
            content = tag.get("content", "").strip()
            if not prop or not content:
                continue
            if SENSITIVE_META_NAMES.search(prop):
                self._add_finding(
                    source="sensitive_meta",
                    category="Leak",
                    name=prop,
                    value=content[:200],
                    url=self._page,
                    severity="high",
                )
                self._log_finding("sensitive meta", f"{prop} = {content[:60]}")

    def _extract_html_comments(self, html: str):
        sensitive_keywords = [
            "todo", "fixme", "hack", "bug", "debug",
            "password", "key", "secret", "token", "remove",
            "disabled", "old", "test", "temp", "staging",
        ]
        for match in COMMENT_PATTERN.finditer(html):
            comment = match.group(1).strip()
            if len(comment) < 4:
                continue
            lower = comment.lower()
            is_sensitive = any(kw in lower for kw in sensitive_keywords)
            severity = "medium" if is_sensitive else "info"
            self._add_finding(
                source="html_comment",
                category="Hidden Comments",
                name="html_comment",
                value=comment[:300],
                url=self._page,
                severity=severity,
            )
            label = "Hidden Comment [SENSITIVE]" if is_sensitive else "Hidden Comment"
            self._log_finding(label, comment[:100])

    def _extract_hidden_fields(self, html: str):
        for pattern in HIDDEN_FIELD_PATTERNS:
            for match in pattern.finditer(html):
                name, value = match.group(1), match.group(2)
                if not value:
                    continue
                self._add_finding(
                    source="hidden_input",
                    category="Leak",
                    name=name,
                    value=value[:200],
                    url=self._page,
                    severity="medium" if SENSITIVE_META_NAMES.search(name) else "info",
                )
                self._log_finding("hidden field", f"{name} = {value[:60]}")

    def _extract_js_leaks(self, soup: BeautifulSoup):
        scripts: list[str] = []
        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            content = script.get_text()
            if content:
                scripts.append(content)

        inline_js = "\n".join(scripts)
        for match in JS_VAR_PATTERN.finditer(inline_js):
            var_name, var_value = match.group(1), match.group(2)
            if INTERESTING_JS_KEYS.search(var_name):
                self._add_finding(
                    source="js_variable",
                    category="Leak",
                    name=var_name,
                    value=var_value[:200],
                    url=self._page,
                    severity="high",
                )
                self._log_finding("JS leak", f"{var_name} = {var_value[:60]}")

    def _analyze_csp(self, soup: BeautifulSoup):
        csp_tag = soup.find(
            "meta",
            attrs={"http-equiv": re.compile(r"content-security-policy", re.I)},
        )
        if not csp_tag:
            return

        csp_value = csp_tag.get("content", "").strip()
        if not csp_value:
            return

        unsafe_directives: list[str] = []
        if "'unsafe-inline'" in csp_value:
            unsafe_directives.append("unsafe-inline")
        if "'unsafe-eval'" in csp_value:
            unsafe_directives.append("unsafe-eval")
        if "data:" in csp_value:
            unsafe_directives.append("data: URI source")

        self._add_finding(
            source="csp",
            category="Security",
            name="content-security-policy",
            value=csp_value[:500],
            url=self._page,
            unsafe=unsafe_directives or None,
            severity="warn" if unsafe_directives else "info",
        )
        if unsafe_directives:
            self._log_finding("CSP weak", ", ".join(unsafe_directives))
        else:
            self._log_finding("CSP", "present")

    def _extract_charset(self, soup: BeautifulSoup):
        charset_tag = soup.find("meta", attrs={"charset": True})
        if charset_tag:
            charset = charset_tag.get("charset", "").strip()
            if charset:
                self._add_finding(
                    source="charset",
                    category="Standard",
                    name="charset",
                    value=charset,
                    url=self._page,
                )
                self._log_finding("charset", charset)
            return

        ct_tag = soup.find(
            "meta",
            attrs={"http-equiv": re.compile(r"content-type", re.I)},
        )
        if ct_tag:
            content = ct_tag.get("content", "")
            match = re.search(r"charset=([^\s;]+)", content, re.I)
            if match:
                self._add_finding(
                    source="charset",
                    category="Standard",
                    name="charset",
                    value=match.group(1),
                    url=self._page,
                )
                self._log_finding("charset (http-equiv)", match.group(1))

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        out: list[dict] = []
        for item in findings:
            key = f"{item.get('url')}:{item.get('source')}:{item.get('name')}:{item.get('value', '')}"
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    def _print_summary(self):
        if not self._findings:
            self.logger.warning("No meta findings discovered.")
            return

        for f in self._findings:
            src = f.get("source", "unknown")
            name = f.get("name", "")
            value = f.get("value", "")
            severity = f.get("severity", "info")

            if src in ("standard_meta", "open_graph", "twitter_card", "http_equiv", "charset"):
                self._log_finding(src, f"{name} = {value[:80]}")
            elif src == "open_graph_missing":
                self._log_finding("og missing", name)
            elif src == "link_rel":
                self._log_finding("link rel", f"{name} -> {value[:80]}")
            elif src == "sensitive_meta":
                self._log_finding(f"[{severity.upper()}] sensitive meta", f"{name} = {value[:60]}")
            elif src == "html_comment":
                label = f"[{severity.upper()}] Hidden Comment [SENSITIVE]" if severity == "medium" else "Hidden Comment"
                self._log_finding(label, value[:100])
            elif src == "hidden_input":
                self._log_finding(f"[{severity.upper()}] hidden field", f"{name} = {value[:60]}")
            elif src == "js_variable":
                self._log_finding(f"[{severity.upper()}] JS leak", f"{name} = {value[:60]}")
            elif src == "csp":
                unsafe = f.get("unsafe")
                if unsafe:
                    self._log_finding("[WARN] CSP", f"unsafe directives: {', '.join(unsafe)}")
                else:
                    self._log_finding("CSP", "policy present")

        by_source: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for f in self._findings:
            src = f.get("source", "unknown")
            cat = f.get("category", "Other")
            by_source[src] = by_source.get(src, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1

        self.logger.table(
            ["Source", "Count"],
            [[src, str(cnt)] for src, cnt in sorted(by_source.items())],
        )
        self.logger.table(
            ["Category", "Count"],
            [[cat, str(cnt)] for cat, cnt in sorted(by_category.items())],
        )