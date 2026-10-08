from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from modules.base import BaseJSModule, Finding


ABSOLUTE_URL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("fetch_absolute", re.compile(
        r"""fetch\s*\(\s*["'`](https?://[^\s"'`<>]{4,512})["'`]""",
        re.IGNORECASE,
    )),
    ("axios_absolute", re.compile(
        r"""axios\.(?:get|post|put|patch|delete|request|head|options)\s*\(\s*["'`](https?://[^\s"'`<>]{4,512})["'`]""",
        re.IGNORECASE,
    )),
    ("xhr_absolute", re.compile(
        r"""\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`](https?://[^\s"'`<>]{4,512})["'`]""",
        re.IGNORECASE,
    )),
    ("superagent_absolute", re.compile(
        r"""(?:request|superagent)\s*\.(?:get|post|put|patch|del|delete)\s*\(\s*["'`](https?://[^\s"'`<>]{4,512})["'`]""",
        re.IGNORECASE,
    )),
    ("got_absolute", re.compile(
        r"""(?:got|needle|ky)\s*(?:\.(?:get|post|put|patch|delete))?\s*\(\s*["'`](https?://[^\s"'`<>]{4,512})["'`]""",
        re.IGNORECASE,
    )),
    ("base_url_const", re.compile(
        r"""(?:BASE_URL|API_URL|API_BASE|ENDPOINT|HOST|BACKEND_URL|SERVER_URL|REMOTE_URL)\s*[=:]\s*["'`](https?://[^\s"'`<>]{4,512})["'`]""",
        re.IGNORECASE,
    )),
]

RELATIVE_PATH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("fetch_relative", re.compile(
        r"""fetch\s*\(\s*["'`](/[^\s"'`<>]{1,512})["'`]""",
        re.IGNORECASE,
    )),
    ("axios_relative", re.compile(
        r"""axios\.(?:get|post|put|patch|delete|request|head|options)\s*\(\s*["'`](/[^\s"'`<>]{1,512})["'`]""",
        re.IGNORECASE,
    )),
    ("xhr_relative", re.compile(
        r"""\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`](/[^\s"'`<>]{1,512})["'`]""",
        re.IGNORECASE,
    )),
    ("superagent_relative", re.compile(
        r"""(?:request|superagent)\s*\.(?:get|post|put|patch|del|delete)\s*\(\s*["'`](/[^\s"'`<>]{1,512})["'`]""",
        re.IGNORECASE,
    )),
    ("got_relative", re.compile(
        r"""(?:got|needle|ky)\s*(?:\.(?:get|post|put|patch|delete))?\s*\(\s*["'`](/[^\s"'`<>]{1,512})["'`]""",
        re.IGNORECASE,
    )),
    ("rest_route_string", re.compile(
        r"""["'`](/(?:api|v\d+|rest|graphql|gql|rpc|service|internal|public|private|backend|gateway|proxy|auth|oauth|webhook|ws|socket|admin|user|account|search|upload|download|data|feed|token|login|logout|register|refresh|verify|confirm|reset|password|profile|settings|config|status|health|ping|metrics|event|log|report|export|import|file|media|asset|resource|item|list|detail|create|update|delete|remove)[^\s"'`<>]{0,512})["'`]""",
        re.IGNORECASE,
    )),
    ("rest_route_template", re.compile(
        r"""`(/[^\s`\n]*?\$\{[^}]+\}[^\s`\n]*?)`""",
        re.IGNORECASE,
    )),
    ("path_join_api", re.compile(
        r"""(?:path\.join|url\.resolve|urljoin|resolve)\s*\([^)]{0,200}["'`](/[^"'`<>\s]{1,512})["'`]""",
        re.IGNORECASE,
    )),
]

DYNAMIC_URL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("fetch_template", re.compile(
        r"""fetch\s*\(\s*(`[^`\n]{1,512}`)""",
        re.IGNORECASE,
    )),
    ("axios_template", re.compile(
        r"""axios\.(?:get|post|put|patch|delete|request|head|options)\s*\(\s*(`[^`\n]{1,512}`)""",
        re.IGNORECASE,
    )),
    ("url_concat", re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*\w[\w$.]*\s*\+\s*["'`/][^\n]{0,256}""",
        re.IGNORECASE,
    )),
    ("url_constructor", re.compile(
        r"""new\s+URL\s*\(\s*["'`]([^"'`\s]{1,512})["'`]""",
        re.IGNORECASE,
    )),
]

GRAPHQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("graphql_query", re.compile(
        r"""(?:gql|graphql)\s*`\s*(query\s+\w+[^`]{0,2000}?)`""",
        re.IGNORECASE | re.DOTALL,
    )),
    ("graphql_mutation", re.compile(
        r"""(?:gql|graphql)\s*`\s*(mutation\s+\w+[^`]{0,2000}?)`""",
        re.IGNORECASE | re.DOTALL,
    )),
    ("graphql_subscription", re.compile(
        r"""(?:gql|graphql)\s*`\s*(subscription\s+\w+[^`]{0,2000}?)`""",
        re.IGNORECASE | re.DOTALL,
    )),
    ("graphql_operation_name", re.compile(
        r"""operationName\s*[:=]\s*["'`](\w+)["'`]""",
        re.IGNORECASE,
    )),
    ("graphql_endpoint", re.compile(
        r"""["'`]([^"'`\s]*graphql[^"'`\s]*)["'`]""",
        re.IGNORECASE,
    )),
]

WS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("websocket_url", re.compile(
        r"""["'`](wss?://[^\s"'`<>]+)["'`]""",
        re.IGNORECASE,
    )),
    ("websocket_constructor", re.compile(
        r"""new\s+WebSocket\s*\(\s*["'`]([^"'`\s]+)["'`]""",
        re.IGNORECASE,
    )),
    ("websocket_constructor_template", re.compile(
        r"""new\s+WebSocket\s*\(\s*(`[^`\n]+`)""",
        re.IGNORECASE,
    )),
    ("socket_io_connect", re.compile(
        r"""(?:^|[^.\w])(?:io|socket(?:io)?)\s*\.connect\s*\(\s*["'`]([^"'`\s]+)["'`]""",
        re.IGNORECASE,
    )),
    ("socket_io_init", re.compile(
        r"""(?:^|[^.\w])io\s*\(\s*["'`]((?:wss?|https?)://[^"'`\s]+)["'`]""",
        re.IGNORECASE,
    )),
    ("ws_socket_event", re.compile(
        r"""(?:socket|ws|sock|conn)\s*\.(?:on|emit)\s*\(\s*["'`]([^"'`\s]{2,64})["'`]""",
        re.IGNORECASE,
    )),
]

DOM_EVENT_NOISE: frozenset[str] = frozenset([
    "click", "mousedown", "mouseup", "mousemove", "mouseenter", "mouseleave",
    "mouseover", "mouseout", "keydown", "keyup", "keypress", "focus", "blur",
    "change", "input", "submit", "reset", "resize", "scroll", "load", "unload",
    "beforeunload", "DOMContentLoaded", "touchstart", "touchmove", "touchend",
    "touchcancel", "pointerdown", "pointermove", "pointerup", "pointercancel",
    "dragstart", "drag", "dragend", "dragenter", "dragleave", "dragover", "drop",
    "contextmenu", "wheel", "select", "copy", "cut", "paste", "focusin", "focusout",
    "ready", "orientationchange", "transitionend", "animationend", "error",
    "abort", "canplay", "canplaythrough", "ended", "pause", "play", "playing",
    "progress", "seeked", "seeking", "stalled", "suspend", "timeupdate",
    "volumechange", "waiting", "fullscreenchange", "fullscreenerror",
    "mousedown.", "mouseup.", "mousemove.", "click.", "keydown.",
])

ROUTE_NOISE: set[str] = {
    "/", "/index.html", "/favicon.ico", "/robots.txt",
    "/static/", "/assets/", "/images/", "/fonts/", "/css/", "/js/",
    "/index", "/home", "/404", "/500",
}

NOISE_EXTENSIONS: frozenset[str] = frozenset([
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".css", ".map", ".txt", ".pdf",
])

NOISE_DOMAINS: frozenset[str] = frozenset([
    "www.w3.org", "schemas.xmlsoap.org", "purl.org",
    "creativecommons.org", "example.com",
    "www.googletagmanager.com", "googletagmanager.com",
    "www.google-analytics.com", "google-analytics.com",
    "analytics.google.com", "stats.g.doubleclick.net",
    "doubleclick.net", "google.com", "googleapis.com",
    "gstatic.com", "facebook.com", "facebook.net",
    "connect.facebook.net", "twitter.com", "linkedin.com",
    "mc.yandex.ru", "mc.yandex.com",
])

NOISE_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".google.com", ".googleapis.com", ".gstatic.com",
    ".doubleclick.net", ".googletagmanager.com",
    ".facebook.com", ".facebook.net", ".twitter.com",
    ".linkedin.com", ".yandex.ru", ".yandex.com",
    ".amazonaws.com", ".cloudfront.net",
)

HTTP_METHOD_RE: re.Pattern = re.compile(
    r"""\b(get|post|put|patch|delete|head|options)\b""", re.IGNORECASE
)


class EndpointsModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []
        self._target_host = self._extract_target_host(filename)
        self._run_absolute_scan(content)
        self._run_relative_scan(content)
        self._run_dynamic_scan(content)
        self._run_graphql_scan(content)
        self._run_websocket_scan(content)
        return self.findings

    def extract_absolute_urls(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for url_type, pattern in ABSOLUTE_URL_PATTERNS:
            for match in pattern.finditer(content):
                url = match.group(1).strip()

                if not self._is_valid_url(url):
                    continue
                if self._is_noise_url(url):
                    continue
                if self._target_host and not self._is_same_host(url, self._target_host):
                    continue

                fingerprint = f"abs:{url}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = url_type,
                    value      = url[:512],
                    severity   = self.SEVERITY_INFO,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "url_type":    "absolute",
                        "http_method": self._infer_http_method(ctx),
                        "host":        urlparse(url).netloc,
                        "path":        urlparse(url).path,
                    },
                ))

        return findings

    def extract_relative_routes(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for route_type, pattern in RELATIVE_PATH_PATTERNS:
            for match in pattern.finditer(content):
                route = match.group(1).strip()

                if route in ROUTE_NOISE:
                    continue
                if self._is_noise_path(route):
                    continue
                if not self._has_meaningful_path(route):
                    continue

                fingerprint = f"rel:{route}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = route_type,
                    value      = route[:512],
                    severity   = self.SEVERITY_INFO,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "url_type":    "relative",
                        "http_method": self._infer_http_method(ctx),
                        "path":        route,
                    },
                ))

        return findings

    def extract_dynamic_urls(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for dyn_type, pattern in DYNAMIC_URL_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0).strip()
                fingerprint = f"dyn:{dyn_type}:{value[:64]}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = dyn_type,
                    value      = value[:512],
                    severity   = self.SEVERITY_INFO,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_MEDIUM,
                    meta       = {
                        "url_type":    "dynamic",
                        "http_method": self._infer_http_method(ctx),
                    },
                ))

        return findings

    def find_graphql_ops(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for op_type, pattern in GRAPHQL_PATTERNS:
            for match in pattern.finditer(content):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()
                value = value[:2000]
                fingerprint = f"{op_type}:{value[:64]}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line     = self._get_line_number(content, match.start())
                ctx      = self._get_context(content, match.start())
                op_name  = self._extract_graphql_op_name(value)
                severity = (
                    self.SEVERITY_MEDIUM
                    if op_type == "graphql_mutation"
                    else self.SEVERITY_INFO
                )

                findings.append(self._finding(
                    type       = op_type,
                    value      = value,
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "operation_name": op_name,
                        "operation_type": op_type.replace("graphql_", ""),
                    },
                ))

        return findings

    def track_websockets(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for ws_type, pattern in WS_PATTERNS:
            for match in pattern.finditer(content):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()

                if ws_type == "ws_socket_event" and self._is_dom_event(value):
                    continue
                if ws_type == "socket_io_connect" and not self._looks_like_url_or_path(value):
                    continue

                fingerprint = f"{ws_type}:{value[:64]}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line     = self._get_line_number(content, match.start())
                ctx      = self._get_context(content, match.start())
                severity = (
                    self.SEVERITY_MEDIUM
                    if ws_type in ("websocket_url", "websocket_constructor", "socket_io_connect", "socket_io_init")
                    else self.SEVERITY_INFO
                )

                findings.append(self._finding(
                    type       = ws_type,
                    value      = value[:512],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {"ws_pattern": ws_type},
                ))

        return findings

    def _run_absolute_scan(self, content: str) -> None:
        self.findings.extend(self.extract_absolute_urls(content))

    def _run_relative_scan(self, content: str) -> None:
        existing: set[str] = {f.value for f in self.findings}
        for f in self.extract_relative_routes(content):
            if f.value not in existing:
                self.findings.append(f)

    def _run_dynamic_scan(self, content: str) -> None:
        self.findings.extend(self.extract_dynamic_urls(content))

    def _run_graphql_scan(self, content: str) -> None:
        self.findings.extend(self.find_graphql_ops(content))

    def _run_websocket_scan(self, content: str) -> None:
        self.findings.extend(self.track_websockets(content))

    @staticmethod
    def _extract_target_host(filename: str) -> str:
        try:
            p = urlparse(filename if filename.startswith("http") else "")
            return p.netloc.lower()
        except Exception:
            return ""

    @staticmethod
    def _is_same_host(url: str, target_host: str) -> bool:
        try:
            host = urlparse(url).netloc.lower()
            base = target_host.lstrip("www.")
            return host == target_host or host == f"www.{base}" or host.endswith(f".{base}")
        except Exception:
            return False

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        try:
            p = urlparse(url)
            return bool(p.scheme in ("http", "https") and p.netloc)
        except Exception:
            return False

    @staticmethod
    def _is_noise_url(url: str) -> bool:
        try:
            p    = urlparse(url)
            host = p.netloc.lower()
            if host in NOISE_DOMAINS:
                return True
            if any(host.endswith(s) for s in NOISE_DOMAIN_SUFFIXES):
                return True
            path = p.path.lower()
            if any(path.endswith(ext) for ext in NOISE_EXTENSIONS):
                return True
            if re.search(r"\.(min|bundle|chunk)\.(js|css)$", path, re.IGNORECASE):
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _is_noise_path(path: str) -> bool:
        lower = path.lower()
        if any(lower.endswith(ext) for ext in NOISE_EXTENSIONS):
            return True
        if re.match(r"^/[a-f0-9]{8,}$", path):
            return True
        return False

    @staticmethod
    def _has_meaningful_path(path: str) -> bool:
        parts = [p for p in path.strip("/").split("/") if p]
        return len(parts) >= 1

    @staticmethod
    def _infer_http_method(context: str) -> str:
        m = HTTP_METHOD_RE.search(context)
        return m.group(1).upper() if m else "UNKNOWN"

    @staticmethod
    def _extract_graphql_op_name(body: str) -> str:
        m = re.match(
            r"""(?:query|mutation|subscription)\s+(\w+)""",
            body.strip(), re.IGNORECASE,
        )
        return m.group(1) if m else "anonymous"

    @staticmethod
    def _is_dom_event(value: str) -> bool:
        base = value.split(".")[0].lower()
        return base in DOM_EVENT_NOISE or value.lower() in DOM_EVENT_NOISE

    @staticmethod
    def _looks_like_url_or_path(value: str) -> bool:
        return bool(re.match(r"^(?:https?://|wss?://|/)", value))