from __future__ import annotations

import re
from typing import Any

from modules.base import BaseJSModule, Finding


REACT_ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jsx_route_element",    re.compile(r"""<Route\s[^>]*path\s*=\s*["'`{]([^"'`}\s>]+)["'`}][^>]*>""", re.IGNORECASE)),
    ("jsx_route_self_close", re.compile(r"""<Route\s[^/]*path\s*=\s*["'`{]([^"'`}\s>]+)["'`}][^/]*/\s*>""", re.IGNORECASE)),
    ("path_prop_object",     re.compile(r"""path\s*:\s*["'`]([/][^"'`\s,}]+)["'`]""")),
    ("createBrowserRouter",  re.compile(r"""path\s*:\s*["'`]([^"'`\s]+)["'`]\s*,\s*(?:element|component)""")),
    ("useRoutes_path",       re.compile(r"""\{\s*path\s*:\s*["'`]([^"'`\s]+)["'`]""")),
    ("navigate_call",        re.compile(r"""navigate\s*\(\s*["'`]([^"'`\s]+)["'`]""")),
    ("history_push",         re.compile(r"""history\.push\s*\(\s*["'`]([^"'`\s]+)["'`]""")),
    ("redirect_to",          re.compile(r"""<Redirect\s[^>]*to\s*=\s*["'`{]([^"'`}\s>]+)["'`}]""", re.IGNORECASE)),
]

REACT_COMPONENT_PATTERNS: list[re.Pattern] = [
    re.compile(r"""component\s*=\s*\{([A-Za-z][A-Za-z0-9_]*)\}"""),
    re.compile(r"""element\s*=\s*\{<([A-Za-z][A-Za-z0-9_]*)"""),
    re.compile(r"""element\s*:\s*<([A-Za-z][A-Za-z0-9_]*)"""),
]

VUE_ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("route_object_path",    re.compile(r"""\{\s*(?:[^}]*,\s*)?path\s*:\s*["'`]([^"'`]+)["'`]""")),
    ("route_children_path",  re.compile(r"""children\s*:\s*\[[^\]]*path\s*:\s*["'`]([^"'`]+)["'`]""")),
    ("router_push",          re.compile(r"""(?:\$router|router)\.push\s*\(\s*["'`]([^"'`\s]+)["'`]""")),
    ("router_replace",       re.compile(r"""(?:\$router|router)\.replace\s*\(\s*["'`]([^"'`\s]+)["'`]""")),
    ("router_push_name",     re.compile(r"""(?:\$router|router)\.push\s*\(\s*\{\s*name\s*:\s*["'`]([^"'`]+)["'`]""")),
    ("router_link_to",       re.compile(r"""<router-link\s[^>]*to\s*=\s*["'`]([^"'`\s>]+)["'`]""", re.IGNORECASE)),
]

VUE_COMPONENT_PATTERNS: list[re.Pattern] = [
    re.compile(r"""component\s*:\s*["'`]([A-Za-z][A-Za-z0-9_-]*)["'`]"""),
    re.compile(r"""component\s*:\s*([A-Za-z][A-Za-z0-9_]*)(?:\s*[,}])"""),
    re.compile(r"""import\s*\(\s*["'`][^"'`]+["'`]\s*\)"""),
]

AUTH_GUARD_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("requiresAuth_meta",    "high",     re.compile(r"""meta\s*:\s*\{[^}]*requiresAuth\s*:\s*true""")),
    ("auth_meta_flag",       "high",     re.compile(r"""meta\s*:\s*\{[^}]*auth\s*:\s*true""")),
    ("beforeEnter_guard",    "medium",   re.compile(r"""beforeEnter\s*:\s*(?:router)?[Gg]uard|authGuard|requireAuth""", re.IGNORECASE)),
    ("PrivateRoute",         "high",     re.compile(r"""<(?:Private|Protected|Auth(?:orized)?|Guarded)Route""")),
    ("role_check_inline",    "high",     re.compile(r"""roles?\s*:\s*\[["'`][A-Za-z]+["'`]""")),
    ("admin_path",           "medium",   re.compile(r"""path\s*[=:]\s*["'`{]?/?(?:admin|dashboard|manage|control|backoffice)[^"'`}\s>]*["'`}]?""", re.IGNORECASE)),
    ("wildcard_catch",       "low",      re.compile(r"""path\s*[=:]\s*["'`]\*["'`]""")),
    ("index_redirect",       "low",      re.compile(r"""index\s*:\s*true""")),
]

MISSING_AUTH_SIGNALS: list[tuple[str, re.Pattern]] = [
    ("no_guard_on_sensitive", re.compile(r"""path\s*[=:]\s*["'`{]?/?(?:account|profile|settings|billing|payment)[^"'`}\s>]*["'`}]?""", re.IGNORECASE)),
    ("lazy_load_no_guard",    re.compile(r"""component\s*:\s*\(\s*\)\s*=>\s*import\s*\((?![^)]*guard)""")),
]

SENSITIVE_PATH_KEYWORDS: frozenset[str] = frozenset([
    "admin", "dashboard", "manage", "control", "backoffice",
    "account", "profile", "settings", "billing", "payment",
    "api", "internal", "debug", "dev", "test",
])


class RoutesModule(BaseJSModule):

    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        self.findings = []

        react_routes = self.parse_react_router(content)
        vue_routes   = self.parse_vue_router(content)
        all_routes   = react_routes + vue_routes

        self.findings.extend(all_routes)
        self.findings.extend(self.identify_auth_gates(content, all_routes))

        return self.findings

    def parse_react_router(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for route_type, pattern in REACT_ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                path        = match.group(1).strip()
                fingerprint = f"react:{path}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line      = self._get_line_number(content, match.start())
                ctx       = self._get_context(content, match.start())
                component = self._extract_component(content, match.start(), REACT_COMPONENT_PATTERNS)
                is_sensitive = self._is_sensitive_path(path)

                findings.append(self._finding(
                    type       = f"react_route_{route_type}",
                    value      = path,
                    severity   = self.SEVERITY_INFO,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "framework":    "react",
                        "path":         path,
                        "component":    component,
                        "is_sensitive": is_sensitive,
                        "route_type":   route_type,
                    },
                ))

        return findings

    def parse_vue_router(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for route_type, pattern in VUE_ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                path        = match.group(1).strip()
                fingerprint = f"vue:{path}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line      = self._get_line_number(content, match.start())
                ctx       = self._get_context(content, match.start())
                component = self._extract_component(content, match.start(), VUE_COMPONENT_PATTERNS)
                is_sensitive = self._is_sensitive_path(path)

                findings.append(self._finding(
                    type       = f"vue_route_{route_type}",
                    value      = path,
                    severity   = self.SEVERITY_INFO,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "framework":    "vue",
                        "path":         path,
                        "component":    component,
                        "is_sensitive": is_sensitive,
                        "route_type":   route_type,
                    },
                ))

        return findings

    def identify_auth_gates(self, content: str, discovered_routes: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for gate_type, severity, pattern in AUTH_GUARD_PATTERNS:
            for match in pattern.finditer(content):
                value       = match.group(0).strip()
                fingerprint = f"gate:{gate_type}:{self._get_line_number(content, match.start())}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                line = self._get_line_number(content, match.start())
                ctx  = self._get_context(content, match.start())

                findings.append(self._finding(
                    type       = f"auth_gate_{gate_type}",
                    value      = value[:256],
                    severity   = severity,
                    context    = ctx,
                    line       = line,
                    confidence = self.CONFIDENCE_HIGH,
                    meta       = {
                        "gate_type": gate_type,
                        "guarded":   True,
                    },
                ))

        guarded_lines   = {f.line for f in findings}
        sensitive_routes = [
            r for r in discovered_routes
            if r.meta.get("is_sensitive")
        ]

        for route in sensitive_routes:
            if not self._has_nearby_guard(content, route.line, guarded_lines):
                findings.append(self._finding(
                    type       = "unguarded_sensitive_route",
                    value      = route.meta.get("path", ""),
                    severity   = "high",
                    context    = route.context,
                    line       = route.line,
                    confidence = self.CONFIDENCE_MEDIUM,
                    meta       = {
                        "framework":   route.meta.get("framework"),
                        "path":        route.meta.get("path"),
                        "component":   route.meta.get("component"),
                        "gate_type":   None,
                        "guarded":     False,
                    },
                ))

        return findings

    @staticmethod
    def _extract_component(content: str, pos: int, patterns: list[re.Pattern], window: int = 200) -> str | None:
        snippet = content[pos: pos + window]
        for pattern in patterns:
            m = pattern.search(snippet)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _is_sensitive_path(path: str) -> bool:
        normalized = path.lower().strip("/")
        return any(kw in normalized for kw in SENSITIVE_PATH_KEYWORDS)

    @staticmethod
    def _has_nearby_guard(content: str, route_line: int, guarded_lines: set[int], proximity: int = 10) -> bool:
        return any(abs(route_line - gl) <= proximity for gl in guarded_lines)