from typing import Dict, List, Optional, Tuple, Any
import re

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


SERVER_SOFTWARE_PATTERNS = {
    "nginx": re.compile(r"nginx[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "apache": re.compile(r"Apache[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "iis": re.compile(r"Microsoft-IIS[/\s](\d+\.\d+)", re.IGNORECASE),
    "openresty": re.compile(r"openresty[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "cloudflare": re.compile(r"cloudflare", re.IGNORECASE),
    "caddy": re.compile(r"Caddy[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "lighttpd": re.compile(r"lighttpd[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "jetty": re.compile(r"Jetty[/\s]\(?(\d+\.\d+\.\d+)", re.IGNORECASE),
    "tomcat": re.compile(r"Apache-Coyote[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "gunicorn": re.compile(r"gunicorn[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "werkzeug": re.compile(r"Werkzeug[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "nodejs": re.compile(r"Node\.js[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "express": re.compile(r"express", re.IGNORECASE),
    "python": re.compile(r"Python[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
}

POWERED_BY_PATTERNS = {
    "asp.net": re.compile(r"ASP\.NET", re.IGNORECASE),
    "php": re.compile(r"PHP[/\s](\d+\.\d+\.\d+)", re.IGNORECASE),
    "django": re.compile(r"Django", re.IGNORECASE),
    "flask": re.compile(r"Flask", re.IGNORECASE),
    "rails": re.compile(r"Rails", re.IGNORECASE),
    "spring": re.compile(r"SpringBoot|Spring[\s-]?Boot", re.IGNORECASE),
    "java": re.compile(r"Java[/\s](\d+\.\d+)", re.IGNORECASE),
    "aspnetcore": re.compile(r"ASP\.NET Core", re.IGNORECASE),
    "passenger": re.compile(r"Passenger", re.IGNORECASE),
    "nginx": re.compile(r"nginx", re.IGNORECASE),
}

DEBUG_HEADERS = [
    "X-Debug-Token",
    "X-Debug-Token-Link",
    "X-Debug-Exception",
    "X-Debug-Exception-Message",
    "X-Debug-Exception-Stack",
    "X-Debug-Error",
    "X-Debug-Path",
    "X-Debug-Info",
    "X-Dump",
    "X-Dump-Detail",
    "X-Dump-Data",
    "X-Debug",
    "X-Profiler",
    "X-Profile",
    "X-Symfony-Debug",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-Drupal-Route",
    "X-Backend",
    "X-Development-Mode",
    "X-Staging",
    "X-Environment",
    "X-Runtime",
    "X-Rack-Cache",
    "X-Rack-Session",
    "X-Rack-Runtime",
    "X-MiniProfiler-Ids",
    "X-Powered-By-Debug",
    "X-Page-Generation-Time",
    "X-Generated-By",
    "X-Server-Info",
    "X-Request-ID-Prefix",
    "X-Error-URL",
    "X-Error-Code",
    "X-SQL-Query",
    "X-Database",
    "X-Trace",
    "X-Trace-URL",
    "X-Cache-Debug",
]

FRAMEWORK_DETECTION_HEADERS = {
    "X-Generator": ["Drupal", "WordPress", "Joomla", "Ghost", "Hugo", "Jekyll", "Wix", "Squarespace"],
    "X-Pingback": ["WordPress"],
    "X-Drupal-Cache": ["Drupal"],
    "X-Drupal-Dynamic-Cache": ["Drupal"],
    "X-WordPress-Admin-Ajax": ["WordPress"],
    "X-Wix-Request-Id": ["Wix"],
}

CACHE_PROXY_FINGERPRINTS = {
    "Via": re.compile(r"[\d.]+?\s+(\S+)"),
    "X-Cache": re.compile(r"(HIT|MISS|BYPASS|STALE|REVALIDATED|UPDATING|EXPIRED)"),
    "X-Cache-Lookup": re.compile(r"(HIT|MISS|BYPASS)"),
    "X-Cache-Status": re.compile(r"(HIT|MISS|BYPASS|DYNAMIC|STALE)"),
    "X-Served-By": re.compile(r".+"),
    "X-Cache-Hits": re.compile(r"\d+"),
    "X-Backend-Server": re.compile(r".+"),
    "X-Origin-Server": re.compile(r".+"),
    "CF-Cache-Status": re.compile(r"(HIT|MISS|DYNAMIC|BYPASS|EXPIRED|STALE)"),
    "CF-Ray": re.compile(r".+"),
    "CF-Request-ID": re.compile(r".+"),
    "Akamai-Request-ID": re.compile(r".+"),
    "X-Akamai-Transformed": re.compile(r".+"),
    "X-CDN": re.compile(r".+"),
    "X-Cache-Provider": re.compile(r".+"),
    "X-Varnish": re.compile(r"\d+(?:\s+\d+)*"),
    "Age": re.compile(r"\d+"),
}

COOKIE_SENSITIVE_PATTERNS = [
    re.compile(r"PHPSESSID", re.IGNORECASE),
    re.compile(r"ASP\.NET_SessionId", re.IGNORECASE),
    re.compile(r"JSESSIONID", re.IGNORECASE),
    re.compile(r"Session", re.IGNORECASE),
    re.compile(r"sessionid", re.IGNORECASE),
    re.compile(r"connect\.sid", re.IGNORECASE),
    re.compile(r"laravel_session", re.IGNORECASE),
    re.compile(r"ci_session", re.IGNORECASE),
    re.compile(r"symfony", re.IGNORECASE),
    re.compile(r"PHPREDIS_SESSION", re.IGNORECASE),
    re.compile(r"TOKEN", re.IGNORECASE),
    re.compile(r"csrf", re.IGNORECASE),
    re.compile(r"xsrf", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"jwt", re.IGNORECASE),
    re.compile(r"api_key", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
]


class ServerInfoAnalysis:
    def __init__(self):
        self.server_header_present: bool = False
        self.raw_server: Optional[str] = None
        self.identified_software: Optional[str] = None
        self.version_leaked: bool = False
        self.version_string: Optional[str] = None
        self.sensitive_info_leaked: bool = False
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_header_present": self.server_header_present,
            "raw_server": self.raw_server,
            "identified_software": self.identified_software,
            "version_leaked": self.version_leaked,
            "version_string": self.version_string,
            "sensitive_info_leaked": self.sensitive_info_leaked,
            "issues": self.issues,
        }


class PoweredByAnalysis:
    def __init__(self):
        self.powered_by_present: bool = False
        self.raw_x_powered_by: Optional[str] = None
        self.raw_x_aspnet_version: Optional[str] = None
        self.identified_technologies: List[str] = []
        self.version_leaked: bool = False
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "powered_by_present": self.powered_by_present,
            "raw_x_powered_by": self.raw_x_powered_by,
            "raw_x_aspnet_version": self.raw_x_aspnet_version,
            "identified_technologies": self.identified_technologies,
            "version_leaked": self.version_leaked,
            "issues": self.issues,
        }


class BackendFingerprintAnalysis:
    def __init__(self):
        self.fingerprint_headers: Dict[str, str] = {}
        self.identified_technologies: List[str] = []
        self.cache_proxies: List[str] = []
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_headers": self.fingerprint_headers,
            "identified_technologies": self.identified_technologies,
            "cache_proxies": self.cache_proxies,
            "issues": self.issues,
        }


class DebugHeaderAnalysis:
    def __init__(self):
        self.debug_headers_found: Dict[str, str] = {}
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "debug_headers_found": self.debug_headers_found,
            "issues": self.issues,
        }


class CookieLeakAnalysis:
    def __init__(self):
        self.cookies_found: Dict[str, str] = {}
        self.sensitive_cookies: List[str] = []
        self.missing_secure_flag: List[str] = []
        self.missing_httponly_flag: List[str] = []
        self.missing_samesite_flag: List[str] = []
        self.issues: List[Tuple[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cookies_found": self.cookies_found,
            "sensitive_cookies": self.sensitive_cookies,
            "missing_secure_flag": self.missing_secure_flag,
            "missing_httponly_flag": self.missing_httponly_flag,
            "missing_samesite_flag": self.missing_samesite_flag,
            "issues": self.issues,
        }


class InfoLeakModule(BaseHeaderModule):
    name = "Information Leak Analyzer"
    description = "Identifies information disclosure vulnerabilities through HTTP headers — server versions, technology stack, debug endpoints, and cookie misconfigurations."

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        headers = response.headers

        server_info = self.check_server_header(headers)
        self._emit_server_info(server_info, result)

        powered_by = self.check_x_powered_by(headers)
        self._emit_powered_by(powered_by, result)

        backend_fingerprints = self.check_backend_fingerprints(headers)
        self._emit_backend_fingerprints(backend_fingerprints, result)

        debug_headers = self.check_debug_headers(headers)
        self._emit_debug_headers(debug_headers, result)

        cookies = self.check_cookie_leaks(headers)
        self._emit_cookie_leaks(cookies, result)

        result.metadata["server_info"] = server_info.to_dict()
        result.metadata["powered_by"] = powered_by.to_dict()
        result.metadata["backend_fingerprints"] = backend_fingerprints.to_dict()
        result.metadata["debug_headers"] = debug_headers.to_dict()
        result.metadata["cookies"] = cookies.to_dict()

        return result

    def check_server_header(self, headers: Dict[str, str]) -> ServerInfoAnalysis:
        analysis = ServerInfoAnalysis()
        server_value = self._get_header(headers, "Server")

        if server_value is None:
            analysis.server_header_present = False
            analysis.issues.append(("INFO", "Server header is not present — good for minimizing fingerprinting"))
            return analysis

        analysis.server_header_present = True
        analysis.raw_server = server_value
        os_indicators = [
            r"Ubuntu", r"Debian", r"CentOS", r"Red Hat", r"Fedora",
            r"Windows", r"Win32", r"Win64", r"FreeBSD", r"OpenBSD",
            r"Darwin", r"macOS", r"Linux",
        ]
        for pattern in os_indicators:
            if re.search(pattern, server_value, re.IGNORECASE):
                analysis.sensitive_info_leaked = True
                analysis.issues.append(("LOW", f"Server header leaks OS information: '{pattern}'"))
                break

        for software_name, pattern in SERVER_SOFTWARE_PATTERNS.items():
            match = pattern.search(server_value)
            if match:
                analysis.identified_software = software_name
                version = match.group(1) if match.lastindex and match.group(1) else None
                if version:
                    analysis.version_leaked = True
                    analysis.version_string = version
                    analysis.issues.append(
                        ("MEDIUM", f"Server header exposes software and version: {software_name}/{version}")
                    )
                else:
                    analysis.issues.append(
                        ("MEDIUM", f"Server header identifies software: {software_name}")
                    )
                break

        if not analysis.identified_software and server_value.strip():
            analysis.issues.append(("MEDIUM", f"Server header present and may aid fingerprinting: '{server_value[:100]}'"))

        if analysis.version_leaked:
            analysis.issues.append(("MEDIUM", f"Exact version disclosure in Server header aids targeted exploit search ({analysis.identified_software} {analysis.version_string})"))

        return analysis

    def check_x_powered_by(self, headers: Dict[str, str]) -> PoweredByAnalysis:
        analysis = PoweredByAnalysis()
        xpb_value = self._get_header(headers, "X-Powered-By")
        xaspnet_value = self._get_header(headers, "X-AspNet-Version")

        if xpb_value is None and xaspnet_value is None:
            analysis.powered_by_present = False
            return analysis

        analysis.powered_by_present = True

        if xpb_value:
            analysis.raw_x_powered_by = xpb_value
            for tech, pattern in POWERED_BY_PATTERNS.items():
                match = pattern.search(xpb_value)
                if match:
                    analysis.identified_technologies.append(tech)
                    version = match.group(1) if match.lastindex and match.group(1) else None
                    if version:
                        analysis.version_leaked = True
                        analysis.issues.append(
                            ("MEDIUM", f"X-Powered-By exposes version: {tech}/{version} (full value: '{xpb_value}')")
                        )
                    else:
                        analysis.issues.append(
                            ("LOW", f"X-Powered-By identifies technology stack: {tech} (full value: '{xpb_value}')")
                        )
            if not analysis.identified_technologies:
                analysis.issues.append(
                    ("LOW", f"X-Powered-By header present: '{xpb_value}'")
                )

        if xaspnet_value:
            analysis.raw_x_aspnet_version = xaspnet_value
            analysis.identified_technologies.append("ASP.NET")
            analysis.version_leaked = True
            analysis.issues.append(
                ("MEDIUM", f"X-AspNet-Version exposes .NET framework version: '{xaspnet_value}'")
            )

        return analysis

    def check_backend_fingerprints(self, headers: Dict[str, str]) -> BackendFingerprintAnalysis:
        analysis = BackendFingerprintAnalysis()

        for header_name, known_technologies in FRAMEWORK_DETECTION_HEADERS.items():
            value = self._get_header(headers, header_name)
            if value is not None:
                analysis.fingerprint_headers[header_name] = value
                for tech in known_technologies:
                    if tech.lower() in value.lower() or tech.lower() in header_name.lower():
                        analysis.identified_technologies.append(tech)
                        analysis.issues.append(
                            ("LOW", f"'{header_name}: {value}' reveals backend technology: {tech}")
                        )
                        break
                else:
                    analysis.issues.append(
                        ("INFO", f"'{header_name}: {value}' may reveal backend technology")
                    )

        for header_name, pattern in CACHE_PROXY_FINGERPRINTS.items():
            value = self._get_header(headers, header_name)
            if value is not None:
                analysis.fingerprint_headers[header_name] = value
                analysis.cache_proxies.append(f"{header_name}")
                analysis.issues.append(
                    ("INFO", f"'{header_name}: {value[:80]}' reveals proxy or CDN layer")
                )

        return analysis

    def check_debug_headers(self, headers: Dict[str, str]) -> DebugHeaderAnalysis:
        analysis = DebugHeaderAnalysis()

        for debug_header in DEBUG_HEADERS:
            value = self._get_header(headers, debug_header)
            if value is not None:
                analysis.debug_headers_found[debug_header] = value
                severity = "HIGH"
                if any(x in debug_header.lower() for x in ["cache", "id", "prefix"]):
                    severity = "LOW"
                elif any(x in debug_header.lower() for x in ["runtime", "time", "generation"]):
                    severity = "MEDIUM"
                analysis.issues.append(
                    (severity, f"Debug header '{debug_header}' exposed: '{value[:120]}'")
                )

        return analysis

    def check_cookie_leaks(self, headers: Dict[str, str]) -> CookieLeakAnalysis:
        analysis = CookieLeakAnalysis()
        set_cookie_value = self._get_header(headers, "Set-Cookie")

        if set_cookie_value is None:
            return analysis

        cookie_pairs = re.split(r",(?=\s*\w+\s*=)", set_cookie_value)
        for cookie_str in cookie_pairs:
            cookie_str = cookie_str.strip()
            if not cookie_str or "=" not in cookie_str:
                continue
            name_part = cookie_str.split("=", 1)[0].strip()
            for pattern in COOKIE_SENSITIVE_PATTERNS:
                if pattern.search(name_part):
                    analysis.sensitive_cookies.append(name_part)
                    analysis.cookies_found[name_part] = cookie_str[:150]

                    sec = r"\bsecure\b"
                    hto = r"\bhttponly\b"
                    samesite = r"\bsamesite=(lax|strict|none)\b"

                    if not re.search(sec, cookie_str, re.IGNORECASE):
                        analysis.missing_secure_flag.append(name_part)
                    if not re.search(hto, cookie_str, re.IGNORECASE):
                        analysis.missing_httponly_flag.append(name_part)
                    if not re.search(samesite, cookie_str, re.IGNORECASE):
                        analysis.missing_samesite_flag.append(name_part)
                    break

        for cookie in analysis.sensitive_cookies:
            if cookie in analysis.missing_secure_flag:
                analysis.issues.append(
                    ("MEDIUM", f"Cookie '{cookie}' lacks 'Secure' flag — transmitted over HTTP")
                )
            if cookie in analysis.missing_httponly_flag:
                analysis.issues.append(
                    ("MEDIUM", f"Cookie '{cookie}' lacks 'HttpOnly' flag — accessible via JavaScript")
                )
            if cookie in analysis.missing_samesite_flag:
                analysis.issues.append(
                    ("LOW", f"Cookie '{cookie}' lacks 'SameSite' attribute — vulnerable to CSRF")
                )

        if analysis.sensitive_cookies:
            analysis.issues.append(
                ("INFO", f"Session/cookie name based fingerprinting possible: {', '.join(analysis.sensitive_cookies)}")
            )

        return analysis

    def _emit_server_info(self, server_info: ServerInfoAnalysis, result: ModuleResult):
        if not server_info.server_header_present:
            result.add_finding("OK", "Server Header", "Server header is absent — minimal fingerprinting surface")
            return
        for sev, detail in server_info.issues:
            result.add_finding(sev, "Server Header", detail)

    def _emit_powered_by(self, powered_by: PoweredByAnalysis, result: ModuleResult):
        if not powered_by.powered_by_present:
            result.add_finding("OK", "X-Powered-By / X-AspNet-Version", "No technology disclosure headers present")
            return
        for sev, detail in powered_by.issues:
            result.add_finding(sev, "X-Powered-By / X-AspNet-Version", detail)

    def _emit_backend_fingerprints(self, fingerprints: BackendFingerprintAnalysis, result: ModuleResult):
        if not fingerprints.fingerprint_headers:
            result.add_finding("OK", "Backend Fingerprint Headers", "No backend technology leak headers detected")
            return
        for sev, detail in fingerprints.issues:
            result.add_finding(sev, "Backend Fingerprint Headers", detail)

    def _emit_debug_headers(self, debug: DebugHeaderAnalysis, result: ModuleResult):
        if not debug.debug_headers_found:
            result.add_finding("OK", "Debug Headers", "No debug or developer headers exposed")
            return
        for sev, detail in debug.issues:
            result.add_finding(sev, "Debug Headers", detail)

    def _emit_cookie_leaks(self, cookies: CookieLeakAnalysis, result: ModuleResult):
        if not cookies.sensitive_cookies:
            result.add_finding("OK", "Cookie Security", "No sensitive cookies with missing security flags detected")
            return
        for sev, detail in cookies.issues:
            result.add_finding(sev, "Cookie Security", detail)
