from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from modules.base import BaseArchiveModule

EXTENSION_GROUPS: dict[str, set[str]] = {
    "js":       {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"},
    "css":      {".css", ".scss", ".sass", ".less"},
    "images":   {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff"},
    "docs":     {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".rtf", ".txt", ".csv"},
    "fonts":    {".woff", ".woff2", ".ttf", ".eot", ".otf"},
    "media":    {".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".flac"},
    "data":     {".json", ".xml", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg"},
    "archives": {".zip", ".tar", ".gz", ".rar", ".7z", ".bz2"},
}

API_PATTERNS: list[re.Pattern] = [
    re.compile(r"/api/",       re.IGNORECASE),
    re.compile(r"/v\d+/",      re.IGNORECASE),
    re.compile(r"/rest/",      re.IGNORECASE),
    re.compile(r"/graphql",    re.IGNORECASE),
    re.compile(r"/rpc",        re.IGNORECASE),
    re.compile(r"/soap",       re.IGNORECASE),
    re.compile(r"/ws/",        re.IGNORECASE),
    re.compile(r"/ajax/",      re.IGNORECASE),
    re.compile(r"/service/",   re.IGNORECASE),
    re.compile(r"/endpoint",   re.IGNORECASE),
    re.compile(r"/webhook",    re.IGNORECASE),
    re.compile(r"/callback",   re.IGNORECASE),
    re.compile(r"/oauth",      re.IGNORECASE),
    re.compile(r"/auth/",      re.IGNORECASE),
    re.compile(r"/admin/",     re.IGNORECASE),
]

SYSTEM_FILES: set[str] = {
    "robots.txt",
    "security.txt",
    ".well-known/security.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "humans.txt",
    ".htaccess",
    "web.config",
    "phpinfo.php",
    "server-status",
    "server-info",
    "elmah.axd",
    "trace.axd",
    "wp-login.php",
    "wp-config.php",
    "config.php",
    ".git/HEAD",
    ".git/config",
    ".env",
    "backup.zip",
    "backup.sql",
    "dump.sql",
}

class URLAnalyzerModule(BaseArchiveModule):

    async def run(self, urls: list[str] | None = None) -> dict[str, Any]:
        if urls is None:
            urls = getattr(self, "input_urls", [])

        self.logger.info(f"URL analysis started → {len(urls)} URLs")

        by_extension  = self.filter_by_extension(urls)
        api_endpoints = self.extract_api_endpoints(urls)
        system_files  = self.find_system_files(urls)
        subdomains    = self.extract_archived_subdomains(urls)

        stats = {
            "total_input":   len(urls),
            "api_endpoints": len(api_endpoints),
            "system_files":  len(system_files),
            "subdomains":    len(subdomains),
            "by_extension":  {k: len(v) for k, v in by_extension.items()},
        }

        self.logger.success(
            f"Analysis complete – "
            f"API:{stats['api_endpoints']} | "
            f"SysFiles:{stats['system_files']} | "
            f"Subdomains:{stats['subdomains']}"
        )

        return {
            "by_extension":  by_extension,
            "api_endpoints": api_endpoints,
            "system_files":  system_files,
            "subdomains":    subdomains,
            "stats":         stats,
        }

    def filter_by_extension(self, urls: list[str]) -> dict[str, list[str]]:
        buckets: dict[str, list[str]] = {group: [] for group in EXTENSION_GROUPS}
        buckets["other"] = []

        for url in urls:
            if not url:
                continue
            path = urlparse(url).path.lower().rstrip("/")
            ext  = self._extract_extension(path)

            matched = False
            for group, extensions in EXTENSION_GROUPS.items():
                if ext in extensions:
                    buckets[group].append(url)
                    matched = True
                    break

            if not matched:
                buckets["other"].append(url)

        return {k: self.deduplicate(v) for k, v in buckets.items()}

    def extract_api_endpoints(self, urls: list[str]) -> list[str]:
        endpoints: list[str] = []

        for url in urls:
            if not url:
                continue
            parsed = urlparse(url)
            for pattern in API_PATTERNS:
                if pattern.search(parsed.path):
                    clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    endpoints.append(clean)
                    break

        return sorted(self.deduplicate(endpoints), key=lambda u: urlparse(u).path)

    def find_system_files(self, urls: list[str]) -> list[str]:
        found: list[str] = []

        for url in urls:
            if not url:
                continue
            path = urlparse(url).path.lstrip("/")
            for sysfile in SYSTEM_FILES:
                if path == sysfile or path.endswith("/" + sysfile):
                    found.append(url)
                    break

        return self.deduplicate(found)

    def extract_archived_subdomains(self, urls: list[str]) -> list[str]:
        hosts: set[str] = set()
        apex = getattr(self, "domain", "")

        for url in urls:
            if not url:
                continue
            host = urlparse(url).hostname
            if not host:
                continue
            host = host.lower().strip()
            if apex and host.endswith(f".{apex}") and host != apex:
                hosts.add(host)
            elif not apex:
                hosts.add(host)

        return sorted(hosts)

    @staticmethod
    def _extract_extension(path: str) -> str:
        dot_pos   = path.rfind(".")
        slash_pos = path.rfind("/")
        if dot_pos > slash_pos and dot_pos != -1:
            return path[dot_pos:]
        return ""