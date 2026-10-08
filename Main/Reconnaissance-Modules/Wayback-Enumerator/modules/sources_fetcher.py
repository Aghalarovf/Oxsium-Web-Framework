import asyncio
import re
from typing import Any
from urllib.parse import urlencode, urlparse
from collections import defaultdict

from modules.base import BaseArchiveModule

_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    (r'/robots\.txt',         'robots-txt'),
    (r'/sitemap',             'sitemap'),
    (r'/\.well-known',        'well-known'),
    (r'/favicon\.ico',        'favicon'),
    (r'/security\.txt',       'security-txt'),
    (r'/login',               'login'),
    (r'/admin',               'admin'),
    (r'/register',            'registration'),
    (r'/logout',              'logout'),
    (r'/forgot.password',     'forgot-password'),
    (r'/signup',              'registration'),
    (r'/signin',              'login'),
    (r'/profile',             'user-profile'),
    (r'/account',             'account'),
    (r'/dashboard',           'dashboard'),
    (r'/api',                 'api-endpoint'),
    (r'/health',              'health-check'),
    (r'/status',              'status-page'),
    (r'/info',                'info-endpoint'),
    (r'/config',              'config'),
    (r'/upload',              'upload'),
    (r'/download',            'download'),
    (r'\.env',                'env-file'),
    (r'\.git',                'git-exposure'),
    (r'/backup',              'backup'),
    (r'phpinfo\.php',         'phpinfo'),
    (r'/phpmyadmin',          'phpmyadmin'),
    (r'/wp-admin',            'wordpress-admin'),
    (r'/wp-login',            'wordpress-login'),
    (r'/xmlrpc\.php',         'wordpress-xmlrpc')
]

_API_PATTERNS: list[str] = [
    r'/api/',
    r'/api/v\d+/',
    r'/v\d+/',
    r'/rest/',
    r'/restful/',
    r'/rpc[/?]',
    r'/json-rpc',
    r'/xmlrpc\.php',

    r'/graphql',
    r'/gql[/?]',
    r'/hasura/',

    r'/soap[/?]',
    r'/wsdl[/?]',
    r'\.asmx',
    r'\.svc[/?]',

    r'/ws/',
    r'/wss/',
    r'/websocket[/?]',
    r'/socket\.io/',
    r'/sockjs/',
    r'/signalr/',

    r'/ajax/',
    r'/async/',
    r'/xhr/',

    r'/service/',
    r'/services/',
    r'/endpoint[s]?[/?]',
    r'/resource/',
    r'/resources/',
    r'/action/',
    r'/handler/',
    r'/gateway/',
    r'/proxy/',

    r'/oauth[/?]',
    r'/oauth2[/?]',
    r'/oauth/token',
    r'/oauth/authorize',
    r'/oauth/callback',
    r'/oauth/revoke',
    r'/openid-connect/',
    r'/oidc/',
    r'/auth/token',
    r'/auth/refresh',
    r'/auth/callback',
    r'/auth/sso',
    r'/auth/saml',
    r'/auth/ldap',
    r'/authorize[/?]',
    r'/introspect[/?]',
    r'/userinfo[/?]',
    r'/jwks\.json',
    r'/.well-known/openid-configuration',
    r'/.well-known/oauth-authorization-server',
    r'/.well-known/jwks\.json',
    r'/saml/acs',
    r'/saml/slo',
    r'/saml/metadata',
    r'/cas/',

    r'/webhook[s]?[/?]',
    r'/callback[s]?[/?]',
    r'/hook[s]?[/?]',
    r'/trigger[s]?[/?]',
    r'/api/subscribe',
    r'/api/unsubscribe',
    r'/api/publish',
    r'/sse[/?]',
    r'/eventsource[/?]',
    r'/api/events[/?]',
    r'/api/notification[s]?',
    r'/api/push',

    r'[?&]returnUrl=',
    r'[?&]return_url=',
    r'[?&]returnTo=',
    r'[?&]return_to=',
    r'[?&]redirect_uri=',
    r'[?&]redirect_url=',
    r'[?&]redirectUrl=',
    r'[?&]redirectTo=',
    r'[?&]redirect_to=',
    r'[?&]next=',
    r'[?&]goto=',
    r'[?&]destination=',
    r'[?&]forward=',
    r'[?&]continue=',
    r'[?&]continueUrl=',
    r'[?&]successUrl=',
    r'[?&]failureUrl=',
    r'[?&]cancelUrl=',
    r'[?&]postLoginRedirect=',

    r'/api/query',
    r'/api/search',
    r'/api/filter',
    r'/api/data/',
    r'/feed[s]?\.json',
    r'/feed[s]?\.xml',
    r'/api/stream',
    r'/api/sync',
    r'/api/batch',
    r'/api/bulk',
    r'/api/export',
    r'/api/import',

    r'sap-client',
    r'sap-theme',
    r'SAP-WD',
    r'/sourcing2/',
    r'/sap/opu/',
    r'/sap/bc/',
    r'/OData/',
    r'\$metadata',
    r'\$batch',

    r'/actuator[/?]',
    r'/actuator/env',
    r'/actuator/health',
    r'/actuator/info',
    r'/actuator/metrics',
    r'/actuator/beans',
    r'/actuator/mappings',
    r'/actuator/heapdump',
    r'/actuator/threaddump',

    r'/internal/api',
    r'/private/api',
    r'/_api/',
    r'/__api__/',
    r'/admin/api',
    r'/debug/api',

    r'/mobile/api',
    r'/app/api',
    r'/m/api',
    r'/cdn-api/',
    r'/media/api',
    r'/storage/api',

    r'/stripe/',
    r'/paypal/',
    r'/twilio/',
    r'/sendgrid/',
    r'/mailchimp/',
    r'/hubspot/',
    r'/salesforce/',
    r'/zendesk/',
    r'/intercom/',
    r'/firebase/',
    r'/pusher/',
    r'/slack/api',
]

_FILE_EXTS: set[str] = {
    '.pdf', '.txt', '.php', '.aspx', '.docx', '.xml',
    '.json', '.zip', '.sql', '.env', '.cfg',
    '.ini', '.bak', '.xlsx', '.doc', '.pptx', '.log',
}

def _extract_brand(domain: str) -> str:
    """Extract brand keyword from domain, stripping TLD and common SLD suffixes.

    Examples:
        aztv.az        → aztv
        sub.aztv.com   → aztv
        my-brand.co.uk → my-brand
    """
    domain = domain.split(':')[0].lower()
    parts = domain.split('.')

    two_part_tlds = {
        'co', 'com', 'gov', 'org', 'net', 'edu', 'mil', 'int',
        'ac', 'sch', 'nhs', 'police', 'mod',
    }

    meaningful = []
    for part in reversed(parts):
        if len(meaningful) == 0 and len(part) <= 3:
            continue
        if len(meaningful) == 1 and part in two_part_tlds:
            continue
        meaningful.append(part)

    return meaningful[0] if meaningful else parts[0]

def _enrich(urls: list[str], base_domain: str) -> dict:
    """Categorise a flat URL list into subdomain / critical / api / files."""

    base_hosts = {base_domain, f'www.{base_domain}'}
    brand = _extract_brand(base_domain)

    _sd: dict[str, str] = {}
    for url in urls:
        host = (urlparse(url).hostname or '').lower()
        if not host or host in base_hosts:
            continue

        is_subdomain   = host.endswith(f'.{base_domain}')
        is_brand_match = brand in host

        if not (is_subdomain or is_brand_match):
            continue

        scheme = urlparse(url).scheme or 'https'
        if host not in _sd or scheme == 'https':
            _sd[host] = f'{scheme}://{host}'
    subdomains = sorted(_sd.values())

    critical: dict[str, list[str]] = defaultdict(list)
    for url in urls:
        for pattern, label in _CRITICAL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                critical[label].append(url)
                break

    api_urls: list[str] = []
    for url in urls:
        for pat in _API_PATTERNS:
            if re.search(pat, url, re.IGNORECASE):
                api_urls.append(url)
                break

    file_urls: list[str] = []
    for url in urls:
        path = urlparse(url).path.lower().rstrip('/')
        dot   = path.rfind('.')
        slash = path.rfind('/')
        if dot > slash and dot != -1 and path[dot:] in _FILE_EXTS:
            file_urls.append(url)

    return {
        'subdomain':        subdomains,
        'critical_pattern': dict(critical),
        'api_pattern':      sorted(set(api_urls)),
        'files':            sorted(set(file_urls)),
    }

WAYBACK_CDX_URL    = "http://web.archive.org/cdx/search/cdx"
COMMONCRAWL_INDEX  = "https://index.commoncrawl.org/collinfo.json"
COMMONCRAWL_API    = "https://index.commoncrawl.org/{index}/cdx"
OTX_URL_LIST       = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
URLSCAN_SEARCH     = "https://urlscan.io/api/v1/search/"

CC_MAX_INDEXES = 3
WAYBACK_PAGE_LIMIT = 10_000
OTX_PAGE_LIMIT = 500
URLSCAN_LIMIT = 1000

class ArchiveSourcesModule(BaseArchiveModule):

    async def run(self) -> dict[str, Any]:
        self.logger.info(f"Source scan started → {self.domain}")

        results = await asyncio.gather(
            self.fetch_wayback_cdx(self.domain),
            self.fetch_commoncrawl(self.domain),
            self.fetch_alienvault_otx(self.domain),
            self.fetch_urlscan(self.domain),
            return_exceptions=True,
        )

        wayback_urls, cc_urls, otx_urls, urlscan_urls = self._unpack(results)

        merged = self.merge_and_deduplicate(
            [wayback_urls, cc_urls, otx_urls, urlscan_urls]
        )

        stats = {
            "total":       len(merged),
            "wayback":     len(wayback_urls),
            "commoncrawl": len(cc_urls),
            "otx":         len(otx_urls),
            "urlscan":     len(urlscan_urls),
        }

        self.logger.success(
            f"Total {stats['total']} unique URLs found "
            f"(WB:{stats['wayback']} | CC:{stats['commoncrawl']} "
            f"| OTX:{stats['otx']} | US:{stats['urlscan']})"
        )

        enriched = _enrich(merged, self.domain)

        return {
            "urls":             merged,
            "subdomain":        enriched["subdomain"],
            "critical_pattern": enriched["critical_pattern"],
            "api_pattern":      enriched["api_pattern"],
            "files":            enriched["files"],
            "stats":            stats,
        }

    async def fetch_wayback_cdx(self, domain: str) -> list[str]:
        self.log_debug(f"Wayback CDX scan: {domain}")
        urls: list[str] = []

        pattern = f"*.{domain}/*"

        num_pages = await self._wayback_page_count(pattern)
        self.log_debug(f"Wayback CDX: {num_pages} pages")

        tasks = [
            self._wayback_fetch_page(pattern, page)
            for page in range(num_pages)
        ]
        pages = await asyncio.gather(*tasks, return_exceptions=True)

        for page_urls in pages:
            if isinstance(page_urls, list):
                urls.extend(page_urls)

        return self.deduplicate(urls)

    async def _wayback_page_count(self, pattern: str) -> int:
        params = {
            "url":        pattern,
            "output":     "json",
            "fl":         "original",
            "collapse":   "urlkey",
            "showNumPages": "true",
        }
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="text")
        try:
            count = int(data.strip()) if data else 1
            return max(1, min(count, 50))
        except (ValueError, AttributeError):
            return 1

    async def _wayback_fetch_page(self, pattern: str, page: int) -> list[str]:
        params = {
            "url":      pattern,
            "output":   "json",
            "fl":       "original",
            "collapse": "urlkey",
            "limit":    WAYBACK_PAGE_LIMIT,
            "page":     page,
        }
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="json")

        if not data or not isinstance(data, list):
            return []

        rows = data[1:] if data and isinstance(data[0], list) else data
        return [row[0] for row in rows if row and isinstance(row, list) and row[0]]

    async def fetch_commoncrawl(self, domain: str) -> list[str]:
        self.log_debug("Loading CommonCrawl indexes...")
        urls: list[str] = []

        indexes = await self._cc_get_indexes()
        if not indexes:
            self.logger.warning("Failed to retrieve CommonCrawl index list.")
            return urls

        recent = indexes[:CC_MAX_INDEXES]
        self.log_debug(f"CommonCrawl: querying {len(recent)} indexes")

        tasks = [
            self._cc_query_index(idx["cdx-api"], domain)
            for idx in recent
            if "cdx-api" in idx
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                urls.extend(res)

        return self.deduplicate(urls)

    async def _cc_get_indexes(self) -> list[dict]:
        data = await self.requester.get(COMMONCRAWL_INDEX, response_type="json")
        if isinstance(data, list):
            return data
        return []

    async def _cc_query_index(self, api_url: str, domain: str) -> list[str]:
        params = {
            "url":      f"*.{domain}",
            "output":   "json",
            "fl":       "url",
            "limit":    5000,
        }
        data = await self.requester.get(api_url, params=params, response_type="text")

        if not data:
            return []

        urls = []
        for line in data.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                import json
                obj = json.loads(line)
                if "url" in obj:
                    urls.append(obj["url"])
            except Exception:
                continue

        return urls

    async def fetch_alienvault_otx(self, domain: str) -> list[str]:
        self.log_debug(f"OTX query: {domain}")
        urls: list[str] = []
        base_url = OTX_URL_LIST.format(domain=domain)

        page = 1
        next_url: str | None = base_url

        while next_url:
            params = {"limit": OTX_PAGE_LIMIT, "page": page}
            data = await self.requester.get(next_url, params=params, response_type="json")

            if not data or not isinstance(data, dict):
                break

            url_list = data.get("url_list", [])
            for entry in url_list:
                if isinstance(entry, dict) and "url" in entry:
                    urls.append(entry["url"])

            next_url = data.get("next")
            page += 1

            if page > 20:
                self.log_debug("OTX: Maximum page limit reached")
                break

        return self.deduplicate(urls)

    async def fetch_urlscan(self, domain: str) -> list[str]:
        self.log_debug(f"URLScan query: {domain}")
        urls: list[str] = []

        search_after: str | None = None
        fetched = 0

        while fetched < URLSCAN_LIMIT:
            params: dict[str, Any] = {
                "q":    f"domain:{domain}",
                "size": min(100, URLSCAN_LIMIT - fetched),
            }
            if search_after:
                params["search_after"] = search_after

            data = await self.requester.get(
                URLSCAN_SEARCH, params=params, response_type="json"
            )

            if not data or not isinstance(data, dict):
                break

            results_list = data.get("results", [])
            if not results_list:
                break

            for hit in results_list:
                page_url = hit.get("page", {}).get("url")
                if page_url:
                    urls.append(page_url)
                task_url = hit.get("task", {}).get("url")
                if task_url and task_url != page_url:
                    urls.append(task_url)

            fetched += len(results_list)

            if len(results_list) < params["size"]:
                break
            last_hit = results_list[-1]
            sort_val = last_hit.get("sort")
            if sort_val:
                search_after = ",".join(str(v) for v in sort_val)
            else:
                break

        return self.deduplicate(urls)

    def merge_and_deduplicate(self, source_lists: list[list[str]]) -> list[str]:
        combined: list[str] = []
        for lst in source_lists:
            if isinstance(lst, (list, tuple)):
                combined.extend(u for u in lst if u and isinstance(u, str))

        return self.deduplicate(combined)

    @staticmethod
    def _unpack(gather_results: tuple) -> tuple[list, list, list, list]:
        unpacked = []
        for r in gather_results:
            if isinstance(r, Exception):
                unpacked.append([])
            elif isinstance(r, list):
                unpacked.append(r)
            else:
                unpacked.append([])
        while len(unpacked) < 4:
            unpacked.append([])
        return tuple(unpacked[:4])