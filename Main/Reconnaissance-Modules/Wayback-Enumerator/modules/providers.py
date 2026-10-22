import asyncio
import html
import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from core.logger import Logger
from core.requester import Requester

VIRUSTOTAL_DOMAIN_REPORT = "https://www.virustotal.com/vtapi/v2/domain/report"
GHOSTARCHIVE_SEARCH = "https://ghostarchive.org/search"
ARQUIVO_CDX = "https://arquivo.pt/wayback/cdx"
UKWA_CDX = "https://www.webarchive.org.uk/wayback/archive/cdx"
HUDSONROCK_URLS = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain"
INTELX_HOSTS = ("2.intelx.io", "free.intelx.io")

GHOSTARCHIVE_MAX_PAGES = 50
CDX_LIMIT = 100000
INTELX_MAX_POLLS = 30
INTELX_TARGET_URLS = 3

GHOSTARCHIVE_ROW = re.compile(
    r'<a[^>]+href="(?:https://ghostarchive\.org)?/archive/[A-Za-z0-9]+"[^>]*>\s*(https?://[^<\s]+)\s*</a>',
    re.IGNORECASE,
)


@dataclass
class ProviderContext:
    domain: str
    requester: Requester
    logger: Logger
    keys: dict[str, str]


def in_scope(url: str, domain: str) -> bool:
    if not isinstance(url, str) or not url:
        return False
    candidate = url if "://" in url else "//" + url
    try:
        host = (urlparse(candidate).hostname or "").lower()
    except ValueError:
        return False
    return host == domain or host.endswith("." + domain)


def scoped(urls: list[str], domain: str) -> list[str]:
    return list(dict.fromkeys(u for u in urls if in_scope(u, domain)))


def parse_cdx_urls(payload: Any) -> list[str]:
    urls: list[str] = []
    if payload is None:
        return urls

    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return urls
        if text.startswith("["):
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
        if isinstance(payload, str):
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                urls.extend(_urls_from_row(obj, None))
            return urls

    if isinstance(payload, list):
        header: list[str] | None = None
        if payload and isinstance(payload[0], list) and all(isinstance(c, str) for c in payload[0]):
            header = payload[0]
            payload = payload[1:]
        for row in payload:
            urls.extend(_urls_from_row(row, header))
    return urls


def _urls_from_row(row: Any, header: list[str] | None) -> list[str]:
    if isinstance(row, dict):
        for key in ("url", "original"):
            value = row.get(key)
            if isinstance(value, str) and value:
                return [value]
        return []
    if isinstance(row, list) and row:
        if header:
            for key in ("url", "original"):
                if key in header:
                    idx = header.index(key)
                    if idx < len(row) and isinstance(row[idx], str):
                        return [row[idx]]
            return []
        if isinstance(row[0], str):
            return [row[0]]
    return []


async def fetch_virustotal(ctx: ProviderContext) -> list[str]:
    ctx.logger.debug(f"[VirusTotal] query: {ctx.domain}")
    data = await ctx.requester.get(
        VIRUSTOTAL_DOMAIN_REPORT,
        params={"apikey": ctx.keys["virustotal"], "domain": ctx.domain},
        response_type="json",
    )
    urls: list[str] = []
    if not isinstance(data, dict):
        return urls

    for entry in data.get("detected_urls") or []:
        if isinstance(entry, dict) and isinstance(entry.get("url"), str):
            urls.append(entry["url"])
    for entry in data.get("undetected_urls") or []:
        if isinstance(entry, (list, tuple)) and entry and isinstance(entry[0], str):
            urls.append(entry[0])
    return scoped(urls, ctx.domain)


async def fetch_ghostarchive(ctx: ProviderContext) -> list[str]:
    ctx.logger.debug(f"[GhostArchive] query: {ctx.domain}")
    urls: list[str] = []
    previous: tuple[str, ...] = ()

    for page in range(GHOSTARCHIVE_MAX_PAGES):
        params: dict[str, Any] = {"term": ctx.domain}
        if page:
            params["page"] = page
        text = await ctx.requester.get(GHOSTARCHIVE_SEARCH, params=params, response_type="text")
        if not text:
            break

        found = tuple(html.unescape(u) for u in GHOSTARCHIVE_ROW.findall(text))
        if not found or found == previous:
            break
        urls.extend(found)
        previous = found

        if "Next Page" not in text:
            break
    return scoped(urls, ctx.domain)


async def _fetch_cdx_archive(ctx: ProviderContext, label: str, endpoint: str, params: dict[str, Any]) -> list[str]:
    ctx.logger.debug(f"[{label}] query: {ctx.domain}")
    text = await ctx.requester.get(endpoint, params=params, response_type="text")
    return scoped(parse_cdx_urls(text), ctx.domain)


async def fetch_arquivo(ctx: ProviderContext) -> list[str]:
    params = {
        "url": f"*.{ctx.domain}",
        "output": "json",
        "fields": "url",
        "limit": CDX_LIMIT,
    }
    return await _fetch_cdx_archive(ctx, "Arquivo.pt", ARQUIVO_CDX, params)


async def fetch_ukwa(ctx: ProviderContext) -> list[str]:
    params = {
        "url": f"*.{ctx.domain}",
        "output": "json",
        "fl": "url",
        "limit": CDX_LIMIT,
    }
    return await _fetch_cdx_archive(ctx, "UKWA", UKWA_CDX, params)


async def fetch_hudsonrock(ctx: ProviderContext) -> list[str]:
    ctx.logger.debug(f"[HudsonRock] query: {ctx.domain}")
    data = await ctx.requester.get(
        HUDSONROCK_URLS, params={"domain": ctx.domain}, response_type="json"
    )
    payload = data.get("data") if isinstance(data, dict) else None
    if not isinstance(payload, dict):
        return []

    urls: list[str] = []
    for key in ("employees_urls", "clients_urls"):
        entries = payload.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            value = entry.get("url") if isinstance(entry, dict) else entry
            if isinstance(value, str) and value:
                urls.append(value)
    return scoped(urls, ctx.domain)


async def fetch_intelx(ctx: ProviderContext) -> list[str]:
    key = ctx.keys["intelx"]
    configured = ctx.keys.get("intelx_host")
    hosts = [configured] if configured else list(INTELX_HOSTS)

    for host in hosts:
        ctx.logger.debug(f"[IntelX] query: {ctx.domain} via {host}")
        body = {
            "term": ctx.domain,
            "maxresults": 100000,
            "media": 0,
            "target": INTELX_TARGET_URLS,
            "terminate": None,
            "timeout": 20,
        }
        search = await ctx.requester.post(
            f"https://{host}/phonebook/search",
            json_body=body,
            params={"k": key},
            response_type="json",
        )
        search_id = search.get("id") if isinstance(search, dict) else None
        if not search_id:
            continue

        urls: list[str] = []
        for _ in range(INTELX_MAX_POLLS):
            result = await ctx.requester.get(
                f"https://{host}/phonebook/search/result",
                params={"k": key, "id": search_id, "limit": 10000},
                response_type="json",
            )
            if not isinstance(result, dict):
                break
            for selector in result.get("selectors") or []:
                if isinstance(selector, dict) and isinstance(selector.get("selectorvalue"), str):
                    urls.append(selector["selectorvalue"])
            if result.get("status") not in (0, 3):
                break
            await asyncio.sleep(1)
        return scoped(urls, ctx.domain)

    return []


EXTRA_PROVIDERS: dict[str, tuple[Callable[[ProviderContext], Awaitable[list[str]]], tuple[str, ...]]] = {
    "virustotal":  (fetch_virustotal, ("virustotal",)),
    "ghostarchive": (fetch_ghostarchive, ()),
    "arquivo":     (fetch_arquivo, ()),
    "ukwa":        (fetch_ukwa, ()),
    "hudsonrock":  (fetch_hudsonrock, ()),
    "intelx":      (fetch_intelx, ("intelx",)),
}

BUILTIN_PROVIDERS: tuple[str, ...] = ("wayback", "commoncrawl", "otx", "urlscan")
ALL_PROVIDER_NAMES: tuple[str, ...] = BUILTIN_PROVIDERS + tuple(EXTRA_PROVIDERS)
DEFAULT_PROVIDERS: tuple[str, ...] = tuple(n for n in ALL_PROVIDER_NAMES if n != "intelx")


def resolve_providers(raw: str | None) -> tuple[list[str], list[str]]:
    if not raw:
        return list(DEFAULT_PROVIDERS), []
    selected: list[str] = []
    unknown: list[str] = []
    for name in raw.split(","):
        name = name.strip().lower()
        if not name:
            continue
        if name in ALL_PROVIDER_NAMES:
            if name not in selected:
                selected.append(name)
        else:
            unknown.append(name)
    return selected, unknown
