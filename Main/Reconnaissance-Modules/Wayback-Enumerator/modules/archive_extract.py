import asyncio
import gzip
import html
import json
import re
from typing import Any
from urllib.parse import urlparse

from colorama import Fore, Style

from modules.base import BaseArchiveModule

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW_URL = "https://web.archive.org/web/{timestamp}id_/{url}"
WAYBACK_VIEW_URL = "https://web.archive.org/web/{timestamp}/{url}"

DEFAULT_SNAPSHOT_LIMIT = 10
MAX_CANDIDATES = 200
MAX_SUBDOMAINS = 20
DISCOVERY_LIMIT = 5000
SNAPSHOT_LIST_LIMIT = 1000
DISPLAY_LIMIT = 40
TIMELINE_EXAMPLES = 3
RAW_LIMIT = 20000

KIND_ORDER = ("robots", "sitemap", "security", "crossdomain", "clientaccess", "humans", "ads", "wellknown")

KIND_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("security",     re.compile(r"/(?:\.well-known/)?security\.txt$")),
    ("robots",       re.compile(r"/robots\.txt$")),
    ("sitemap",      re.compile(r"/[^/]*sitemap[^/]*\.(?:xml|xml\.gz|txt)$")),
    ("crossdomain",  re.compile(r"/crossdomain\.xml$")),
    ("clientaccess", re.compile(r"/clientaccesspolicy\.xml$")),
    ("humans",       re.compile(r"/humans\.txt$")),
    ("ads",          re.compile(r"/(?:app-)?ads\.txt$")),
    ("wellknown",    re.compile(r"/\.well-known/[^/]+$")),
]

DISCOVERY_ALTERNATIVES: dict[str, str] = {
    "robots":       r"robots\.txt",
    "sitemap":      r"[^/]*sitemap[^/]*\.(xml|xml\.gz|txt)",
    "security":     r"security\.txt",
    "crossdomain":  r"crossdomain\.xml",
    "clientaccess": r"clientaccesspolicy\.xml",
    "humans":       r"humans\.txt",
    "ads":          r"(app-)?ads\.txt",
    "wellknown":    r"\.well-known/[^/?]+",
}

BASELINE_PATHS: dict[str, tuple[str, ...]] = {
    "robots":       ("/robots.txt",),
    "sitemap":      ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.xml.gz"),
    "security":     ("/security.txt", "/.well-known/security.txt"),
    "crossdomain":  ("/crossdomain.xml",),
    "clientaccess": ("/clientaccesspolicy.xml",),
    "humans":       ("/humans.txt",),
    "ads":          ("/ads.txt", "/app-ads.txt"),
    "wellknown":    ("/.well-known/openid-configuration", "/.well-known/assetlinks.json",
                     "/.well-known/apple-app-site-association"),
}

SUBDOMAIN_PATHS: dict[str, tuple[str, ...]] = {
    "robots":   ("/robots.txt",),
    "sitemap":  ("/sitemap.xml",),
    "security": ("/.well-known/security.txt",),
}

SECURITY_FIELDS = (
    "contact", "expires", "encryption", "acknowledgments", "policy",
    "canonical", "preferred-languages", "hiring", "csaf",
)

WELLKNOWN_ID_KEYS = {
    "package_name", "namespace", "sha256_cert_fingerprints", "appid", "appids",
    "bundleid", "issuer", "jwks_uri", "authorization_endpoint", "token_endpoint",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
LOC_RE = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", re.IGNORECASE | re.DOTALL)


def classify(url: str) -> str | None:
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return None
    for kind, pattern in KIND_PATTERNS:
        if pattern.search(path):
            return kind
    return None


def resource_key(url: str) -> str:
    stripped = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip(), flags=re.IGNORECASE)
    host, sep, rest = stripped.partition("/")
    host = host.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return f"{host}{sep}{rest}"


def format_timestamp(ts: str) -> str:
    if len(ts) >= 12 and ts[:12].isdigit():
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"
    return ts


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def looks_like_html(text: str) -> bool:
    head = text.lstrip("﻿ \t\r\n")[:300].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head


def parse_robots(text: str) -> dict[str, list[str]]:
    data: dict[str, list[str]] = {
        "user_agents": [], "disallow": [], "allow": [], "sitemaps": [],
        "crawl_delay": [], "host": [], "other": [],
    }
    for raw in text.lstrip("﻿").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, value = line.split(":", 1)
        field = field.strip().lower()
        value = value.strip()
        if not value:
            continue
        if field == "user-agent":
            data["user_agents"].append(value)
        elif field == "disallow":
            data["disallow"].append(value)
        elif field == "allow":
            data["allow"].append(value)
        elif field == "sitemap":
            data["sitemaps"].append(value)
        elif field == "crawl-delay":
            data["crawl_delay"].append(value)
        elif field == "host":
            data["host"].append(value)
        else:
            data["other"].append(f"{field}: {value}")
    return {k: dedupe(v) for k, v in data.items() if v}


def parse_sitemap(text: str, url: str) -> dict[str, list[str]]:
    path = urlparse(url).path.lower()
    if path.endswith(".txt"):
        entries = [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith("http")]
        return {"urls": dedupe(entries)} if entries else {}

    locs = [html.unescape(m.strip()) for m in LOC_RE.findall(text)]
    if not locs:
        return {}
    if "<sitemapindex" in text.lower():
        return {"sitemaps": dedupe(locs)}
    return {"urls": dedupe(locs)}


def parse_security(text: str) -> dict[str, list[str]]:
    data: dict[str, list[str]] = {field: [] for field in SECURITY_FIELDS}
    for raw in text.lstrip("﻿").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        field, value = line.split(":", 1)
        field = field.strip().lower()
        if field in data and value.strip():
            data[field].append(value.strip())
    return {k: dedupe(v) for k, v in data.items() if v}


def _attr(tag: str, name: str) -> str | None:
    match = re.search(rf'{name}\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
    return match.group(1) if match else None


def parse_crossdomain(text: str) -> dict[str, list[str]]:
    data: dict[str, list[str]] = {"allow_access_from": [], "allow_headers_from": [], "site_control": []}
    for tag in re.findall(r"<allow-access-from\b[^>]*>", text, re.IGNORECASE):
        domain = _attr(tag, "domain")
        if domain is None:
            continue
        secure = _attr(tag, "secure")
        data["allow_access_from"].append(f"{domain} (secure={secure})" if secure else domain)
    for tag in re.findall(r"<allow-http-request-headers-from\b[^>]*>", text, re.IGNORECASE):
        domain = _attr(tag, "domain")
        headers = _attr(tag, "headers")
        if domain is not None:
            data["allow_headers_from"].append(f"{domain} headers={headers}" if headers else domain)
    for tag in re.findall(r"<site-control\b[^>]*>", text, re.IGNORECASE):
        policy = _attr(tag, "permitted-cross-domain-policies")
        if policy:
            data["site_control"].append(policy)
    return {k: dedupe(v) for k, v in data.items() if v}


def parse_clientaccess(text: str) -> dict[str, list[str]]:
    data = {
        "domains": [html.unescape(d) for d in re.findall(r'<domain\s+uri\s*=\s*["\']([^"\']*)["\']', text, re.IGNORECASE)],
        "resources": [html.unescape(r) for r in re.findall(r'<resource\s+path\s*=\s*["\']([^"\']*)["\']', text, re.IGNORECASE)],
    }
    return {k: dedupe(v) for k, v in data.items() if v}


def parse_humans(text: str) -> dict[str, list[str]]:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()][:100]
    data = {
        "emails": dedupe(EMAIL_RE.findall(text)),
        "urls": dedupe(URL_RE.findall(text)),
        "lines": lines,
    }
    return {k: v for k, v in data.items() if v}


def parse_ads(text: str) -> dict[str, list[str]]:
    records: list[str] = []
    variables: list[str] = []
    for raw in text.lstrip("﻿").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line and "," not in line:
            variables.append(line)
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3:
            records.append(f"{parts[0].lower()}, {parts[1]}, {parts[2].upper()}")
    data = {"records": dedupe(records), "variables": dedupe(variables)}
    return {k: v for k, v in data.items() if v}


def _walk_json(node: Any, urls: list[str], identifiers: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in WELLKNOWN_ID_KEYS:
                if isinstance(value, str):
                    identifiers.append(f"{key}: {value}")
                elif isinstance(value, list):
                    identifiers.extend(f"{key}: {v}" for v in value if isinstance(v, (str, int)))
            _walk_json(value, urls, identifiers)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, urls, identifiers)
    elif isinstance(node, str) and node.startswith(("http://", "https://")):
        urls.append(node)


def parse_wellknown(text: str) -> dict[str, list[str]]:
    try:
        payload = json.loads(text.lstrip("﻿"))
    except ValueError:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()][:100]
        return {"lines": lines} if lines else {}

    urls: list[str] = []
    identifiers: list[str] = []
    _walk_json(payload, urls, identifiers)
    data: dict[str, list[str]] = {}
    if isinstance(payload, dict):
        data["keys"] = sorted(str(k) for k in payload.keys())
    data["identifiers"] = dedupe(identifiers)
    data["urls"] = dedupe(urls)
    return {k: v for k, v in data.items() if v}


def parse_content(kind: str, text: str, url: str) -> dict[str, list[str]] | None:
    if not text or not text.strip():
        return None
    if kind != "wellknown" and looks_like_html(text):
        return None
    if kind == "robots":
        return parse_robots(text)
    if kind == "sitemap":
        return parse_sitemap(text, url)
    if kind == "security":
        return parse_security(text)
    if kind == "crossdomain":
        return parse_crossdomain(text)
    if kind == "clientaccess":
        return parse_clientaccess(text)
    if kind == "humans":
        return parse_humans(text)
    if kind == "ads":
        return parse_ads(text)
    if kind == "wellknown":
        if text.lstrip().lower().startswith(("<!doctype html", "<html")):
            return None
        return parse_wellknown(text)
    return None


def to_items(parsed: dict[str, list[str]]) -> set[str]:
    return {f"{key}: {value}" for key, values in parsed.items() for value in values}


def merge_parsed(parsed_list: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for parsed in parsed_list:
        for key, values in parsed.items():
            merged.setdefault(key, [])
            merged[key].extend(values)
    return {k: dedupe(v) for k, v in merged.items()}


def subtract_parsed(source: dict[str, list[str]], other: dict[str, list[str]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, values in source.items():
        excluded = set(other.get(key, []))
        remaining = [v for v in values if v not in excluded]
        if remaining:
            result[key] = remaining
    return result


def sample_snapshots(snapshots: list[dict[str, str]], limit: int) -> list[dict[str, str]]:
    count = len(snapshots)
    if count <= limit:
        return snapshots
    if limit == 1:
        return [snapshots[-1]]
    indexes = sorted({round(i * (count - 1) / (limit - 1)) for i in range(limit)})
    return [snapshots[i] for i in indexes]


class ArchiveExtractModule(BaseArchiveModule):

    async def run(self) -> dict[str, Any]:
        self.kinds = self._selected_kinds()
        self.snapshot_limit = max(1, getattr(self.args, "extract_limit", None) or DEFAULT_SNAPSHOT_LIMIT)
        self.include_raw = bool(getattr(self.args, "extract_raw", False))

        self.logger.info(f"Extract started → {self.domain} | types: {', '.join(self.kinds)}")

        candidates = await self._collect_candidates()
        self.logger.info(f"Candidate resources: {len(candidates)}")

        groups = await self._collect_snapshots(candidates)
        self.logger.info(f"Resources with archived 200 snapshots: {len(groups)}")

        analyzed = await asyncio.gather(
            *(self._analyze_group(items) for items in groups.values()),
            return_exceptions=True,
        )

        files: list[dict[str, Any]] = []
        for entry in analyzed:
            if isinstance(entry, Exception):
                self.logger.warning(f"Extract analysis failed: {entry}")
            elif entry:
                files.append(entry)

        files.sort(key=lambda f: (KIND_ORDER.index(f["kind"]), f["url"]))

        for index, entry in enumerate(files, start=1):
            self._print_entry(entry, index, len(files))

        by_kind: dict[str, list[str]] = {}
        for entry in files:
            by_kind.setdefault(entry["kind"], []).append(entry["url"])

        stats = {
            "resources_found": len(files),
            "snapshots_analyzed": sum(f["snapshots_analyzed"] for f in files),
            "by_kind": {k: len(v) for k, v in by_kind.items()},
        }

        if files:
            self.logger.success(
                f"Extract complete – {stats['resources_found']} resources, "
                f"{stats['snapshots_analyzed']} snapshots analyzed"
            )
        else:
            self.logger.warning("Extract complete – no archived critical files found")

        return {"files": files, "by_kind": by_kind, "stats": stats}

    def _selected_kinds(self) -> list[str]:
        raw = getattr(self.args, "extract_types", None)
        if not raw:
            return list(KIND_ORDER)
        selected: list[str] = []
        for name in raw.split(","):
            name = name.strip().lower()
            if not name:
                continue
            if name in KIND_ORDER:
                if name not in selected:
                    selected.append(name)
            else:
                self.logger.warning(f"Unknown extract type ignored: {name}")
        return selected or list(KIND_ORDER)

    async def _collect_candidates(self) -> list[str]:
        ordered: dict[str, str] = {}

        def add(url: str) -> None:
            key = resource_key(url)
            if key not in ordered:
                ordered[key] = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip(), flags=re.IGNORECASE)

        for kind in self.kinds:
            for path in BASELINE_PATHS.get(kind, ()):
                add(f"{self.domain}{path}")

        sources = self.prior_results.get("sources", {})
        subdomains = sources.get("subdomain", []) if isinstance(sources, dict) else []
        for host in list(subdomains)[:MAX_SUBDOMAINS]:
            for kind in self.kinds:
                for path in SUBDOMAIN_PATHS.get(kind, ()):
                    add(f"{host}{path}")

        for url in self.get_prior_urls():
            if isinstance(url, str) and classify(url) in self.kinds:
                add(url)

        for url in await self._discover():
            if classify(url) in self.kinds:
                add(url)

        candidates = list(ordered.values())
        if len(candidates) > MAX_CANDIDATES:
            self.logger.warning(f"Candidate list capped at {MAX_CANDIDATES} (found {len(candidates)})")
            candidates = candidates[:MAX_CANDIDATES]
        return candidates

    async def _discover(self) -> list[str]:
        alternatives = "|".join(DISCOVERY_ALTERNATIVES[k] for k in self.kinds)
        pattern = rf"original:.*/({alternatives})(\?.*)?$"
        params = {
            "url":       self.domain,
            "matchType": "domain",
            "output":    "json",
            "fl":        "original",
            "collapse":  "urlkey",
            "filter":    pattern,
            "limit":     DISCOVERY_LIMIT,
        }
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="json")
        if not isinstance(data, list) or not data:
            return []
        rows = data[1:] if isinstance(data[0], list) and data[0] and data[0][0] == "original" else data
        return [row[0] for row in rows if isinstance(row, list) and row and isinstance(row[0], str)]

    async def _collect_snapshots(self, candidates: list[str]) -> dict[str, list[dict[str, str]]]:
        results = await asyncio.gather(
            *(self._list_snapshots(c) for c in candidates), return_exceptions=True
        )

        groups: dict[str, dict[str, dict[str, str]]] = {}
        for rows in results:
            if not isinstance(rows, list):
                continue
            for row in rows:
                kind = classify(row["original"])
                if kind not in self.kinds:
                    continue
                key = resource_key(row["original"])
                snapshots = groups.setdefault(key, {})
                snapshots[f"{row['timestamp']}:{row['digest']}"] = {**row, "kind": kind}

        return {
            key: sorted(snapshots.values(), key=lambda s: s["timestamp"])
            for key, snapshots in groups.items()
        }

    async def _list_snapshots(self, candidate: str) -> list[dict[str, str]]:
        params = {
            "url":      candidate,
            "output":   "json",
            "fl":       "original,timestamp,statuscode,digest",
            "filter":   "statuscode:200",
            "collapse": "digest",
            "limit":    SNAPSHOT_LIST_LIMIT,
        }
        data = await self.requester.get(WAYBACK_CDX_URL, params=params, response_type="json")
        if not isinstance(data, list) or len(data) < 2:
            return []

        rows: list[dict[str, str]] = []
        for row in data[1:]:
            if isinstance(row, list) and len(row) >= 4:
                rows.append({
                    "original":  row[0],
                    "timestamp": row[1],
                    "status":    row[2],
                    "digest":    row[3],
                })
        return rows

    async def _fetch_snapshot(self, original: str, timestamp: str) -> str | None:
        url = WAYBACK_RAW_URL.format(timestamp=timestamp, url=original)
        if urlparse(original).path.lower().endswith(".gz"):
            payload = await self.requester.get(url, response_type="bytes")
            if not payload:
                return None
            try:
                payload = gzip.decompress(payload)
            except (OSError, EOFError):
                pass
            return payload.decode("utf-8", errors="replace")
        return await self.requester.get(url, response_type="text")

    async def _analyze_group(self, snapshots: list[dict[str, str]]) -> dict[str, Any] | None:
        kind = snapshots[0]["kind"]
        sampled = sample_snapshots(snapshots, self.snapshot_limit)

        texts = await asyncio.gather(
            *(self._fetch_snapshot(s["original"], s["timestamp"]) for s in sampled),
            return_exceptions=True,
        )

        timeline: list[dict[str, Any]] = []
        parsed_list: list[dict[str, list[str]]] = []
        previous_items: set[str] | None = None

        for snap, text in zip(sampled, texts):
            if not isinstance(text, str):
                continue
            parsed = parse_content(kind, text, snap["original"])
            if parsed is None:
                continue

            items = to_items(parsed)
            added = sorted(items - previous_items) if previous_items is not None else []
            removed = sorted(previous_items - items) if previous_items is not None else []

            entry: dict[str, Any] = {
                "timestamp":   snap["timestamp"],
                "archive_url": WAYBACK_VIEW_URL.format(timestamp=snap["timestamp"], url=snap["original"]),
                "size":        len(text),
                "item_count":  len(items),
                "added":       added,
                "removed":     removed,
                "content":     parsed,
            }
            if self.include_raw:
                entry["raw"] = text[:RAW_LIMIT]

            timeline.append(entry)
            parsed_list.append(parsed)
            previous_items = items

        if not timeline:
            return None

        latest = parsed_list[-1]
        union = merge_parsed(parsed_list)
        historical_only = subtract_parsed(union, latest)

        return {
            "url":                snapshots[-1]["original"],
            "kind":               kind,
            "snapshots_total":    len(snapshots),
            "snapshots_analyzed": len(timeline),
            "first_seen":         snapshots[0]["timestamp"],
            "last_seen":          snapshots[-1]["timestamp"],
            "latest":             latest,
            "historical_only":    historical_only,
            "all_time":           union,
            "timeline":           timeline,
        }

    def _print_values(self, label: str, content: dict[str, list[str]], color: str) -> None:
        for key, values in content.items():
            self.logger.result(f"{label} {key}", f"({len(values)})", color)
            for value in values[:DISPLAY_LIMIT]:
                print(f"      {value}")
            if len(values) > DISPLAY_LIMIT:
                print(f"      ... (+{len(values) - DISPLAY_LIMIT} more)")

    def _print_entry(self, entry: dict[str, Any], index: int, total: int) -> None:
        self.logger.section(f"[{index}/{total}] {entry['kind'].upper()}  {entry['url']}")
        self.logger.result("Snapshots (unique content)", entry["snapshots_total"])
        self.logger.result("Snapshots analyzed", entry["snapshots_analyzed"])
        self.logger.result("First seen", format_timestamp(entry["first_seen"]))
        self.logger.result("Last seen", format_timestamp(entry["last_seen"]))

        latest_snapshot = entry["timeline"][-1]
        self.logger.result("Latest analyzed snapshot", format_timestamp(latest_snapshot["timestamp"]))
        self.logger.result("Archive link", latest_snapshot["archive_url"])

        print(f"\n  {Style.BRIGHT}Latest content{Style.RESET_ALL}")
        if entry["latest"]:
            self._print_values("", entry["latest"], Fore.GREEN)
        else:
            print("      (empty)")

        if entry["historical_only"]:
            print(f"\n  {Style.BRIGHT}Present in older snapshots only{Style.RESET_ALL}")
            self._print_values("", entry["historical_only"], Fore.YELLOW)

        print(f"\n  {Style.BRIGHT}Timeline{Style.RESET_ALL}")
        for snap in entry["timeline"]:
            print(
                f"    {format_timestamp(snap['timestamp'])}  "
                f"size={snap['size']:<8} items={snap['item_count']:<5} "
                f"+{len(snap['added'])} -{len(snap['removed'])}"
            )
            for item in snap["added"][:TIMELINE_EXAMPLES]:
                print(f"        {Fore.GREEN}+ {item}{Style.RESET_ALL}")
            for item in snap["removed"][:TIMELINE_EXAMPLES]:
                print(f"        {Fore.RED}- {item}{Style.RESET_ALL}")
