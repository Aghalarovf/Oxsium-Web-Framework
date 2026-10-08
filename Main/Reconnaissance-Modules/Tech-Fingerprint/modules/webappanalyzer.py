import re
import json
import urllib.request
from bs4 import BeautifulSoup
from core.logger import get_logger
from core.requester import fetch

logger = get_logger()

TECH_BASE_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json"
CATEGORIES_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json"
TECH_FILES = list("abcdefghijklmnopqrstuvwxyz") + ["_"]

_db_cache = None
_cat_cache = None


def _load_categories() -> dict:
    global _cat_cache
    if _cat_cache:
        return _cat_cache
    with urllib.request.urlopen(CATEGORIES_URL, timeout=10) as r:
        _cat_cache = json.loads(r.read().decode())
    return _cat_cache


def _load_db() -> dict:
    global _db_cache
    if _db_cache:
        return _db_cache

    logger.info("Loading enthec/webappanalyzer technology database...")
    db = {}
    for char in TECH_FILES:
        url = TECH_BASE_URL.format(char)
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                db.update(json.loads(r.read().decode()))
        except Exception as e:
            logger.warning(f"Failed to load tech file '{char}': {e}")

    _db_cache = db
    logger.info(f"Loaded {len(db)} technology fingerprints")
    return db


def _to_list(val) -> list:
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _parse_pattern(raw: str) -> tuple[str, str]:
    parts = raw.split("\\;")
    pattern = parts[0]
    version_tpl = ""
    for part in parts[1:]:
        if part.startswith("version:"):
            version_tpl = part[len("version:"):]
    return pattern, version_tpl


def _extract_version(match: re.Match, version_tpl: str) -> str:
    if not version_tpl or not match:
        return ""
    result = version_tpl
    for i, group in enumerate(match.groups(), start=1):
        result = result.replace(f"\\{i}", group or "")
    return result.strip()


def _match_patterns(patterns: list[str], text: str) -> tuple[bool, str]:
    for raw in patterns:
        pattern, version_tpl = _parse_pattern(raw)
        try:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return True, _extract_version(m, version_tpl)
        except re.error:
            pass
    return False, ""


def _analyze(page: dict, db: dict, categories: dict) -> list:
    html = page.get("body", "")
    headers = {k.lower(): v for k, v in page.get("headers", {}).items()}
    url = page.get("url", "")

    soup = BeautifulSoup(html, "html.parser")
    meta_tags = {
        tag.get("name", "").lower(): tag.get("content", "")
        for tag in soup.find_all("meta")
        if tag.get("name")
    }
    script_srcs = " ".join(
        tag.get("src", "") for tag in soup.find_all("script") if tag.get("src")
    )
    cookies_header = headers.get("set-cookie", "")

    results = []

    for name, tech in db.items():
        matched = False
        version = ""

        for pattern in _to_list(tech.get("html")):
            ok, v = _match_patterns([pattern], html)
            if ok:
                matched, version = True, v or version
                break

        if not matched:
            for pattern in _to_list(tech.get("scriptSrc")):
                ok, v = _match_patterns([pattern], script_srcs)
                if ok:
                    matched, version = True, v or version
                    break

        if not matched:
            for pattern in _to_list(tech.get("scripts")):
                ok, v = _match_patterns([pattern], html)
                if ok:
                    matched, version = True, v or version
                    break

        if not matched:
            for header_name, pattern in (tech.get("headers") or {}).items():
                header_val = headers.get(header_name.lower(), "")
                if header_val:
                    ok, v = _match_patterns([pattern], header_val)
                    if ok:
                        matched, version = True, v or version
                        break

        if not matched:
            for meta_name, pattern in (tech.get("meta") or {}).items():
                meta_val = meta_tags.get(meta_name.lower(), "")
                if meta_val:
                    ok, v = _match_patterns([pattern], meta_val)
                    if ok:
                        matched, version = True, v or version
                        break

        if not matched:
            for pattern in _to_list(tech.get("url")):
                ok, v = _match_patterns([pattern], url)
                if ok:
                    matched, version = True, v or version
                    break

        if not matched:
            for cookie_name, pattern in (tech.get("cookies") or {}).items():
                if cookie_name.lower() in cookies_header.lower():
                    ok, v = _match_patterns([pattern or ""], cookies_header)
                    if ok:
                        matched, version = True, v or version
                        break

        if matched:
            cat_ids = _to_list(tech.get("cats"))
            cat_names = [
                categories.get(str(cid), {}).get("name", str(cid))
                for cid in cat_ids
            ]
            results.append({
                "name": name,
                "version": version,
                "categories": cat_names,
                "website": tech.get("website", ""),
            })

    return sorted(results, key=lambda x: x["name"].lower())


class WebAppAnalyzer:
    def run(self, domain: str) -> dict:
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            import subprocess, sys
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "beautifulsoup4", "lxml", "-q", "--break-system-packages"],
                capture_output=True
            )

        url = domain if domain.startswith("http") else f"https://{domain}"
        logger.info(f"Fetching page: {url}")

        page = fetch(url)
        if not page.get("body"):
            return {"error": f"Failed to fetch page: {url}"}

        try:
            db = _load_db()
            categories = _load_categories()
        except Exception as e:
            return {"error": f"Failed to load technology database: {e}"}

        technologies = _analyze(page, db, categories)
        logger.info(f"Detected {len(technologies)} technologies on {url}")
        return {"technologies": technologies}