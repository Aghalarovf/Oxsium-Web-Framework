from core.logger import get_logger
from core.requester import fetch
import re

logger = get_logger()

RETIRE_JS_REPO = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"

_db_cache = None


def _load_db() -> dict:
    global _db_cache
    if _db_cache:
        return _db_cache

    logger.info("Fetching Retire.js vulnerability database...")
    result = fetch(RETIRE_JS_REPO)
    if not result["body"]:
        raise RuntimeError("Failed to load Retire.js database")

    import json
    _db_cache = json.loads(result["body"])
    logger.info(f"Loaded {len(_db_cache)} entries from Retire.js database")
    return _db_cache


def _parse_version(v: str) -> tuple:
    parts = re.split(r"[-+]", str(v))[0]
    nums = []
    for p in parts.split("."):
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums)


def _version_in_range(version: str, at_or_above: str, below: str) -> bool:
    v = _parse_version(version)
    lo = _parse_version(at_or_above) if at_or_above else (0, 0, 0, 0)
    hi = _parse_version(below) if below else (9999, 0, 0, 0)
    return lo <= v < hi


def _extract_scripts(html: str, base_url: str) -> list:
    pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    seen = set()
    scripts = []
    for match in pattern.findall(html):
        if match.startswith("http"):
            url = match
        elif match.startswith("//"):
            url = "https:" + match
        elif match.startswith("/"):
            url = base_url.rstrip("/") + match
        else:
            continue
        if url not in seen:
            seen.add(url)
            scripts.append(url)
    return scripts


def _check_library(name: str, content: str, db: dict) -> dict | None:
    if name not in db:
        return None

    entry = db[name]
    extractors = entry.get("extractors", {})

    version = None
    for pattern in extractors.get("filecontent", []):
        try:
            match = re.search(pattern.replace("§§version§§", r"([\d.]+(?:[-+][^\s,;\"']+)?)"), content)
            if match:
                version = match.group(1)
                break
        except re.error:
            continue

    if not version:
        return None

    vulnerabilities = []
    for vuln in entry.get("vulnerabilities", []):
        at_or_above = vuln.get("atOrAbove", "0")
        below = vuln.get("below", "9999")

        if not _version_in_range(version, at_or_above, below):
            continue

        vulnerabilities.append({
            "severity": vuln.get("severity", "unknown"),
            "identifiers": vuln.get("identifiers", {}),
            "info": vuln.get("info", []),
            "affected_range": f">={at_or_above} <{below}",
        })

    return {
        "library": name,
        "version": version,
        "vulnerabilities": vulnerabilities,
    }


class RetireJS:
    def run(self, domain: str) -> dict:
        url = domain if domain.startswith("http") else f"https://{domain}"
        db = _load_db()

        logger.info(f"Fetching page: {url}")
        page = fetch(url)
        scripts = _extract_scripts(page["body"], url)
        logger.info(f"Found {len(scripts)} external scripts")

        findings = []
        seen_results: set[tuple] = set()

        for script_url in scripts:
            logger.info(f"Checking: {script_url}")
            response = fetch(script_url)
            if not response["body"]:
                continue

            for lib_name in db:
                result = _check_library(lib_name, response["body"], db)
                if not result:
                    continue

                dedup_key = (result["library"], result["version"], script_url)
                if dedup_key in seen_results:
                    continue
                seen_results.add(dedup_key)

                result["script_url"] = script_url
                findings.append(result)
                vuln_count = len(result["vulnerabilities"])
                if vuln_count:
                    logger.info(
                        f"Detected {result['library']} v{result['version']} "
                        f"— {vuln_count} vulnerabilit{'y' if vuln_count == 1 else 'ies'}"
                    )
                else:
                    logger.info(f"Detected {result['library']} v{result['version']} — clean")

        return {
            "scripts_checked": len(scripts),
            "findings": findings,
        }