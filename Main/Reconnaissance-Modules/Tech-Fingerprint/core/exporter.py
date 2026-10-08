import json
from datetime import datetime
from core.logger import get_logger

logger = get_logger()

OUTPUT_FILE = "tech_fingerprint.json"

ALLOWED_CATEGORIES = {
    # CMS
    "cms", "blogs",
    # JS Frameworks
    "javascript frameworks",
    # Web Frameworks
    "web frameworks",
    # Web Servers
    "web servers", "web server", "reverse proxies",
    # Security
    "security", "security header", "security headers",
    # Databases
    "databases",
    # OS
    "operating systems",
    # Authentication
    "authentication",
    # CDN
    "cdn",
    # Programming Languages
    "programming languages",
    # PaaS / Hosting
    "paas", "hosting",
}


def _is_allowed(tech: dict) -> bool:
    cats = tech.get("categories") or []
    if isinstance(cats, str):
        cats = [cats]
    cat = tech.get("category")
    if cat:
        cats = list(cats) + [cat]
    return any(c.lower() in ALLOWED_CATEGORIES for c in cats)


def _filter_results(results: dict) -> dict:
    filtered = {}
    for module_name, data in results.items():
        if "error" in data:
            filtered[module_name] = data
            continue

        if "technologies" in data:
            kept = [t for t in data["technologies"] if _is_allowed(t)]
            removed = len(data["technologies"]) - len(kept)
            if removed:
                logger.info(f"{module_name}: filtered out {removed} non-pentest categories")
            filtered[module_name] = {**data, "technologies": kept}
        else:
            filtered[module_name] = data

    return filtered


def export(domain: str, results: dict, output_path: str = None) -> str:
    import os
    out = output_path if output_path else OUTPUT_FILE

    # Qovluq mövcud deyilsə yarat
    out_dir = os.path.dirname(os.path.abspath(out))
    os.makedirs(out_dir, exist_ok=True)

    payload = {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "results": _filter_results(results),
    }

    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info(f"Results saved to {out}")
    return out