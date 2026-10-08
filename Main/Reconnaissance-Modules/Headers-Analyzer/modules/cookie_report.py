import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from core.engine import COOKIE_MODULE_NAME, SEVERITY_ORDER
from .cookie_intel.entropy import rate_strength

MAX_VALUES_SHOWN = 5
MAX_IDS_SHOWN = 15

_DIRECTION_PREFIX = re.compile(r"^(Value )?(?:Set-Cookie|Cookie) \(")
_LENGTH_PHRASE = re.compile(r"opaque \d+-character state token")


def _normalize_finding(severity: str, header: str, detail: str) -> Tuple[str, str, str]:
    """Collapse the same informational finding seen as Set-Cookie and as request Cookie, or with a different value length."""
    if severity in ("INFO", "OK"):
        header = _DIRECTION_PREFIX.sub(lambda m: f"{m.group(1) or ''}Cookie (", header)
        detail = _LENGTH_PHRASE.sub("opaque state token", detail)
    return severity, header, detail


def _new_record(host: str, name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "host": host,
        "fingerprint": None,
        "category": None,
        "sensitive": False,
        "value_type": None,
        "layers": [],
        "decoded": None,
        "entropy": None,
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [],
        "values": {},
        "attribute_sets": [],
        "findings": {},
    }


def _merge(record: Dict[str, Any], item: Dict[str, Any], direction: str, entry_id: Any) -> None:
    for key in ("fingerprint", "category", "value_type", "decoded", "entropy"):
        if item.get(key) is not None:
            record[key] = item[key]
    record["sensitive"] = record["sensitive"] or bool(item.get("sensitive"))
    for key in ("layers", "hash_candidates", "provider_tokens"):
        for entry in item.get(key) or []:
            if entry not in record[key]:
                record[key].append(entry)
    ids = record["issued_in"] if direction == "set_cookie" else record["sent_in"]
    if entry_id not in ids:
        ids.append(entry_id)
    value = item.get("value")
    if value is not None:
        record["values"][value] = record["values"].get(value, 0) + 1
    if direction == "set_cookie":
        attributes = {
            "secure": item.get("secure"),
            "httponly": item.get("httponly"),
            "samesite": item.get("samesite"),
            "partitioned": item.get("partitioned"),
            "domain": item.get("domain"),
            "path": item.get("path"),
            "max_age": item.get("max_age"),
            "expires": item.get("expires"),
            "lifetime_seconds": item.get("lifetime_seconds"),
        }
        if attributes not in record["attribute_sets"]:
            record["attribute_sets"].append(attributes)


def build_cookie_report(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    cookies: Dict[Tuple[str, str], Dict[str, Any]] = {}
    general: Dict[Tuple[str, str, str], int] = {}

    for entry in entries:
        module = entry["modules"].get(COOKIE_MODULE_NAME)
        if not module or module.get("error"):
            continue
        meta = module.get("metadata", {}).get("cookies")
        if not meta:
            continue
        entry_host = (urlsplit(entry.get("url") or "").hostname or "").lower()
        names = set()
        for direction in ("set_cookie", "request_cookie"):
            for item in meta.get(direction, []):
                host = item.get("host") or entry_host
                record = cookies.setdefault((host, item["name"]), _new_record(host, item["name"]))
                _merge(record, item, direction, entry["id"])
                names.add(item["name"])

        for finding in module.get("findings", []):
            header = finding.get("header", "")
            severity = finding.get("severity", "INFO")
            detail = finding.get("detail", "")
            if severity == "OK" and header.startswith("Value ") and detail.startswith("Value looks like an opaque random token"):
                detail = "Value looks like an opaque random token (per-value entropy figures are listed above)"
            if header == "Cookie Inventory":
                continue
            key = _normalize_finding(severity, header, detail)
            matched = [name for name in names if f"({name})" in header]
            if matched:
                for name in matched:
                    record = cookies[(entry_host, name)]
                    record["findings"][key] = record["findings"].get(key, 0) + 1
            else:
                general[key] = general.get(key, 0) + 1

    def _findings_list(source: Dict[Tuple[str, str, str], int]) -> List[Dict[str, Any]]:
        ordered = sorted(source.items(), key=lambda pair: (SEVERITY_ORDER.get(pair[0][0], 99), pair[0][1], pair[0][2]))
        return [{"severity": s, "header": h, "detail": d, "count": n} for (s, h, d), n in ordered]

    result_cookies = []
    for (host, name), record in sorted(cookies.items()):
        item = dict(record)
        item["distinct_values"] = len(record["values"])
        item["values"] = [{"value": value, "count": count} for value, count in list(record["values"].items())[:MAX_VALUES_SHOWN]]
        item["issued_total"] = len(record["issued_in"])
        item["sent_total"] = len(record["sent_in"])
        item["issued_in"] = record["issued_in"][:MAX_IDS_SHOWN]
        item["sent_in"] = record["sent_in"][:MAX_IDS_SHOWN]
        item["findings"] = _findings_list(record["findings"])
        result_cookies.append(item)

    category_counts: Dict[str, int] = {}
    for item in result_cookies:
        label = item["category"] or "uncategorized"
        category_counts[label] = category_counts.get(label, 0) + 1

    return {"cookies": result_cookies, "general_findings": _findings_list(general), "category_counts": category_counts}


def _lifetime_text(seconds: Optional[float]) -> str:
    if seconds is None:
        return "session cookie (no Max-Age / Expires)"
    if seconds <= 0:
        return "already expired / cleared immediately"
    if seconds >= 86400:
        return f"{seconds / 86400:.1f} day(s)"
    return f"{int(seconds)} second(s)"


def _ids_text(ids: List[Any], total: Optional[int] = None) -> str:
    total = len(ids) if total is None else total
    shown = ", ".join(f"#{value}" for value in ids[:MAX_IDS_SHOWN])
    extra = total - len(ids[:MAX_IDS_SHOWN])
    return shown + (f" (+{extra} more)" if extra > 0 else "")


def _yes_no(flag: Optional[bool]) -> str:
    if flag is None:
        return "n/a"
    return "yes" if flag else "no"


def _print_rows(logger, rows: List[Tuple[str, str]]) -> None:
    for key, value in rows:
        logger.result_line(key.ljust(20), value)


def print_cookie_report(logger, report: Dict[str, Any]) -> None:
    cookies = report["cookies"]
    logger.section(f"Cookie Report - {len(cookies)} unique cookie(s)")
    if not cookies:
        logger.info("No cookies observed.")
        return
    counts = report.get("category_counts") or {}
    if counts:
        logger.info("Categories: " + ", ".join(f"{name}={number}" for name, number in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))))

    for index, cookie in enumerate(cookies, 1):
        logger.subsection(f"Cookie {index}/{len(cookies)}: {cookie['name']}  [{cookie['host']}]")
        rows: List[Tuple[str, str]] = [
            ("Fingerprint", cookie["fingerprint"] or "none (name not in signature database)"),
            ("Category", cookie["category"] or "uncategorized"),
            ("Sensitive", _yes_no(cookie["sensitive"])),
            ("Set-Cookie seen in", f"{cookie['issued_total']} response(s) {_ids_text(cookie['issued_in'], cookie['issued_total'])}".strip()),
            ("Sent in requests", f"{cookie['sent_total']} request(s) {_ids_text(cookie['sent_in'], cookie['sent_total'])}".strip()),
            ("Value type", cookie["value_type"] or "unknown"),
            ("Decoding layers", " -> ".join(cookie["layers"]) if cookie["layers"] else "none"),
            ("Decoded content", cookie["decoded"] or "none"),
        ]
        entropy = cookie["entropy"]
        if entropy:
            rows.extend([
                ("Length", f"{entropy['length']} chars"),
                ("Charset", entropy["charset"]),
                ("Shannon entropy", f"{entropy['shannon_bits_per_char']} bits/char"),
                ("Uniformity", str(entropy["uniformity"])),
                ("Estimated entropy", f"{entropy['estimated_bits']} bits"),
                ("Patterns", ", ".join(entropy["patterns"]) if entropy["patterns"] else "none"),
                ("Strength rating", rate_strength(entropy)),
            ])
        rows.append(("Hash candidates", ", ".join(cookie["hash_candidates"]) if cookie["hash_candidates"] else "none"))
        rows.append(("Provider tokens", ", ".join(cookie["provider_tokens"]) if cookie["provider_tokens"] else "none"))
        _print_rows(logger, rows)

        for number, attributes in enumerate(cookie["attribute_sets"], 1):
            label = "Attributes" if len(cookie["attribute_sets"]) == 1 else f"Attributes (variant {number})"
            _print_rows(logger, [
                (label, ""),
                ("  Secure", _yes_no(attributes["secure"])),
                ("  HttpOnly", _yes_no(attributes["httponly"])),
                ("  SameSite", attributes["samesite"] or "not set"),
                ("  Partitioned", _yes_no(attributes["partitioned"])),
                ("  Domain", attributes["domain"] or "not set (host-only)"),
                ("  Path", attributes["path"] or "not set"),
                ("  Max-Age", attributes["max_age"] or "not set"),
                ("  Expires", attributes["expires"] or "not set"),
                ("  Lifetime", _lifetime_text(attributes["lifetime_seconds"])),
            ])
        if not cookie["attribute_sets"]:
            logger.result_line("Attributes".ljust(20), "not available (cookie only observed in request headers)")

        values = cookie["values"]
        distinct = cookie["distinct_values"]
        logger.result_line("Distinct values".ljust(20), str(distinct))
        for number, item in enumerate(values[:MAX_VALUES_SHOWN], 1):
            logger.result_line(f"Value {number} (x{item['count']})".ljust(20), item["value"] if item["value"] != "" else "<empty>")
        if distinct > len(values):
            logger.result_line("".ljust(20), f"... and {distinct - len(values)} more distinct value(s)")

        print("")
        logger.result_line("Findings".ljust(20), str(len(cookie["findings"])))
        for finding in cookie["findings"]:
            detail = finding["detail"] if finding["count"] == 1 else f"{finding['detail']} (x{finding['count']})"
            logger.finding(finding["severity"], finding["header"], detail, force=True)

    if report["general_findings"]:
        logger.subsection("General cookie findings")
        for finding in report["general_findings"]:
            detail = finding["detail"] if finding["count"] == 1 else f"{finding['detail']} (x{finding['count']})"
            logger.finding(finding["severity"], finding["header"], detail, force=True)