from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from .config import PRIVACY_HINTS


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def idna(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    if domain.startswith("*."):
        domain = domain[2:]
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


_MULTI_LABEL_TLDS = {
    "co", "com", "net", "org", "gov", "edu", "ac", "mil",
    "ne", "or", "gr", "sch", "nhs", "police", "mod",
}

def tld_of(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return domain
    if len(parts) >= 3 and parts[-2] in _MULTI_LABEL_TLDS:
        return ".".join(parts[-2:])
    return parts[-1]


def first(*vals: Any) -> Optional[Any]:
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        if isinstance(v, (list, tuple, dict)) and not v:
            continue
        return v
    return None


def as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        out: list[str] = []
        for i in v:
            s = str(i).strip()
            if s and s not in out:
                out.append(s)
        return out
    s = str(v).strip()
    return [s] if s else []


def parse_dt(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = str(value).strip()
    value = re.sub(r"\s*\(.*\)$", "", value)
    fmts = (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d-%b-%Y %H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%Y.%m.%d",
        "%d.%m.%Y",
        "%m/%d/%Y",
    )
    raw = value.replace(" UTC", "Z").replace("Z", "+0000")
    raw2 = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", raw)
    for candidate in (value, raw, raw2, value[:19], value[:10]):
        for fmt in fmts:
            try:
                dt = datetime.strptime(candidate, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                continue
    return value


def days_until(dt_str: Optional[str]) -> Optional[int]:
    if not dt_str:
        return None
    try:
        dt = datetime.strptime(dt_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return (dt - now_utc()).days
    except Exception:
        return None


def looks_privacy(text: str) -> bool:
    blob = text.lower()
    return any(h in blob for h in PRIVACY_HINTS)


def parse_asn(text: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    if not text:
        return None, None
    m = re.search(r"AS(\d+)\s*(.*)$", text.strip(), re.I)
    if m:
        name = m.group(2).strip() or None
        return int(m.group(1)), name
    if text.strip().isdigit():
        return int(text.strip()), None
    return None, text.strip()


def flatten_vcard(vcard: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(vcard, list):
        return out
    for item in vcard:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = str(item[0]).lower()
        val = item[3]
        if key == "fn" and isinstance(val, str):
            out["name"] = val
        elif key == "org":
            if isinstance(val, list) and val:
                out["organization"] = str(val[0])
            elif isinstance(val, str):
                out["organization"] = val
        elif key == "email" and isinstance(val, str):
            out["email"] = val
        elif key == "tel":
            out["phone"] = str(val)
        elif key == "adr" and isinstance(val, list):
            parts = [str(x) for x in val if x]
            if parts:
                out["address"] = ", ".join(parts)
    return out