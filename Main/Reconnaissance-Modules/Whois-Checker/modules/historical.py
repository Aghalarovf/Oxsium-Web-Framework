from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

from core.net import Net
from core.utils import parse_dt

_RDAP_DOMAIN = "https://rdap.org/domain/{domain}"

_CDX_FIRST = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&fl=timestamp,statuscode,original"
    "&filter=statuscode:200&limit=1&fastLatest=true"
)
_CDX_LATEST = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&fl=timestamp,statuscode,original"
    "&filter=statuscode:200&limit=1&fastLatest=true&sort=reverse"
)

_WHOISFREAKS = (
    "https://whoisfreaks.com/v1.0/whois/history"
    "?whois=live&domainName={domain}"
)


@dataclass
class WhoisSnapshot:
    date:         Optional[str] = None
    registrar:    Optional[str] = None
    created:      Optional[str] = None
    expires:      Optional[str] = None
    status:       list[str]     = field(default_factory=list)
    name_servers: list[str]     = field(default_factory=list)
    source:       str           = ""

    def to_dict(self) -> dict:
        return {
            "date":         self.date,
            "registrar":    self.registrar,
            "created":      self.created,
            "expires":      self.expires,
            "status":       self.status,
            "name_servers": self.name_servers,
            "source":       self.source,
        }


@dataclass
class ArchiveInfo:
    first_seen: Optional[str] = None
    last_seen:  Optional[str] = None
    source:     str           = ""

    def to_dict(self) -> dict:
        return {
            "first_seen": self.first_seen,
            "last_seen":  self.last_seen,
            "source":     self.source,
        }


@dataclass
class HistoricalResult:
    domain:      str
    rdap_events: list[dict]           = field(default_factory=list)
    snapshots:   list[WhoisSnapshot]  = field(default_factory=list)
    archive:     Optional[ArchiveInfo] = None
    errors:      list[str]            = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain":      self.domain,
            "rdap_events": self.rdap_events,
            "snapshots":   [s.to_dict() for s in self.snapshots],
            "archive":     self.archive.to_dict() if self.archive else None,
            "errors":      self.errors,
        }


def _ts_to_date(ts: str) -> Optional[str]:
    if not ts or len(ts) < 8:
        return None
    try:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        return ts


def _cdx_timestamp(raw: Any) -> Optional[str]:
    if not isinstance(raw, list) or len(raw) < 2:
        return None
    row = raw[1]
    if isinstance(row, list) and row:
        return _ts_to_date(str(row[0]))
    return None


def _rdap_events(data: dict) -> list[dict]:
    events = []
    for ev in data.get("events") or []:
        action = ev.get("eventAction", "")
        date   = parse_dt(ev.get("eventDate", ""))
        if action and date:
            events.append({"action": action, "date": date})
    return events


def _rdap_snapshot(data: dict) -> Optional[WhoisSnapshot]:
    snap = WhoisSnapshot(source="rdap")

    events = {
        ev.get("eventAction", ""): parse_dt(ev.get("eventDate", ""))
        for ev in (data.get("events") or [])
    }
    snap.created = events.get("registration") or events.get("registered")
    snap.expires = events.get("expiration")   or events.get("expires")
    snap.date    = (
        events.get("last changed")
        or events.get("last update of RDAP database")
        or snap.created
    )
    snap.status = [str(s) for s in (data.get("status") or [])]

    nss = []
    for ns_obj in (data.get("nameservers") or []):
        name = ns_obj.get("ldhName") or ns_obj.get("unicodeName") or ""
        if name:
            nss.append(name.lower())
    snap.name_servers = nss

    for ent in (data.get("entities") or []):
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" not in roles:
            continue
        vcard = ent.get("vcardArray") or []
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in (vcard[1] if isinstance(vcard[1], list) else []):
                if isinstance(item, list) and item and str(item[0]).lower() == "fn":
                    snap.registrar = str(item[3]) if len(item) > 3 else None
                    break
        if not snap.registrar:
            snap.registrar = ent.get("handle") or None
        break

    return snap if (snap.created or snap.expires or snap.name_servers) else None


def _parse_whoisfreaks(data: Any) -> list[WhoisSnapshot]:
    snapshots = []
    records = data if isinstance(data, list) else (data.get("whois_records") or [])
    for rec in records:
        if not isinstance(rec, dict):
            continue
        snap = WhoisSnapshot(source="whoisfreaks")
        snap.date         = parse_dt(rec.get("query_time") or rec.get("updated_date", ""))
        snap.registrar    = rec.get("registrar_name") or rec.get("registrar")
        snap.created      = parse_dt(rec.get("create_date") or rec.get("creation_date", ""))
        snap.expires      = parse_dt(rec.get("expiry_date") or rec.get("expiration_date", ""))
        snap.status       = [
            s.strip() for s in str(rec.get("domain_status", "")).split(",") if s.strip()
        ]
        snap.name_servers = [
            n.lower().strip() for n in (rec.get("name_servers") or []) if n
        ]
        if snap.registrar or snap.created or snap.name_servers:
            snapshots.append(snap)
    return snapshots


def lookup(net: Net, domain: str) -> HistoricalResult:
    result = HistoricalResult(domain=domain)
    enc    = urllib.parse.quote(domain)

    try:
        data = net.http_json(_RDAP_DOMAIN.format(domain=enc))
        if isinstance(data, dict):
            result.rdap_events = _rdap_events(data)
            snap = _rdap_snapshot(data)
            if snap:
                result.snapshots.append(snap)
    except Exception as exc:
        result.errors.append(f"rdap: {exc}")

    try:
        first_raw  = net.http_json(_CDX_FIRST.format(domain=enc))
        latest_raw = net.http_json(_CDX_LATEST.format(domain=enc))

        archive = ArchiveInfo(source="Wayback Machine (CDX)")
        archive.first_seen = _cdx_timestamp(first_raw)
        archive.last_seen  = _cdx_timestamp(latest_raw)

        if archive.first_seen or archive.last_seen:
            result.archive = archive
    except Exception as exc:
        result.errors.append(f"wayback cdx: {exc}")

    try:
        data = net.http_json(_WHOISFREAKS.format(domain=enc))
        if isinstance(data, (dict, list)):
            snaps = _parse_whoisfreaks(data)
            existing = {s.date for s in result.snapshots}
            for s in snaps:
                if s.date not in existing:
                    result.snapshots.append(s)
    except Exception as exc:
        result.errors.append(f"whoisfreaks: {exc}")

    result.snapshots.sort(key=lambda s: s.date or "", reverse=True)

    return result