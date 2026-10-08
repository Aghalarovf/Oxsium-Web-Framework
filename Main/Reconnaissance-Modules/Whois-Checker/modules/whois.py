from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional

from core.config import IANA_WHOIS, RDAP_DOMAIN
from core.models import ContactInfo, PrivacyInfo, WhoisResult
from core.net import Net
from core.utils import (
    as_list,
    first,
    flatten_vcard,
    looks_privacy,
    parse_dt,
    PRIVACY_HINTS,
)


def _whois_field(raw: str, keys: List[str]) -> List[str]:
    found: List[str] = []
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if not val or val in {".", "not disclosed", "n/a"}:
            continue
        for want in keys:
            if key == want.lower() or key.endswith(" " + want.lower()):
                if val not in found:
                    found.append(val)
    return found


def _whois_block(raw: str, prefix: str) -> ContactInfo:
    mapping: Dict[str, List[str]] = {
        "name":         ["name"],
        "organization": ["organization", "organisation", "org"],
        "address":      ["street", "address", "address1", "address2"],
        "city":         ["city"],
        "state":        ["state", "state/province", "province"],
        "postal":       ["postal code", "postalcode", "zip"],
        "country":      ["country", "country code", "countrycode"],
        "phone":        ["phone", "telephone", "phone number"],
        "email":        ["email", "e-mail", "mail"],
    }
    out: Dict[str, List[str]] = {k: [] for k in mapping}
    pref = prefix.lower()

    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = re.sub(r"\s+", " ", k.strip().lower())
        val = v.strip()
        if not val or not key.startswith(pref):
            continue
        rest = key[len(pref):].strip(" :/")
        for dest, aliases in mapping.items():
            if rest in aliases or any(rest.endswith(a) for a in aliases):
                if val not in out[dest]:
                    out[dest].append(val)

    address = ", ".join(
        x for x in [
            " ".join(out["address"]),
            ", ".join(out["city"]),
            ", ".join(out["state"]),
            ", ".join(out["postal"]),
        ] if x
    )
    return ContactInfo(
        name="; ".join(out["name"]),
        organization="; ".join(out["organization"]),
        address=address,
        country="; ".join(out["country"]),
        phone="; ".join(out["phone"]),
        email="; ".join(out["email"]),
    )


def _parse_whois_raw(raw: str) -> Dict[str, Any]:
    statuses = _whois_field(raw, ["domain status", "status"])
    clean_status = []
    for s in statuses:
        token = s.split()[0] if s else s
        if token and token not in clean_status:
            clean_status.append(token)

    created = first(*_whois_field(raw, ["creation date", "created", "created on", "registered on", "registration time"]))
    updated = first(*_whois_field(raw, ["updated date", "last updated", "last modified", "modified", "changed"]))
    expires = first(*_whois_field(raw, ["registry expiry date", "registrar registration expiration date", "expiry date", "expiration date", "expires", "expire", "paid-till"]))
    registrar = first(*_whois_field(raw, ["registrar", "registrar name", "sponsoring registrar"]))
    iana_id = first(*_whois_field(raw, ["registrar iana id", "iana id"]))
    whois_server = first(*_whois_field(raw, ["registrar whois server", "whois server", "refer"]))
    ns = _whois_field(raw, ["name server", "nserver", "nameserver"])
    dnssec = first(*_whois_field(raw, ["dnssec"]))

    return {
        "created": parse_dt(created),
        "updated": parse_dt(updated),
        "expires": parse_dt(expires),
        "status": clean_status,
        "registrar": registrar,
        "registrar_iana_id": iana_id,
        "whois_server": whois_server,
        "name_servers": [n.rstrip(".").lower() for n in ns],
        "dnssec": dnssec,
        "contacts": {
            "registrant": _whois_block(raw, "registrant"),
            "admin":      _whois_block(raw, "admin") if not _whois_block(raw, "admin").is_empty() else _whois_block(raw, "administrative"),
            "tech":       _whois_block(raw, "tech") if not _whois_block(raw, "tech").is_empty() else _whois_block(raw, "technical"),
            "billing":    _whois_block(raw, "billing"),
        },
        "raw": raw,
    }


def _parse_rdap_domain(data: Dict[str, Any]) -> Dict[str, Any]:
    events: Dict[str, Optional[str]] = {}
    for ev in data.get("events") or []:
        action = (ev.get("eventAction") or "").lower()
        events[action] = parse_dt(ev.get("eventDate"))

    statuses = as_list(data.get("status"))
    registrar: Optional[str] = None
    iana_id: Optional[str] = None
    contacts: Dict[str, ContactInfo] = {
        "registrant": ContactInfo(),
        "admin":      ContactInfo(),
        "tech":       ContactInfo(),
        "billing":    ContactInfo(),
    }
    role_map = {
        "registrant":   "registrant",
        "administrative":"admin",
        "admin":        "admin",
        "technical":    "tech",
        "tech":         "tech",
        "billing":      "billing",
        "registrar":    "registrar",
    }

    for ent in data.get("entities") or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        vcard = flatten_vcard(ent.get("vcardArray"))
        handle = ent.get("handle")

        if "registrar" in roles:
            registrar = first(vcard.get("fn"), vcard.get("organization"), ent.get("fn"), handle)
            for pid in ent.get("publicIds") or []:
                if str(pid.get("type", "")).lower() in {"iana registrar id", "iana id"}:
                    iana_id = str(pid.get("identifier"))
            if not iana_id and handle and str(handle).isdigit():
                iana_id = str(handle)

        for role in roles:
            dest = role_map.get(role)
            if dest and dest != "registrar" and vcard and contacts[dest].is_empty():
                addr = vcard.get("address", "")
                contacts[dest] = ContactInfo(
                    name=vcard.get("name") or vcard.get("fn", ""),
                    organization=vcard.get("organization", ""),
                    address=addr,
                    country=addr.split(",")[-1].strip() if addr else "",
                    phone=vcard.get("phone", ""),
                    email=vcard.get("email", ""),
                )

        for sub in ent.get("entities") or []:
            sub_vcard = flatten_vcard(sub.get("vcardArray"))
            for role in [str(r).lower() for r in (sub.get("roles") or [])]:
                dest = role_map.get(role)
                if dest and dest != "registrar" and sub_vcard and contacts[dest].is_empty():
                    addr = sub_vcard.get("address", "")
                    contacts[dest] = ContactInfo(
                        name=sub_vcard.get("name") or sub_vcard.get("fn", ""),
                        organization=sub_vcard.get("organization", ""),
                        address=addr,
                        country=addr.split(",")[-1].strip() if addr else "",
                        phone=sub_vcard.get("phone", ""),
                        email=sub_vcard.get("email", ""),
                    )

    ns = []
    for item in data.get("nameservers") or []:
        ldh = item.get("ldhName") or item.get("unicodeName")
        if ldh:
            ns.append(ldh.rstrip(".").lower())

    dnssec: Optional[str] = None
    sec = data.get("secureDNS") or {}
    if isinstance(sec, dict) and "delegationSigned" in sec:
        dnssec = "signedDelegation" if sec.get("delegationSigned") else "unsigned"

    return {
        "created":          first(events.get("registration"), events.get("registered")),
        "updated":          first(events.get("last changed"), events.get("last update of rdap database")),
        "expires":          first(events.get("expiration"), events.get("expiry")),
        "status":           statuses,
        "registrar":        registrar,
        "registrar_iana_id": iana_id,
        "name_servers":     ns,
        "dnssec":           dnssec,
        "contacts":         contacts,
    }


def _merge(base: WhoisResult, patch: Dict[str, Any]) -> WhoisResult:
    if not base.created and patch.get("created"):
        base.created = patch["created"]
    if not base.updated and patch.get("updated"):
        base.updated = patch["updated"]
    if not base.expires and patch.get("expires"):
        base.expires = patch["expires"]
    if not base.registrar and patch.get("registrar"):
        base.registrar = patch["registrar"]
    if not base.registrar_iana_id and patch.get("registrar_iana_id"):
        base.registrar_iana_id = patch["registrar_iana_id"]
    if not base.dnssec and patch.get("dnssec"):
        base.dnssec = patch["dnssec"]

    seen_status = list(base.status)
    for s in as_list(patch.get("status")):
        if s not in seen_status:
            seen_status.append(s)
    base.status = seen_status

    seen_ns = list(base.name_servers)
    for ns in as_list(patch.get("name_servers")):
        ns = ns.rstrip(".").lower()
        if ns not in seen_ns:
            seen_ns.append(ns)
    base.name_servers = seen_ns

    patch_contacts = patch.get("contacts") or {}
    for role in ("registrant", "admin", "tech", "billing"):
        existing = base.contacts.get(role, ContactInfo())
        incoming = patch_contacts.get(role)
        if incoming is None:
            continue
        if isinstance(incoming, ContactInfo):
            if existing.is_empty():
                base.contacts[role] = incoming
        elif isinstance(incoming, dict):
            if existing.is_empty():
                base.contacts[role] = ContactInfo(**{k: v for k, v in incoming.items() if k in ContactInfo.__dataclass_fields__})
            else:
                for fk, fv in incoming.items():
                    if fv and not getattr(existing, fk, ""):
                        setattr(existing, fk, fv)

    if patch.get("raw"):
        base.raw = (base.raw + "\n\n" + patch["raw"]).strip()
    if patch.get("whois_server") and not getattr(base, "whois_server", None):
        base.whois_server = patch["whois_server"]

    return base


def _detect_privacy(result: WhoisResult) -> PrivacyInfo:
    blob_parts = [result.raw, result.registrar or ""]
    for c in result.contacts.values():
        for v in c.__dict__.values():
            blob_parts.append(str(v))
    blob = "\n".join(blob_parts)
    active = looks_privacy(blob)

    reasons = []
    if active:
        for h in ("redacted", "privacy", "whoisguard", "proxy", "withheld", "gdpr", "identity protect"):
            if h in blob.lower() and h not in reasons:
                reasons.append(h)

    emails = [c.email for c in result.contacts.values() if c.email]
    return PrivacyInfo(
        enabled=active,
        indicators=reasons,
        note="WHOIS privacy / redaction appears active" if active else "No obvious privacy/redaction markers",
        visible_emails=emails,
    )


def lookup(net: Net, domain: str, forced_server: Optional[str] = None) -> WhoisResult:
    result = WhoisResult(
        contacts={"registrant": ContactInfo(), "admin": ContactInfo(), "tech": ContactInfo(), "billing": ContactInfo()},
    )

    rdap_data = net.http_json(RDAP_DOMAIN.format(domain=urllib.parse.quote(domain)))
    if isinstance(rdap_data, dict) and (rdap_data.get("ldhName") or rdap_data.get("objectClassName") == "domain"):
        result = _merge(result, _parse_rdap_domain(rdap_data))
        result.sources.append("rdap")

    raw_parts: List[str] = []
    server = forced_server
    if not server:
        iana_raw = net.tcp_whois(IANA_WHOIS, domain)
        if iana_raw:
            raw_parts.append(f"; IANA\n{iana_raw}")
            refer = first(*_whois_field(iana_raw, ["whois", "refer"]))
            if refer:
                server = refer

    if server:
        raw = net.tcp_whois(server, domain)
        if raw:
            raw_parts.append(f"; {server}\n{raw}")
            parsed = _parse_whois_raw(raw)
            result = _merge(result, parsed)
            result.sources.append(f"whois:{server}")
            next_server = parsed.get("whois_server")
            if next_server and next_server.lower() not in {server.lower(), "whois.iana.org"}:
                raw2 = net.tcp_whois(next_server, domain)
                if raw2:
                    raw_parts.append(f"; {next_server}\n{raw2}")
                    result = _merge(result, _parse_whois_raw(raw2))
                    result.sources.append(f"whois:{next_server}")

    result.raw = "\n\n".join(raw_parts).strip()
    result.privacy = _detect_privacy(result)
    return result