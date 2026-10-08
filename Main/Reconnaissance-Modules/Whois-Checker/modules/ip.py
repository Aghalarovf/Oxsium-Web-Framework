from __future__ import annotations

import socket
import urllib.parse
from typing import Any, Dict, List

from core.config import HOSTING_HINTS, IP_API, IPWHO, RDAP_IP
from core.models import IpInfo
from core.net import Net
from core.utils import first, flatten_vcard, parse_asn


def lookup(net: Net, ip: str) -> IpInfo:
    info = IpInfo(ip=ip)

    # PTR record
    try:
        info.ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # ip-api.com
    api = net.http_json(IP_API.format(ip=urllib.parse.quote(ip)))
    if isinstance(api, dict) and api.get("status") == "success":
        info.source.append("ip-api")
        info.country = api.get("country")
        info.country_code = api.get("countryCode")
        info.city = api.get("city")
        info.region = api.get("regionName")
        info.lat = api.get("lat")
        info.lon = api.get("lon")
        info.timezone = api.get("timezone")
        info.isp = api.get("isp")
        info.org = api.get("org")
        asn, as_name = parse_asn(api.get("as"))
        info.asn = asn
        info.as_name = first(api.get("asname"), as_name)
        info.hosting = bool(api.get("hosting"))
        info.proxy_or_vpn = bool(api.get("proxy"))
        info.mobile = bool(api.get("mobile"))

    # ipwho.is fallback
    if info.asn is None or info.city is None:
        who = net.http_json(IPWHO.format(ip=urllib.parse.quote(ip)))
        if isinstance(who, dict) and who.get("success") is not False:
            info.source.append("ipwho.is")
            info.country = first(info.country, who.get("country"))
            info.country_code = first(info.country_code, who.get("country_code"))
            info.city = first(info.city, who.get("city"))
            info.region = first(info.region, who.get("region"))
            info.lat = first(info.lat, who.get("latitude"))
            info.lon = first(info.lon, who.get("longitude"))
            tz = who.get("timezone")
            info.timezone = first(
                info.timezone,
                tz.get("id") if isinstance(tz, dict) else tz,
            )
            conn = who.get("connection") or {}
            info.isp = first(info.isp, conn.get("isp"), who.get("isp"))
            info.org = first(info.org, conn.get("org"), who.get("org"))
            if info.asn is None:
                info.asn = conn.get("asn")
            info.as_name = first(info.as_name, conn.get("org"))

    # RDAP
    rdap = net.http_json(RDAP_IP.format(ip=urllib.parse.quote(ip)))
    if isinstance(rdap, dict):
        info.source.append("rdap")
        info.rdap_country = rdap.get("country")
        for cidr in rdap.get("cidr0_cidrs") or []:
            v4 = cidr.get("v4prefix")
            v6 = cidr.get("v6prefix")
            if v4 and not info.cidr:
                info.cidr = f"{v4}/{cidr.get('length')}"
            elif v6 and not info.cidr:
                info.cidr = f"{v6}/{cidr.get('length')}"
        if rdap.get("startAddress") and rdap.get("endAddress"):
            info.rdap_range = f"{rdap['startAddress']} - {rdap['endAddress']}"
        for ent in rdap.get("entities") or []:
            vcard = flatten_vcard(ent.get("vcardArray"))
            roles = [str(r).lower() for r in (ent.get("roles") or [])]
            if "registrant" in roles or not info.org:
                info.org = first(info.org, vcard.get("organization"), vcard.get("name"))
        remarks: List[str] = []
        for r in rdap.get("remarks") or []:
            remarks.extend(r.get("description") or [])
        if remarks:
            info.rdap_remarks = remarks[:3]

    # Determine usage type
    blob = " ".join(
        str(x).lower()
        for x in (info.isp, info.org, info.as_name, info.ptr)
        if x
    )
    usage = "unknown"
    if info.mobile:
        usage = "mobile"
    elif info.hosting is True or any(h in blob for h in HOSTING_HINTS):
        usage = "datacenter / hosting"
        info.hosting = True
    elif info.hosting is False and not any(h in blob for h in HOSTING_HINTS):
        usage = "residential / isp"
    elif info.isp and not any(h in blob for h in HOSTING_HINTS):
        usage = "likely residential / isp"
    if info.proxy_or_vpn:
        usage += " (proxy/vpn flagged)"
    info.usage_type = usage

    return info