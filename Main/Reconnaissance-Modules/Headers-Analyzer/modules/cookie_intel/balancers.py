"""Decoders for load-balancer / CDN persistence cookies that leak backend topology."""

import ipaddress
import re
import socket
import struct
from typing import Any, Dict, List, Optional

_BIGIP_IPV4 = re.compile(r"^(\d{1,10})\.(\d{1,5})\.(\d+)$")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_INTERNAL_HOST_RE = re.compile(r"\b[a-zA-Z0-9-]+\.(?:internal|corp|local|intranet|lan)\b", re.IGNORECASE)


def _scope_for(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "internal-hostname"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    return "public"


def decode_bigip(value: str) -> Optional[Dict[str, Any]]:
    """Decode an F5 BIG-IP persistence cookie value: <uint32-le-ip>.<swapped-port>.<route-domain>."""
    match = _BIGIP_IPV4.match(value.strip())
    if not match:
        return None
    raw_ip, raw_port, raw_route = match.groups()
    try:
        n = int(raw_ip)
        p = int(raw_port)
        if n > 0xFFFFFFFF or p > 0xFFFF:
            return None
        address = socket.inet_ntoa(struct.pack("<I", n))
        port = struct.unpack(">H", struct.pack("<H", p))[0]
    except (struct.error, OSError, ValueError):
        return None
    route_domain = None
    if raw_route and raw_route != "0000":
        try:
            route_domain = int(raw_route)
        except ValueError:
            route_domain = None
    return {
        "address": address,
        "port": port,
        "scope": _scope_for(address),
        "route_domain": route_domain,
    }


def find_addresses(text: str) -> List[Dict[str, str]]:
    """Find IPv4 addresses or obvious internal hostnames embedded in a decoded cookie value."""
    found: List[Dict[str, str]] = []
    seen = set()
    for match in _IPV4_RE.findall(text or ""):
        if match in seen:
            continue
        seen.add(match)
        found.append({"address": match, "scope": _scope_for(match)})
    for match in _INTERNAL_HOST_RE.findall(text or ""):
        if match in seen:
            continue
        seen.add(match)
        found.append({"address": match, "scope": "internal-hostname"})
    return found
