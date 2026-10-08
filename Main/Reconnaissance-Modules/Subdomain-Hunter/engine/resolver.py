from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

import dns.resolver
import dns.exception

from core import HostInfo


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _cname_chain(hostname: str) -> list[str]:
    """
    Return the full CNAME chain for *hostname*, not including the hostname
    itself.  Returns [] if there is no CNAME or on any DNS error.
    """
    chain: list[str] = []
    current = hostname
    seen: set[str] = {current}
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        for _ in range(10):   # guard against infinite loops
            try:
                ans = resolver.resolve(current, "CNAME")
                target = str(ans[0].target).rstrip(".")
                if target in seen:
                    break
                chain.append(target)
                seen.add(target)
                current = target
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
    except Exception:
        pass
    return chain


def _resolve_one(hostname: str) -> tuple[str, list[str], Optional[str], list[str]]:
    """
    Returns (hostname, ips, dns_error, cname_chain).
    """
    chain = _cname_chain(hostname)
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted(
            {item[4][0] for item in infos},
            key=lambda ip: (":" in ip, ip),
        )
        if not ips:
            return hostname, [], "NXDOMAIN", chain
        return hostname, ips, None, chain
    except socket.gaierror as exc:
        errno = getattr(exc, "errno", None)
        if errno in (
            socket.EAI_NONAME,
            getattr(socket, "EAI_NODATA", -5),
            getattr(socket, "EAI_AGAIN", -3),
        ):
            err = "SERVFAIL" if errno == getattr(socket, "EAI_AGAIN", -3) else "NXDOMAIN"
            return hostname, [], err, chain
        return hostname, [], "DNS", chain
    except OSError:
        return hostname, [], "DNS", chain


# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------

def detect_wildcard(domain: str) -> Optional[str]:
    """
    Probe a random subdomain.  If it resolves, *domain* has a wildcard DNS
    record.  Returns the wildcard IP (first one) so callers can filter it out,
    or None if no wildcard exists.
    """
    probe = "".join(random.choices(string.ascii_lowercase, k=16)) + "." + domain
    try:
        infos = socket.getaddrinfo(probe, None)
        ips = [item[4][0] for item in infos]
        return ips[0] if ips else None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_hosts(
    subdomains: Iterable[str],
    *,
    workers: int = 20,
    wildcard_ip: Optional[str] = None,
) -> dict[str, HostInfo]:
    """
    Resolve all subdomains concurrently.  If *wildcard_ip* is given, any host
    that resolves **only** to that IP is marked as WILDCARD instead.
    """
    subs = list(subdomains)
    hosts: dict[str, HostInfo] = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for name, ips, err, chain in pool.map(_resolve_one, subs):
            # Wildcard filter
            if wildcard_ip and ips and all(ip == wildcard_ip for ip in ips):
                hosts[name] = HostInfo(
                    subdomain=name,
                    ips=[],
                    dns_error="WILDCARD",
                    cname_chain=chain,
                )
            else:
                hosts[name] = HostInfo(
                    subdomain=name,
                    ips=ips,
                    dns_error=err,
                    cname_chain=chain,
                )

    return hosts