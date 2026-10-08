from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import List, Optional

from core.models import DnsResult, IpInfo
from core.net import Net

_DNSBL_ZONES: list[tuple[str, str, str]] = [
    ("zen.spamhaus.org",       "Spamhaus ZEN",      "ip"),
    ("bl.spamcop.net",         "SpamCop",            "ip"),
    ("dnsbl.sorbs.net",        "SORBS",              "ip"),
    ("b.barracudacentral.org", "Barracuda",          "ip"),
    ("dbl.spamhaus.org",       "Spamhaus DBL",       "domain"),
    ("multi.surbl.org",        "SURBL Multi",        "domain"),
    ("uribl.com",              "URIBL",              "domain"),
    ("hostkarma.junkemailfilter.com", "HostKarma",  "both"),
    ("psbl.surriel.com",       "PSBL",               "ip"),
    ("drone.abuse.ch",         "Abuse.ch DRONE",     "ip"),
    ("feodo.abuse.ch",         "Abuse.ch Feodo",     "ip"),
]

_LISTED_PREFIXES = ("127.0.0.", "127.0.1.", "127.0.2.", "127.0.3.")


@dataclass
class BlacklistHit:
    list_name: str
    query:     str
    response:  str
    type:      str


@dataclass
class BlacklistResult:
    domain:      str
    ips_checked: list[str]          = field(default_factory=list)
    hits:        list[BlacklistHit] = field(default_factory=list)
    checked:     list[str]          = field(default_factory=list)
    errors:      list[str]          = field(default_factory=list)
    score:       int                = 0
    risk:        str                = "clean"

    def to_dict(self) -> dict:
        return {
            "domain":      self.domain,
            "ips_checked": self.ips_checked,
            "score":       self.score,
            "risk":        self.risk,
            "hits": [
                {"list": h.list_name, "query": h.query,
                 "response": h.response, "type": h.type}
                for h in self.hits
            ],
            "checked": self.checked,
            "errors":  self.errors,
        }


def _dnsbl_query(zone: str, query: str, timeout: int) -> Optional[str]:
    fqdn = f"{query}.{zone}"
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(fqdn)
    except socket.gaierror:
        return None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def _reverse_ip(ip: str) -> Optional[str]:
    try:
        obj = ipaddress.ip_address(ip)
        if isinstance(obj, ipaddress.IPv4Address):
            return ".".join(reversed(ip.split(".")))
        exploded = obj.exploded.replace(":", "")
        return ".".join(reversed(exploded))
    except ValueError:
        return None


def _is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def check(
    net: Net,
    domain: str,
    dns: Optional[DnsResult],
    ip_infos: List[IpInfo],
    timeout: int = 8,
) -> BlacklistResult:
    result = BlacklistResult(domain=domain)
    ips: list[str] = []

    if ip_infos:
        for rec in ip_infos:
            if rec.ip and rec.ip not in ips:
                ips.append(rec.ip)
    elif dns:
        for ip in dns.a + dns.aaaa:
            if ip not in ips:
                ips.append(ip)

    result.ips_checked = ips

    tasks: list[tuple[str, str, str, str]] = []

    for zone, label, rtype in _DNSBL_ZONES:
        if rtype in ("ip", "both"):
            for ip in ips:
                if _is_ipv6(ip) and zone not in ("zen.spamhaus.org",):
                    continue
                rev = _reverse_ip(ip)
                if rev:
                    tasks.append((zone, label, rev, "ip"))
        if rtype in ("domain", "both"):
            tasks.append((zone, label, domain, "domain"))

    result.checked = sorted({label for _, label, _, _ in tasks})

    per_task_timeout = max(3, timeout // 2)

    def _run(task: tuple[str, str, str, str]) -> Optional[BlacklistHit]:
        zone, label, query, rtype = task
        resp = _dnsbl_query(zone, query, per_task_timeout)
        if resp and any(resp.startswith(p) for p in _LISTED_PREFIXES):
            return BlacklistHit(list_name=label, query=query,
                                response=resp, type=rtype)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        future_map: dict[concurrent.futures.Future, tuple] = {
            pool.submit(_run, t): t for t in tasks
        }
        done, _ = concurrent.futures.wait(
            future_map, timeout=timeout,
            return_when=concurrent.futures.ALL_COMPLETED,
        )
        for fut in done:
            task = future_map[fut]
            try:
                hit = fut.result()
                if hit:
                    result.hits.append(hit)
            except Exception as exc:
                _, label, query, _ = task
                result.errors.append(f"{label} [{query}]: {exc}")

    result.score = len(result.hits)
    if result.score == 0:
        result.risk = "clean"
    elif result.score <= 2:
        result.risk = "low"
    elif result.score <= 5:
        result.risk = "medium"
    else:
        result.risk = "high"

    return result