from __future__ import annotations

import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from core.models import DnsResult, IpInfo
from core.net import Net

_HT_REVERSE_NS = "https://api.hackertarget.com/reversens/?q={ns}"
_HT_REVERSE_IP = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
_BGPVIEW_ASN   = "https://api.bgpview.io/asn/{asn}/prefixes"

_RATE_LIMIT_PATTERNS = (
    "error: API count exceeded", "error: access denied",
    "<!DOCTYPE", "<html",
)

_PRIVACY_EMAIL_HINTS = (
    "please query", "rdds service", "registrar of record",
    "contact the registrant", "whoisproxy", "privacyproxy",
    "domainsbyproxy", "domains by proxy", "contactprivacy",
    "whoisguard", "anonymize", "redacted",
)


@dataclass
class RelatedDomain:
    domain: str
    pivot:  str
    value:  str
    source: str

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "pivot":  self.pivot,
            "value":  self.value,
            "source": self.source,
        }


@dataclass
class CrossSearchResult:
    domain:           str
    pivots_used:      list[str]           = field(default_factory=list)
    related_domains:  list[RelatedDomain] = field(default_factory=list)
    registrant_email: Optional[str]       = None
    registrant_org:   Optional[str]       = None
    nameservers:      list[str]           = field(default_factory=list)
    ips_pivoted:      list[str]           = field(default_factory=list)
    errors:           list[str]           = field(default_factory=list)

    def to_dict(self) -> dict:
        seen: set[str] = set()
        unique: list[dict] = []
        for rd in self.related_domains:
            if rd.domain not in seen and rd.domain != self.domain:
                seen.add(rd.domain)
                unique.append(rd.to_dict())
        return {
            "domain":           self.domain,
            "pivots_used":      self.pivots_used,
            "registrant_email": self.registrant_email,
            "registrant_org":   self.registrant_org,
            "nameservers":      self.nameservers,
            "ips_pivoted":      self.ips_pivoted,
            "related_count":    len(unique),
            "related_domains":  unique[:200],
            "errors":           self.errors,
        }


_DOMAIN_RE = re.compile(r"(?:[a-z0-9\-]+\.)+[a-z]{2,}", re.IGNORECASE)


def _is_privacy_email(email: Optional[str]) -> bool:
    if not email:
        return True
    low = email.lower()
    return any(hint in low for hint in _PRIVACY_EMAIL_HINTS)


def _fetch_text(net: Net, url: str) -> str:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": net.ua, "Accept": "text/plain, */*"},
        )
        handlers: list = []
        if net.proxy and not net._is_socks():
            handlers.append(
                urllib.request.ProxyHandler({"http": net.proxy, "https": net.proxy})
            )
        elif not net.proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=net.timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as exc:
        net.log(f"fetch_text {url}: {exc}")
        return ""


def _parse_ht_text(text: str) -> list[str]:
    if not text or any(p in text for p in _RATE_LIMIT_PATTERNS):
        return []
    domains: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if "," in line:
            line = line.split(",")[-1].strip()
        if _DOMAIN_RE.fullmatch(line):
            domains.append(line.lower())
    return domains


def _parse_rapiddns_json(data) -> list[str]:
    if not isinstance(data, (list, dict)):
        return []
    items = data if isinstance(data, list) else data.get("data") or []
    domains: list[str] = []
    for item in items:
        if isinstance(item, dict):
            d = item.get("domain") or item.get("host") or ""
            if d:
                domains.append(d.lower().strip("."))
        elif isinstance(item, str) and _DOMAIN_RE.fullmatch(item):
            domains.append(item.lower())
    return domains


def _pivot_ns(net: Net, ns: str, result: CrossSearchResult) -> None:
    ns = ns.rstrip(".")

    url = _HT_REVERSE_NS.format(ns=urllib.parse.quote(ns))
    text = _fetch_text(net, url)
    domains = _parse_ht_text(text)
    for d in domains:
        result.related_domains.append(
            RelatedDomain(domain=d, pivot="nameserver", value=ns, source="hackertarget")
        )
    if domains and f"NS:{ns}" not in result.pivots_used:
        result.pivots_used.append(f"NS:{ns}")

    try:
        rdns_url = f"https://rapiddns.io/ns/{urllib.parse.quote(ns)}?full=1&json=1"
        data = net.http_json(rdns_url)
        if data:
            for d in _parse_rapiddns_json(data):
                result.related_domains.append(
                    RelatedDomain(domain=d, pivot="nameserver", value=ns, source="rapiddns")
                )
    except Exception as exc:
        result.errors.append(f"rapiddns-ns [{ns}]: {exc}")


def _pivot_ip(net: Net, ip: str, result: CrossSearchResult) -> None:
    url = _HT_REVERSE_IP.format(ip=urllib.parse.quote(ip))
    text = _fetch_text(net, url)
    domains = _parse_ht_text(text)
    for d in domains:
        result.related_domains.append(
            RelatedDomain(domain=d, pivot="ip", value=ip, source="hackertarget")
        )
    if domains:
        if f"IP:{ip}" not in result.pivots_used:
            result.pivots_used.append(f"IP:{ip}")
        if ip not in result.ips_pivoted:
            result.ips_pivoted.append(ip)


def _extract_registrant(
    whois_data: Optional[dict],
) -> tuple[Optional[str], Optional[str]]:
    if not whois_data:
        return None, None
    contacts = whois_data.get("contacts") or {}
    best_email: Optional[str] = None
    best_org:   Optional[str] = None
    for role in ("registrant", "admin", "tech"):
        c = contacts.get(role) or {}
        email = c.get("email")
        org   = c.get("organization")
        if email and not _is_privacy_email(email) and best_email is None:
            best_email = email
        if org and best_org is None:
            proxy_orgs = ("domains by proxy", "whoisguard", "contact privacy",
                          "withheld", "redacted", "privacy")
            if not any(p in org.lower() for p in proxy_orgs):
                best_org = org
    return best_email, best_org


def search(
    net: Net,
    domain: str,
    dns: Optional[DnsResult],
    ip_infos: List[IpInfo],
    whois_data: Optional[dict] = None,
    max_ns: int = 3,
    max_ips: int = 2,
) -> CrossSearchResult:
    result = CrossSearchResult(domain=domain)

    email, org = _extract_registrant(whois_data)
    result.registrant_email = email
    result.registrant_org   = org

    ns_list: list[str] = []
    if dns and dns.ns:
        ns_list = [ns.rstrip(".") for ns in dns.ns[:max_ns]]
    result.nameservers = ns_list

    ip_list: list[str] = []
    if ip_infos:
        for rec in ip_infos[:max_ips]:
            if rec.ip:
                ip_list.append(rec.ip)
    elif dns:
        ip_list = dns.a[:max_ips]

    for ns in ns_list:
        try:
            _pivot_ns(net, ns, result)
        except Exception as exc:
            result.errors.append(f"ns-pivot [{ns}]: {exc}")

    for ip in ip_list:
        try:
            _pivot_ip(net, ip, result)
        except Exception as exc:
            result.errors.append(f"ip-pivot [{ip}]: {exc}")

    for rec in ip_infos[:1]:
        if rec.asn:
            try:
                url  = _BGPVIEW_ASN.format(asn=rec.asn)
                data = net.http_json(url)
                if isinstance(data, dict) and data.get("status") == "ok":
                    label = f"ASN:AS{rec.asn}"
                    if label not in result.pivots_used:
                        result.pivots_used.append(label)
            except Exception as exc:
                result.errors.append(f"bgpview-asn [{rec.asn}]: {exc}")

    return result