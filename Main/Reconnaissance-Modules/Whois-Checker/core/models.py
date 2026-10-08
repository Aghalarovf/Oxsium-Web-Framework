from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ContactInfo:
    name: str = ""
    organization: str = ""
    address: str = ""
    country: str = ""
    phone: str = ""
    email: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.__dict__.items() if v}

    def is_empty(self) -> bool:
        return not any(self.__dict__.values())


@dataclass
class PrivacyInfo:
    enabled: bool = False
    indicators: list[str] = field(default_factory=list)
    note: str = ""
    visible_emails: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "indicators": self.indicators,
            "note": self.note,
            "visible_emails": self.visible_emails,
        }


@dataclass
class WhoisResult:
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    days_until_expiry: Optional[int] = None
    expiry_warning: bool = False
    status: list[str] = field(default_factory=list)
    registrar: Optional[str] = None
    registrar_iana_id: Optional[str] = None
    whois_server: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    contacts: dict[str, ContactInfo] = field(default_factory=dict)
    privacy: Optional[PrivacyInfo] = None
    sources: list[str] = field(default_factory=list)
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "updated": self.updated,
            "expires": self.expires,
            "days_until_expiry": self.days_until_expiry,
            "expiry_warning": self.expiry_warning,
            "status": self.status,
            "registrar": self.registrar,
            "registrar_iana_id": self.registrar_iana_id,
            "name_servers": self.name_servers,
            "dnssec": self.dnssec,
            "contacts": {r: c.to_dict() for r, c in self.contacts.items()},
            "privacy": self.privacy.to_dict() if self.privacy else None,
            "sources": self.sources,
            "raw": self.raw,
        }


@dataclass
class IpInfo:
    ip: str = ""
    asn: Optional[int] = None
    as_name: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    timezone: Optional[str] = None
    hosting: Optional[bool] = None
    proxy_or_vpn: Optional[bool] = None
    mobile: Optional[bool] = None
    usage_type: Optional[str] = None
    ptr: Optional[str] = None
    rdap_country: Optional[str] = None
    cidr: Optional[str] = None
    rdap_range: Optional[str] = None
    rdap_remarks: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class DnsResult:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    resolver: str = "socket"

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class CdnResult:
    behind_cdn: bool = False
    vendors: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "behind_cdn": self.behind_cdn,
            "vendors": self.vendors,
            "evidence": self.evidence,
            "note": self.note,
        }


@dataclass
class HttpProbe:
    url: str = ""
    status: int = 0
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "final_url": self.final_url,
            "headers": self.headers,
        }


@dataclass
class Report:
    tool: str = ""
    version: str = ""
    queried_at: str = ""
    domain: Optional[str] = None
    tld: Optional[str] = None
    whois: Optional[WhoisResult] = None
    dns: Optional[DnsResult] = None
    ips: list[IpInfo] = field(default_factory=list)
    cdn: Optional[CdnResult] = None
    cdn_advanced: Optional[Any] = None
    http: list[HttpProbe] = field(default_factory=list)
    blacklist: Optional[Any] = None
    cross_search: Optional[Any] = None
    historical: Optional[Any] = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "queried_at": self.queried_at,
            "domain": self.domain,
            "tld": self.tld,
            "whois": self.whois.to_dict() if self.whois else None,
            "dns": self.dns.to_dict() if self.dns else None,
            "ips": [ip.to_dict() for ip in self.ips],
            "cdn": self.cdn.to_dict() if self.cdn else None,
            "cdn_advanced": self.cdn_advanced.to_dict() if self.cdn_advanced else None,
            "http": [p.to_dict() for p in self.http],
            "blacklist": self.blacklist.to_dict() if self.blacklist else None,
            "cross_search": self.cross_search.to_dict() if self.cross_search else None,
            "historical": self.historical.to_dict() if self.historical else None,
            "errors": self.errors,
        }