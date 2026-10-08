from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SourceResult:
    source: str
    subdomains: set[str] = field(default_factory=set)
    error: Optional[str] = None


@dataclass
class CheckResult:
    scheme: str
    subdomain: str
    status: Optional[int] = None
    error: Optional[str] = None
    final_url: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "url": f"{self.scheme}://{self.subdomain}",
            "status": self.status,
            "error": self.error,
            "final_url": self.final_url,
        }

    def describe(self) -> str:
        if self.status is not None:
            label = str(self.status)
            if self.final_url and self.final_url != f"{self.scheme}://{self.subdomain}":
                label += f" -> {self.final_url}"
            return label
        return f"ERR/{self.error or 'UNKNOWN'}"


@dataclass
class TakeoverResult:
    """Populated when a subdomain is vulnerable to takeover."""
    cname: str          # the dangling CNAME target
    provider: str       # matched provider name (e.g. "github-pages")
    evidence: str       # what we matched (fingerprint string or HTTP body snippet)

    def to_dict(self) -> dict:
        return {
            "cname": self.cname,
            "provider": self.provider,
            "evidence": self.evidence,
        }


@dataclass
class HostInfo:
    subdomain: str
    ips: list[str] = field(default_factory=list)
    dns_error: Optional[str] = None
    checks: list[CheckResult] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)   # full CNAME chain, excl. subdomain itself
    takeover: Optional[TakeoverResult] = None               # set if vulnerable

    def ip_label(self) -> str:
        if self.ips:
            return ", ".join(self.ips)
        return self.dns_error or "NXDOMAIN"

    def check_for(self, scheme: str) -> Optional[CheckResult]:
        for c in self.checks:
            if c.scheme == scheme:
                return c
        return None

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ips": self.ips,
            "dns_error": self.dns_error,
            "cname_chain": self.cname_chain,
            "takeover": self.takeover.to_dict() if self.takeover else None,
            "checks": [c.to_dict() for c in self.checks],
        }