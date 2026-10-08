from __future__ import annotations

from typing import Dict, List

from core.config import CDN_ASNS, CDN_HEADERS, CDN_NS_HINTS
from core.models import CdnResult, DnsResult, HttpProbe, IpInfo


def detect(
    domain: str,
    dns: DnsResult,
    ip_infos: List[IpInfo],
    http_probes: List[HttpProbe],
) -> CdnResult:
    hits: Dict[str, List[str]] = {}

    def add(name: str, why: str) -> None:
        hits.setdefault(name, [])
        if why not in hits[name]:
            hits[name].append(why)

    # NS / CNAME hints
    for ns in dns.ns:
        low = ns.lower()
        for vendor, keys in CDN_NS_HINTS.items():
            if any(k in low for k in keys):
                add(vendor, f"NS {ns}")

    for cn in dns.cname:
        low = cn.lower()
        for vendor, keys in CDN_NS_HINTS.items():
            if any(k in low for k in keys):
                add(vendor, f"CNAME {cn}")

    # ASN / org hints from IP info
    for rec in ip_infos:
        if rec.asn and rec.asn in CDN_ASNS:
            add(CDN_ASNS[rec.asn], f"AS{rec.asn} {rec.as_name or ''}".strip())
        blob = " ".join(
            str(x).lower() for x in (rec.org, rec.isp, rec.as_name, rec.ptr) if x
        )
        for vendor, keys in CDN_NS_HINTS.items():
            if any(k in blob for k in keys):
                add(vendor, f"IP org/PTR match on {rec.ip}")

    # HTTP header hints
    for probe in http_probes:
        headers = {k.lower(): v for k, v in probe.headers.items()}
        for hk, vendor in CDN_HEADERS.items():
            if hk not in headers:
                continue
            val = headers[hk]
            if vendor:
                add(vendor, f"HTTP header {hk}: {val}")
            else:
                low = f"{hk}:{val}".lower()
                for name, keys in CDN_NS_HINTS.items():
                    if any(k in low for k in keys):
                        add(name, f"HTTP header {hk}: {val}")
                if "cloudflare" in low:
                    add("Cloudflare", f"HTTP header {hk}: {val}")

    vendors = sorted(hits.keys())
    return CdnResult(
        behind_cdn=bool(vendors),
        vendors=vendors,
        evidence=hits,
        note=(
            ", ".join(vendors)
            if vendors
            else "No CDN signatures detected (origin may still sit behind an unknown proxy)"
        ),
    )