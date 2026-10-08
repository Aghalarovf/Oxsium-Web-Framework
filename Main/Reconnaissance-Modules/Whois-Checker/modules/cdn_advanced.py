from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from core.config import CDN_ASNS, CDN_NS_HINTS
from core.models import CdnResult, DnsResult, HttpProbe, IpInfo

_WAF_HEADERS: dict[str, Optional[str]] = {
    "cf-ray":                       "Cloudflare",
    "cf-cache-status":              "Cloudflare",
    "cf-request-id":                "Cloudflare",
    "x-sucuri-id":                  "Sucuri WAF",
    "x-sucuri-cache":               "Sucuri WAF",
    "x-iinfo":                      "Imperva/Incapsula",
    "x-cdn-shield":                 "Incapsula",
    "x-amz-cf-id":                  "Amazon CloudFront",
    "x-amz-cf-pop":                 "Amazon CloudFront",
    "x-fastly-request-id":          "Fastly",
    "x-served-by":                  "Fastly",
    "x-cache":                      "Fastly/Varnish",
    "x-akamai-transformed":         "Akamai",
    "x-akamai-request-id":          "Akamai",
    "x-akamai-session-info":        "Akamai",
    "x-check-cacheable":            "Akamai",
    "x-azure-ref":                  "Azure CDN / Front Door",
    "x-msedge-ref":                 "Azure Front Door",
    "x-goog-backend-server":        "Google CDN",
    "x-goog-served-by":             "Google CDN",
    "x-cache-hits":                 "Varnish Cache",
    "x-varnish":                    "Varnish Cache",
    "x-bunnycdn-cache-status":      "BunnyCDN",
    "cdn-cacheability":             "StackPath",
    "x-hw":                         "Highwinds/StackPath",
    "x-f5-server":                  "F5 BIG-IP",
    "x-waf-status":                 "Generic WAF",
    "x-barracuda-connect":          "Barracuda WAF",
    "x-squid-error":                "Squid Proxy",
    "x-litespeed-cache":            "LiteSpeed",
    "x-quic":                       "QUIC.cloud",
    "x-kinsta-cache":               "Kinsta CDN",
    "x-mod-pagespeed":              "Google PageSpeed/CDN",
    "x-edgeconnect-midmile-rtt":    "Akamai EdgeConnect",
    "x-oracle-dms-ecid":            "Oracle CDN",
    "x-hs-cf-cache-status":         "HubSpot CDN",
    "via":                          None,
    "x-cdn":                        None,
}

_SERVER_HINTS: dict[str, str] = {
    "cloudflare":   "Cloudflare",
    "awselb":       "Amazon ELB",
    "amazons3":     "Amazon S3",
    "gws":          "Google Web Server",
    "litespeed":    "LiteSpeed",
    "sucuri":       "Sucuri WAF",
    "bunnycdn":     "BunnyCDN",
    "varnish":      "Varnish Cache",
    "squid":        "Squid Proxy",
    "imperva":      "Imperva WAF",
    "f5":           "F5 BIG-IP",
}

_VALUE_HINTS: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("akamai",     "Akamai"),
    ("fastly",     "Fastly"),
    ("varnish",    "Varnish Cache"),
    ("cdn77",      "CDN77"),
    ("stackpath",  "StackPath"),
    ("cloudfront", "Amazon CloudFront"),
    ("azure",      "Azure CDN"),
    ("sucuri",     "Sucuri WAF"),
    ("imperva",    "Imperva/Incapsula"),
    ("bunny",      "BunnyCDN"),
    ("quic",       "QUIC.cloud"),
]

_ANYCAST_ASNS = {
    13335,  # Cloudflare
    20940,  # Akamai
    54113,  # Fastly
    16509,  # Amazon AWS
    15169,  # Google
    8075,   # Microsoft
}

_WAF_VENDORS = {
    "Sucuri WAF", "Imperva/Incapsula", "Incapsula",
    "Barracuda WAF", "Generic WAF", "F5 BIG-IP",
}


@dataclass
class CdnAdvancedResult:
    behind_cdn:   bool                 = False
    vendors:      list[str]            = field(default_factory=list)
    evidence:     dict[str, list[str]] = field(default_factory=dict)
    waf_detected: list[str]            = field(default_factory=list)
    anycast:      bool                 = False
    note:         str                  = ""

    def to_dict(self) -> dict:
        return {
            "behind_cdn":   self.behind_cdn,
            "vendors":      self.vendors,
            "evidence":     self.evidence,
            "waf_detected": self.waf_detected,
            "anycast":      self.anycast,
            "note":         self.note,
        }

    def to_cdn_result(self) -> CdnResult:
        return CdnResult(
            behind_cdn=self.behind_cdn,
            vendors=self.vendors,
            evidence=self.evidence,
            note=self.note,
        )


def detect_advanced(
    domain: str,
    dns: DnsResult,
    ip_infos: List[IpInfo],
    http_probes: List[HttpProbe],
) -> CdnAdvancedResult:
    res  = CdnAdvancedResult()
    hits: dict[str, list[str]] = {}

    def add(vendor: str, why: str) -> None:
        hits.setdefault(vendor, [])
        if why not in hits[vendor]:
            hits[vendor].append(why)

    def mark_waf(vendor: str) -> None:
        if vendor not in res.waf_detected:
            res.waf_detected.append(vendor)

    for ns in dns.ns:
        low = ns.lower()
        for vendor, keys in CDN_NS_HINTS.items():
            if any(k in low for k in keys):
                add(vendor, f"NS: {ns}")

    for cn in dns.cname:
        low = cn.lower()
        for vendor, keys in CDN_NS_HINTS.items():
            if any(k in low for k in keys):
                add(vendor, f"CNAME: {cn}")

    for rec in ip_infos:
        if rec.asn and rec.asn in CDN_ASNS:
            vendor = CDN_ASNS[rec.asn]
            add(vendor, f"AS{rec.asn} ({rec.as_name or ''})")
            if rec.asn in _ANYCAST_ASNS:
                res.anycast = True

        blob = " ".join(
            str(x).lower() for x in (rec.org, rec.isp, rec.as_name, rec.ptr) if x
        )
        for vendor, keys in CDN_NS_HINTS.items():
            if any(k in blob for k in keys):
                add(vendor, f"IP org/ISP/PTR on {rec.ip}")

    for probe in http_probes:
        headers = {k.lower(): v.lower() for k, v in probe.headers.items()}
        status  = probe.status if isinstance(probe.status, int) else 0

        for hk, vendor in _WAF_HEADERS.items():
            if hk not in headers:
                continue
            val = headers[hk]

            if vendor:
                add(vendor, f"HTTP header: {hk}")
                if vendor in _WAF_VENDORS:
                    mark_waf(vendor)
            else:
                for hint, hvendor in _VALUE_HINTS:
                    if hint in val:
                        add(hvendor, f"HTTP {hk}: {val[:60]}")

        if "server" in headers:
            sv = headers["server"]
            for hint, hvendor in _SERVER_HINTS.items():
                if hint in sv:
                    add(hvendor, f"Server header: {sv[:80]}")

        if "cf-ray" in headers and status in (403, 503, 1020):
            mark_waf("Cloudflare WAF")

    res.evidence   = hits
    res.vendors    = sorted(hits.keys())
    res.behind_cdn = bool(res.vendors)
    res.note = (
        ", ".join(res.vendors)
        if res.vendors
        else "No CDN/WAF signatures detected"
    )
    if res.anycast:
        res.note += " [anycast IPs detected]"

    return res