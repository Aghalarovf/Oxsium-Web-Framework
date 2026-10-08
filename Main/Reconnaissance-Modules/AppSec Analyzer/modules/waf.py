from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core.exporter import Finding, Severity
from core.logger import get_logger
from core.requester import Requester, Response

log = get_logger("waf")

WAF_DB: Dict[str, Dict] = {

    "Cloudflare": {
        "headers": [
            ("cf-ray",              r".+",                               40),
            ("cf-cache-status",     r".+",                               35),
            ("cf-request-id",       r".+",                               40),
            ("cf-connecting-ip",    r".+",                               35),
            ("cf-ipcountry",        r".+",                               35),
            ("cf-visitor",          r".+",                               30),
            ("cf-worker",           r".+",                               30),
            ("server",              r"^cloudflare$",                     35),
            ("report-to",           r"endpoints.*nel\.cloudflare\.com",  25),
            ("alt-svc",             r"h3.*cloudflare",                   25),
        ],
        "cookies": [
            (r"^__cf_bm$",          35),
            (r"^__cflb$",           40),
            (r"^cf_clearance$",     40),
            (r"^__cfduid$",         30),
            (r"^__cf_chl_",         40),
        ],
        "body": [
            (r"cloudflare\.com/cdn-cgi/",                   30),
            (r"cdn-cgi/challenge-platform",                 40),
            (r"/_cdn-cgi/scripts/",                         40),
            (r"ray\s+id\s*[:\|]\s*[0-9a-f]{16}",           40),
            (r"attention required.*cloudflare",              35),
            (r"cloudflare\s+is\s+blocking",                 35),
            (r"__cf_chl_opt\s*=",                           40),
            (r"challenge-form.*cloudflare",                 35),
        ],
        "cname": [
            (r"\.cloudflare\.net$",   45),
            (r"\.cloudflare\.com$",   45),
            (r"\.cf-ipfs\.com$",      40),
        ],
        "cidr": [
            ("103.21.244.0/22",  40), ("103.22.200.0/22", 40),
            ("103.31.4.0/22",    40), ("104.16.0.0/13",   40),
            ("104.24.0.0/14",    40), ("108.162.192.0/18",40),
            ("131.0.72.0/22",    40), ("141.101.64.0/18", 40),
            ("162.158.0.0/15",   40), ("172.64.0.0/13",   40),
            ("173.245.48.0/20",  40), ("188.114.96.0/20", 40),
            ("190.93.240.0/20",  40), ("197.234.240.0/22",40),
            ("198.41.128.0/17",  40), ("2400:cb00::/32",  40),
            ("2606:4700::/32",   40), ("2803:f800::/32",  40),
            ("2405:b500::/32",   40), ("2405:8100::/32",  40),
            ("2a06:98c0::/29",   40), ("2c0f:f248::/32",  40),
        ],
        "tls_cn": [
            (r"cloudflare",     35),
            (r"\.cloudflare\.", 35),
            (r"Cloudflare Inc ECC", 40),
        ],
    },

    "Akamai": {
        "headers": [
            ("x-akamai-transformed",       r".+",           40),
            ("x-akamai-request-id",        r".+",           40),
            ("x-akamai-session-info",      r".+",           40),
            ("x-akamai-edgescape",         r".+",           40),
            ("x-akamai-ssl-client-sid",    r".+",           40),
            ("x-akamai-config-log-detail", r".+",           40),
            ("x-check-cacheable",          r".+",           35),
            ("akamai-origin-hop",          r".+",           40),
            ("x-serial",                   r"^\d+$",        20),
            ("x-true-cache-key",           r".+",           35),
            ("server",                     r"AkamaiGHost",  40),
            ("server",                     r"AkamaiNetStorage", 40),
        ],
        "cookies": [
            (r"^ak_bmsc$",  35),
            (r"^bm_sz$",    35),
            (r"^AKA_A2$",   40),
        ],
        "body": [
            (r"akamai.*reference.*id",            40),
            (r"access denied.*akamai",             35),
            (r"ghost\.akamai\.com",               40),
            (r"akamaized\.net",                   30),
            (r"akamai error",                     40),
            (r"akamai-bot-loader\.js",            40),
            (r"reference\s+#\d+\.\d+\.\d+\.\d+", 20),
        ],
        "cname": [
            (r"\.akamaiedge\.net$",          45),
            (r"\.akamaitechnologies\.com$",  45),
            (r"\.akamai\.net$",              45),
            (r"\.akamaized\.net$",           40),
            (r"\.edgesuite\.net$",           40),
            (r"\.edgekey\.net$",             40),
            (r"\.srip\.net$",                35),
        ],
        "cidr": [
            ("23.32.0.0/11",   35), ("23.64.0.0/14",   35),
            ("23.192.0.0/11",  35), ("72.246.0.0/15",  35),
            ("88.221.0.0/16",  35), ("92.122.0.0/15",  35),
            ("96.6.0.0/15",    35), ("96.16.0.0/15",   35),
            ("104.64.0.0/10",  35), ("110.224.0.0/13", 35),
        ],
        "tls_cn": [
            (r"akamai",    35),
            (r"edgesuite", 30),
        ],
    },

    "Imperva / Incapsula": {
        "headers": [
            ("x-iinfo",       r"\d+-\d+-\d+", 40),
            ("x-cdn",         r"incapsula",   40),
            ("x-incap-ses",   r".+",          40),
            ("x-visid-incap", r".+",          40),
        ],
        "cookies": [
            (r"^incap_ses_",   40),
            (r"^visid_incap_", 40),
            (r"^nlbi_",        35),
            (r"^reese84$",     35),
        ],
        "body": [
            (r"incapsula incident id",            40),
            (r"powered by incapsula",             40),
            (r"/_Incapsula_Resource\?",           40),
            (r"incapsula\.com",                   30),
            (r"imperva\.com",                     30),
            (r"request unsuccessful\. incapsula", 40),
        ],
        "cname": [
            (r"\.incapdns\.net$",   45),
            (r"\.imperva\.com$",    45),
            (r"\.incapsula\.com$",  45),
            (r"\.impervadns\.net$", 45),
        ],
        "cidr": [
            ("45.64.64.0/22",   40), ("149.126.72.0/21", 40),
            ("199.83.128.0/21", 40), ("208.91.112.0/21", 40),
            ("45.60.0.0/16",    40), ("103.28.248.0/22", 40),
        ],
        "tls_cn": [
            (r"incapsula", 35),
            (r"imperva",   35),
        ],
    },

    "Sucuri": {
        "headers": [
            ("x-sucuri-id",      r".+",                  40),
            ("x-sucuri-cache",   r".+",                  40),
            ("x-sucuri-country", r".+",                  40),
            ("server",           r"^sucuri/cloudproxy$", 40),
        ],
        "cookies": [
            (r"^sucuri_cloudproxy_uuid$", 40),
        ],
        "body": [
            (r"sucuri website firewall",  40),
            (r"access denied.*sucuri",    40),
            (r"sucuri\.net",              30),
            (r"cloudproxy\.sucuri\.net",  40),
            (r"sucuri-waf",               35),
        ],
        "cname": [
            (r"\.sucuri\.net$",           45),
            (r"cloudproxy\.sucuri\.net$", 45),
        ],
        "cidr": [
            ("192.88.134.0/23", 40), ("185.93.228.0/22", 40),
            ("66.248.200.0/22", 40), ("208.109.0.0/22",  40),
        ],
        "tls_cn": [
            (r"sucuri", 35),
        ],
    },

    "AWS WAF / CloudFront": {
        "headers": [
            ("x-amzn-requestid",  r".+",                          40),
            ("x-amz-cf-id",       r".+",                          40),
            ("x-amz-cf-pop",      r".+",                          40),
            ("x-amzn-trace-id",   r"Root=",                       40),
            ("x-amzn-errortype",  r".+",                          40),
            ("x-cache",           r"(Hit|Miss) from cloudfront",  40),
            ("via",               r"CloudFront",                  40),
            ("server",            r"awselb",                      35),
        ],
        "cookies": [
            (r"^AWSALB$",     40),
            (r"^AWSALBCORS$", 40),
            (r"^AWSELB$",     40),
        ],
        "body": [
            (r"AwsWafIntegration",                       40),
            (r"captcha\.us-east-1\.amazonaws\.com",      40),
            (r"Generated by cloudfront \(CloudFront\)",  40),
            (r"request blocked.*amazon",                 40),
            (r"aws-waf-token",                           40),
            (r"x-amzn-waf",                              40),
        ],
        "cname": [
            (r"\.cloudfront\.net$",                  45),
            (r"\.awsglobalaccelerator\.com$",        40),
            (r"\.execute-api\.\S+\.amazonaws\.com$", 40),
        ],
        "cidr": [
            ("13.32.0.0/15",    35), ("13.35.0.0/16",   35),
            ("52.84.0.0/15",    35), ("54.182.0.0/16",  35),
            ("64.252.64.0/18",  35), ("70.132.0.0/18",  35),
            ("99.84.0.0/16",    35), ("130.176.0.0/17", 35),
            ("204.246.164.0/22",35), ("205.251.192.0/19",35),
        ],
        "tls_cn": [
            (r"cloudfront\.net", 40),
            (r"amazonaws\.com",  30),
        ],
    },

    "Fastly": {
        "headers": [
            ("x-fastly-request-id", r".+",          40),
            ("fastly-io-warning",   r".+",           40),
            ("fastly-ff",           r".+",           40),
            ("x-served-by",         r"cache-",       35),
            ("x-cache",             r"HIT|MISS",     20),
            ("x-cache-hits",        r"\d+",          30),
            ("x-timer",             r"S\d+\.\d+",    35),
            ("via",                 r"varnish",      30),
            ("server",              r"varnish",      30),
        ],
        "cookies": [
            (r"^fastly-ssl$", 30),
        ],
        "body": [
            (r"varnish cache server", 35),
            (r"fastly error: ",       40),
            (r"fastly\.com",          30),
        ],
        "cname": [
            (r"\.fastly\.net$",             45),
            (r"\.fastlylb\.net$",           45),
            (r"\.fastlycontrolplane\.com$", 40),
        ],
        "cidr": [
            ("23.235.32.0/20",  40), ("43.249.72.0/22",  40),
            ("103.244.50.0/24", 40), ("103.245.222.0/23",40),
            ("104.156.80.0/20", 40), ("151.101.0.0/16",  40),
            ("157.52.64.0/18",  40), ("167.82.0.0/17",   40),
            ("199.27.72.0/21",  40), ("199.232.0.0/16",  40),
            ("140.82.112.0/20", 40), ("185.199.108.0/22",40),
            ("192.30.252.0/22", 40), ("143.55.64.0/20",  40),
        ],
        "tls_cn": [
            (r"fastly", 35),
        ],
    },

    "F5 BIG-IP ASM": {
        "headers": [
            ("x-wa-info",        r".+",   40),
            ("f5-routedsession", r".+",   40),
            ("server",           r"BigIP", 40),
        ],
        "cookies": [
            (r"^TS[0-9a-f]{8}$", 40),
            (r"^BIGipServer",     40),
            (r"^F5_",             35),
        ],
        "body": [
            (r"the requested url was rejected.*f5",    40),
            (r"reference id.*f5.*networks",            40),
            (r"f5 networks.*web application firewall", 40),
            (r"request rejected.*f5",                  40),
            (r"your support id is",                    35),
        ],
        "cname": [],
        "cidr": [],
        "tls_cn": [
            (r"f5\s+networks", 35),
            (r"big.?ip",       30),
        ],
    },

    "ModSecurity": {
        "headers": [
            ("server", r"mod_security", 40),
        ],
        "cookies": [],
        "body": [
            (r"mod_security",                     40),
            (r"406\s+not acceptable.*modsec",     40),
            (r"this error.*generated by.*modsec", 40),
            (r"ModSecurity Action",               40),
        ],
        "cname": [],
        "cidr": [],
        "tls_cn": [],
    },

    "Fortinet FortiWeb": {
        "headers": [
            ("x-kojak-version", r".+", 40),
        ],
        "cookies": [
            (r"^FORTIWAFSID=", 40),
        ],
        "body": [
            (r"fortiweb",                           40),
            (r"web application firewall.*fortinet", 40),
            (r"fortigate",                          25),
        ],
        "cname": [
            (r"\.fortiddns\.com$", 35),
        ],
        "cidr": [],
        "tls_cn": [
            (r"fortinet", 35),
            (r"fortiweb", 40),
        ],
    },

    "Barracuda WAF": {
        "headers": [],
        "cookies": [
            (r"^barra_counter_session=",    40),
            (r"^BNI__BARRACUDA_LB_COOKIE=", 40),
            (r"^BNI_persistence=",          35),
        ],
        "body": [
            (r"barracuda.*networks",  40),
            (r"blocked by barracuda", 40),
        ],
        "cname": [
            (r"\.barracuda\.com$", 40),
            (r"\.cudacloud\.net$", 40),
        ],
        "cidr": [],
        "tls_cn": [
            (r"barracuda", 35),
        ],
    },

    "Wordfence": {
        "headers": [],
        "cookies": [
            (r"^wfvt_",      35),
            (r"^wordfence_", 35),
        ],
        "body": [
            (r"generated by wordfence",          40),
            (r"wordfence.*blocked.*your access",  40),
            (r"wordfence\.com",                  30),
        ],
        "cname": [],
        "cidr": [],
        "tls_cn": [],
    },

    "Squarespace": {
        "headers": [
            ("x-servedby", r"squarespace", 40),
            ("server",     r"squarespace", 40),
        ],
        "cookies": [
            (r"^crumb=", 20),
        ],
        "body": [
            (r"squarespace\.com", 30),
        ],
        "cname": [
            (r"\.squarespace\.com$", 40),
            (r"\.sqsp\.net$",        40),
        ],
        "cidr": [],
        "tls_cn": [
            (r"squarespace", 35),
        ],
    },

    "Alibaba Cloud WAF": {
        "headers": [
            ("eagleid",       r".+", 40),
            ("x-swift-error", r".+", 35),
        ],
        "cookies": [
            (r"^cna=",    30),
            (r"^alicdn=", 35),
        ],
        "body": [
            (r"error.*by alibaba",      40),
            (r"blocked.*alibaba cloud", 40),
            (r"alibaba cloud waf",      40),
        ],
        "cname": [
            (r"\.aliyuncs\.com$", 40),
            (r"\.alicdn\.com$",   40),
            (r"\.aliyun\.com$",   40),
        ],
        "cidr": [],
        "tls_cn": [
            (r"alibaba", 35),
            (r"aliyun",  35),
        ],
    },

    "Reblaze": {
        "headers": [
            ("x-reblaze-protection", r".+", 40),
        ],
        "cookies": [
            (r"^rbzid=",       40),
            (r"^rbzsessionid=",40),
        ],
        "body": [
            (r"reblaze", 40),
        ],
        "cname": [
            (r"\.reblaze\.com$", 40),
        ],
        "cidr": [],
        "tls_cn": [
            (r"reblaze", 35),
        ],
    },

    "DataDome": {
        "headers": [
            ("x-datadome-isbot", r".+", 40),
            ("x-datadome-cid",   r".+", 40),
        ],
        "cookies": [
            (r"^datadome$", 40),
        ],
        "body": [
            (r"datadome",              40),
            (r"js\.datadome\.com",     40),
            (r"protected by datadome", 40),
        ],
        "cname": [
            (r"\.datadome\.co$", 40),
        ],
        "cidr": [],
        "tls_cn": [
            (r"datadome", 35),
        ],
    },

    "PerimeterX": {
        "headers": [
            ("x-px-score",             r"\d+", 40),
            ("x-px-bypass",            r".+",  40),
            ("x-perimeterx-device-id", r".+",  40),
        ],
        "cookies": [
            (r"^_px$",    35),
            (r"^_px2$",   40),
            (r"^_px3$",   40),
            (r"^_pxvid$", 35),
        ],
        "body": [
            (r"perimeterx",         40),
            (r"px\.init\(",         40),
            (r"_perimeterx",        40),
            (r"human\.px-cdn\.net", 40),
        ],
        "cname": [
            (r"\.perimeterx\.com$", 40),
            (r"\.px-cdn\.net$",     40),
        ],
        "cidr": [],
        "tls_cn": [
            (r"perimeterx", 35),
        ],
    },
}

CONFIDENCE_CONFIRMED = 70
CONFIDENCE_PROBABLE  = 40
CONFIDENCE_POSSIBLE  = 10


@dataclass
class WAFCandidate:
    name:    str
    score:   int      = 0
    signals: List[str] = field(default_factory=list)
    methods: Set[str]  = field(default_factory=set)

    def add(self, points: int, signal: str, method: str) -> None:
        self.score += points
        self.signals.append(signal)
        self.methods.add(method)

    @property
    def confidence_label(self) -> str:
        if self.score >= CONFIDENCE_CONFIRMED:
            return "CONFIRMED"
        if self.score >= CONFIDENCE_PROBABLE:
            return "PROBABLE"
        if self.score >= CONFIDENCE_POSSIBLE:
            return "POSSIBLE"
        return "UNLIKELY"

    @property
    def severity(self) -> str:
        if self.score >= CONFIDENCE_CONFIRMED:
            return Severity.HIGH
        if self.score >= CONFIDENCE_PROBABLE:
            return Severity.MEDIUM
        return Severity.LOW


def _extract_hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def _resolve_ip(hostname: str) -> Optional[str]:
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return info[0][4][0]
    except (socket.gaierror, IndexError):
        return None


def _cidr_contains(ip_str: str, cidr: str) -> bool:
    try:
        net  = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip_str)
        return addr in net
    except ValueError:
        return False


def _get_tls_cert_fields(hostname: str, port: int = 443) -> Dict[str, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
            server_hostname=hostname,
        ) as tls:
            der = tls.getpeercert(binary_form=True)

        if not der:
            return {}

        fields: Dict[str, str] = {}

        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_der_x509_certificate(der, default_backend())

            for attr in cert.subject:
                fields[f"subject_{attr.oid.dotted_string}"] = str(attr.value)
            try:
                fields["subject_commonname"] = cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)[0].value
            except Exception:
                pass

            for attr in cert.issuer:
                fields[f"issuer_{attr.oid.dotted_string}"] = str(attr.value)
            try:
                fields["issuer_organizationname"] = cert.issuer.get_attributes_for_oid(
                    x509.NameOID.ORGANIZATION_NAME)[0].value
            except Exception:
                pass
            try:
                fields["issuer_commonname"] = cert.issuer.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME)[0].value
            except Exception:
                pass

            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                fields["san"] = " ".join(
                    name.value for name in san_ext.value.get_values_for_type(x509.DNSName)
                )
            except Exception:
                fields["san"] = ""

        except ImportError:
            import struct as _struct
            fields["san"] = ""
            fields["_raw_der_len"] = str(len(der))
            log.debug("cryptography library not installed — TLS parsing limited.")

        return fields

    except Exception as exc:
        log.debug(f"TLS cert retrieval failed for {hostname}: {exc}")
        return {}


def _resolve_cname_chain(hostname: str) -> List[str]:
    chain: List[str] = []
    try:
        import dns.resolver
        current = hostname
        for _ in range(10):
            try:
                answers = dns.resolver.resolve(current, "CNAME")
                target  = str(answers[0].target).rstrip(".")
                chain.append(target)
                current = target
            except dns.resolver.NoAnswer:
                break
            except Exception:
                break
    except ImportError:
        log.debug("dnspython not installed — CNAME analysis skipped.")
    except Exception as exc:
        log.debug(f"CNAME resolution failed: {exc}")
    return chain


def _extract_cookies(resp: Response) -> List[str]:
    raw = resp.header("set-cookie")
    if not raw:
        return []
    return re.findall(r"(?:^|,\s*)([^=;,\s]+)=", raw)


class WAFModule:

    MODULE_NAME = "waf"

    def __init__(self, target: str, requester: Requester) -> None:
        self.target    = target
        self.requester = requester
        self.hostname  = _extract_hostname(target)
        self._candidates: Dict[str, WAFCandidate] = {
            name: WAFCandidate(name=name) for name in WAF_DB
        }

    def run(self) -> List[Finding]:
        log.info(f"Passive WAF fingerprinting started → {self.target}")

        baseline = self.requester.get(self.target)
        if baseline:
            self._layer_headers(baseline)
            self._layer_cookies(baseline)
            self._layer_body(baseline)
        else:
            log.warning("Baseline request failed; HTTP layers skipped.")

        self._layer_dns_cname()
        self._layer_ip_cidr()
        self._layer_tls_certificate()

        return self._build_findings()

    def _layer_headers(self, resp: Response) -> None:
        log.debug("Layer 1 — HTTP header + cookie fingerprinting …")
        for waf_name, sigs in WAF_DB.items():
            for header_name, pattern, pts in sigs.get("headers", []):
                value = resp.header(header_name)
                if value and re.search(pattern, value, re.IGNORECASE):
                    self._candidates[waf_name].add(
                        pts,
                        f"Header '{header_name}: {value[:80]}'",
                        "HTTP headers",
                    )

    def _layer_cookies(self, resp: Response) -> None:
        log.debug("Layer 2 — Cookie fingerprinting …")
        cookie_names = _extract_cookies(resp)
        if not cookie_names:
            return
        for waf_name, sigs in WAF_DB.items():
            for pattern, pts in sigs.get("cookies", []):
                for cname in cookie_names:
                    if re.search(pattern, cname, re.IGNORECASE):
                        self._candidates[waf_name].add(
                            pts,
                            f"Cookie name '{cname}' matches {pattern}",
                            "Cookie fingerprint",
                        )
                        break

    def _layer_body(self, resp: Response) -> None:
        log.debug("Layer 3 — HTML body / source fingerprinting …")
        for waf_name, sigs in WAF_DB.items():
            for pattern, pts in sigs.get("body", []):
                if re.search(pattern, resp.body, re.IGNORECASE | re.DOTALL):
                    self._candidates[waf_name].add(
                        pts,
                        f"Body pattern /{pattern}/",
                        "HTML source",
                    )

    def _layer_dns_cname(self) -> None:
        log.debug("Layer 4 — DNS CNAME chain analysis …")
        chain = _resolve_cname_chain(self.hostname)
        if chain:
            log.debug(f"CNAME chain: {self.hostname} → {' → '.join(chain)}")
        else:
            log.debug("No CNAME records found.")
        for waf_name, sigs in WAF_DB.items():
            for pattern, pts in sigs.get("cname", []):
                for cname in chain:
                    if re.search(pattern, cname, re.IGNORECASE):
                        self._candidates[waf_name].add(
                            pts,
                            f"CNAME '{cname}' matches {pattern}",
                            "DNS CNAME chain",
                        )
                        break

    def _layer_ip_cidr(self) -> None:
        log.debug("Layer 5 — IP/CIDR range matching …")
        ip = _resolve_ip(self.hostname)
        if not ip:
            log.debug("IP resolution failed; CIDR layer skipped.")
            return
        log.debug(f"Resolved {self.hostname} → {ip}")
        for waf_name, sigs in WAF_DB.items():
            for cidr, pts in sigs.get("cidr", []):
                if _cidr_contains(ip, cidr):
                    self._candidates[waf_name].add(
                        pts,
                        f"IP {ip} is inside {waf_name} range {cidr}",
                        "IP/CIDR range",
                    )
                    break

    def _layer_tls_certificate(self) -> None:
        log.debug("Layer 6 — TLS certificate inspection …")
        fields = _get_tls_cert_fields(self.hostname)
        if not fields:
            return
        all_values = " ".join(fields.values())
        log.debug(
            f"TLS cert: CN={fields.get('subject_commonname','?')} "
            f"Issuer={fields.get('issuer_organizationname','?')}"
        )
        for waf_name, sigs in WAF_DB.items():
            for pattern, pts in sigs.get("tls_cn", []):
                if re.search(pattern, all_values, re.IGNORECASE):
                    matched_field = next(
                        (f"{k}={v}" for k, v in fields.items()
                         if re.search(pattern, v, re.IGNORECASE)),
                        "(certificate field)"
                    )
                    self._candidates[waf_name].add(
                        pts,
                        f"TLS cert field '{matched_field}' matches /{pattern}/",
                        "TLS certificate",
                    )

    def _build_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        scorers = sorted(
            [c for c in self._candidates.values()
             if c.score >= CONFIDENCE_POSSIBLE],
            key=lambda c: c.score,
            reverse=True,
        )
        for cand in scorers:
            methods_str = ", ".join(sorted(cand.methods))
            evidence = [
                f"Confidence score : {cand.score} pts ({cand.confidence_label})",
                f"Detection layers : {methods_str}",
                "── Matched signals ──",
            ] + [f"  • {s}" for s in cand.signals]

            findings.append(Finding(
                module=self.MODULE_NAME,
                title=(
                    f"WAF identified [{cand.confidence_label}]: {cand.name} "
                    f"(score {cand.score})"
                ),
                severity=cand.severity,
                detail=(
                    f"Passive fingerprinting identified {cand.name} with "
                    f"{cand.score} confidence points across "
                    f"{len(cand.methods)} detection layer(s): {methods_str}. "
                    f"Confidence: {cand.confidence_label}."
                ),
                evidence=evidence,
            ))
            log.info(
                f"WAF candidate: {cand.name:30s}  score={cand.score:3d}  "
                f"[{cand.confidence_label}]  layers={methods_str}"
            )

        if not findings:
            findings.append(Finding(
                module=self.MODULE_NAME,
                title="No WAF detected (passive scan)",
                severity=Severity.INFO,
                detail=(
                    "No WAF signatures matched across all passive detection "
                    "layers (HTTP headers, cookies, HTML source, DNS CNAME, "
                    "IP/CIDR, TLS certificate). The target may be unprotected, "
                    "use a custom WAF, or strip all identifiable headers."
                ),
            ))
        return findings