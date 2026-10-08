from __future__ import annotations

VERSION = "2.0.0"
TOOL = "whois-checker"
DEFAULT_TIMEOUT = 15
DEFAULT_UA = f"{TOOL}/{VERSION} (+recon)"

IANA_WHOIS = "whois.iana.org"
RDAP_DOMAIN = "https://rdap.org/domain/{domain}"
RDAP_IP = "https://rdap.org/ip/{ip}"
IP_API = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,countryCode,region,regionName,"
    "city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
)
IPWHO = "https://ipwho.is/{ip}"

PRIVACY_HINTS = (
    "redacted", "privacy", "whoisguard", "domains by proxy", "contact privacy",
    "anonymize", "data protected", "gdpr", "withheld", "identity protect",
    "proxy protection", "redacted for privacy", "not disclosed", "personal data",
    "statutory masking", "whois privacy", "protected", "anonymousspeak",
    "withheldforprivacy", "privacyproxy", "select request email",
    "registration private", "data redacted", "redacted |", "personendaten",
)

CDN_NS_HINTS: dict[str, tuple[str, ...]] = {
    "Cloudflare":        ("cloudflare",),
    "Akamai":            ("akamai", "akam.net", "akamaiedge", "edgekey.net", "edgesuite.net"),
    "Fastly":            ("fastly",),
    "Amazon CloudFront": ("cloudfront.net",),
    "Incapsula/Imperva": ("incapdns", "incapsula", "imperva"),
    "Sucuri":            ("sucuri",),
    "StackPath":         ("stackpath",),
    "BunnyCDN":          ("bunnycdn", "b-cdn.net"),
    "KeyCDN":            ("keycdn",),
    "CDN77":             ("cdn77",),
    "Azure CDN":         ("azureedge.net", "msecnd.net"),
    "Google CDN":        ("googleusercontent", "googledomains", "google.com"),
    "DDoS-Guard":        ("ddos-guard",),
    "QUIC.cloud":        ("quic.cloud",),
}

CDN_ASNS: dict[int, str] = {
    13335: "Cloudflare",
    132892: "Cloudflare",
    209242: "Cloudflare",
    20940: "Akamai",
    16625: "Akamai",
    32787: "Akamai",
    54113: "Fastly",
    16509: "Amazon AWS",
    14618: "Amazon AWS",
    15169: "Google",
    396982: "Google",
    8075: "Microsoft",
    19551: "Incapsula/Imperva",
    20446: "StackPath",
    60068: "CDN77",
    199524: "G-Core",
    16276: "OVH",
    24940: "Hetzner",
    14061: "DigitalOcean",
    63949: "Akamai Linode",
    57724: "DDoS-Guard",
}

CDN_HEADERS: dict[str, str | None] = {
    "cf-ray":                "Cloudflare",
    "cf-cache-status":       "Cloudflare",
    "cf-connecting-ip":      "Cloudflare",
    "x-sucuri-id":           "Sucuri",
    "x-amz-cf-id":           "CloudFront",
    "x-amz-cf-pop":          "CloudFront",
    "x-fastly-request-id":   "Fastly",
    "x-served-by":           "Fastly",
    "x-akamai-transformed":  "Akamai",
    "x-akamai-request-id":   "Akamai",
    "x-iinfo":               "Incapsula/Imperva",
    "x-cdn":                 None,
    "server":                None,
}

HOSTING_HINTS = (
    "amazon", "aws", "google cloud", "gcp", "microsoft", "azure", "digitalocean",
    "linode", "akamai", "ovh", "hetzner", "vultr", "contabo", "leaseweb",
    "choopa", "cogent", "datacenter", "data center", "dedicated", "colocation",
    "hosting", "vps", "cloud", "cdn", "fastly", "cloudflare",
)