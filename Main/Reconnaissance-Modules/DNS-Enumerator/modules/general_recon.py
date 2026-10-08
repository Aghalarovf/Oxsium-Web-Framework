import dns.reversename
import dns.resolver

from modules.base import BaseDNSModule
from core.ui import C, ok, fail, warn, info, banner


RECORD_TYPES_CORE = [
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR",
]

RECORD_TYPES_SECURITY = [
    "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM",
    "CDNSKEY", "CDS",
    "TLSA", "SSHFP", "SMIMEA", "OPENPGPKEY",
    "IPSECKEY",
]

# RFC 7208: SPF record type (99) is deprecated; SPF policy is carried in TXT records.
# Do not query for "SPF" — resolvers no longer recognise it.
RECORD_TYPES_MAIL: list = []

RECORD_TYPES_SERVICE = [
    "HTTPS", "SVCB",
    "NAPTR", "URI", "LOC",
    "HINFO", "RP",
]

RECORD_TYPES_LEGACY = [
    "AFSDB", "CERT", "DNAME",
    "HIP", "KX",
    "DHCID", "CSYNC", "ZONEMD",
    "EUI48", "EUI64",
    "NID", "L32", "L64", "LP",
    "WKS", "X25", "ISDN", "RT", "NSAP",
    "APL", "GPOS",
    "A6",
]

RECORD_TYPES = (
    RECORD_TYPES_CORE
    + RECORD_TYPES_SECURITY
    + RECORD_TYPES_MAIL
    + RECORD_TYPES_SERVICE
    + RECORD_TYPES_LEGACY
)

RECORD_CATEGORY = {}
for _t in RECORD_TYPES_CORE:     RECORD_CATEGORY[_t] = "Core"
for _t in RECORD_TYPES_SECURITY: RECORD_CATEGORY[_t] = "Security"
for _t in RECORD_TYPES_MAIL:     RECORD_CATEGORY[_t] = "Mail"
for _t in RECORD_TYPES_SERVICE:  RECORD_CATEGORY[_t] = "Service"
for _t in RECORD_TYPES_LEGACY:   RECORD_CATEGORY[_t] = "Legacy"


class GeneralReconModule(BaseDNSModule):

    def query_records(self, types: list = None) -> dict:
        banner("DNS Records")
        types   = types or RECORD_TYPES
        results = {}

        current_category = None
        for rtype in types:
            cat = RECORD_CATEGORY.get(rtype, "Other")
            if cat != current_category:
                current_category = cat
                print(f"\n  {C.BOLD}── {cat} Records {'─' * (40 - len(cat))}{C.RESET}")

            try:
                answers = self.resolver.resolve(self.domain, rtype)
                records = [r.to_text() for r in answers]
                results[rtype] = {"records": records, "ttl": answers.rrset.ttl}
                for rec in records:
                    ok(f"{C.BOLD}{rtype:12}{C.RESET}  {rec}")
            except dns.resolver.NoAnswer:
                results[rtype] = {"records": [], "ttl": None}
            except dns.resolver.NXDOMAIN:
                fail(f"{rtype:12}  Domain does not exist")
                break
            except dns.resolver.NoNameservers:
                results[rtype] = {"records": [], "ttl": None}
            except Exception as e:
                results[rtype] = {"records": [], "ttl": None}
                warn(f"{rtype:12}  {e}")

        found = sum(1 for v in results.values() if v["records"])
        print(f"\n  {C.DIM}Queried {len(types)} record types — {found} with data{C.RESET}")
        return results

    def reverse_lookup(self) -> dict:
        banner("Reverse DNS Lookup")
        results = {}
        ips     = []

        try:
            a_records = self.resolver.resolve(self.domain, "A")
            ips       = [str(r) for r in a_records]
        except Exception:
            pass

        try:
            aaaa_records = self.resolver.resolve(self.domain, "AAAA")
            ips         += [str(r) for r in aaaa_records]
        except Exception:
            pass

        if not ips:
            fail("No IP addresses resolved for reverse lookup")
            return results

        for ip in ips:
            try:
                rev      = dns.reversename.from_address(ip)
                ptr      = self.resolver.resolve(rev, "PTR")
                hostname = str(ptr[0])
                results[ip] = hostname
                ok(f"{ip}  →  {hostname}")
            except Exception:
                results[ip] = None
                warn(f"{ip}  →  No PTR record")

        return results