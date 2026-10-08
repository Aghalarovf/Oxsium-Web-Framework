#!/usr/bin/env python3
"""
whois-checker — Domain & IP intelligence recon tool
Usage:
  python3 whois-checker.py -d example.com
  python3 whois-checker.py -d example.com -p http://127.0.0.1:8080
  python3 whois-checker.py -d example.com --proxy socks5://127.0.0.1:9050 --json
  python3 whois-checker.py -i 1.1.1.1 --ip-only
  python3 whois-checker.py -f domains.txt --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple

from core.config import DEFAULT_TIMEOUT, DEFAULT_UA, TOOL, VERSION
from core.models import Report
from core.net import Net
from core.utils import days_until, idna, tld_of, now_utc

import modules.blacklist as _blacklist
import modules.cdn as _cdn
import modules.cdn_advanced as _cdn_advanced
import modules.cross_search as _cross_search
import modules.dns as _dns
import modules.historical as _historical
import modules.http as _http
import modules.ip as _ip
import modules.whois as _whois

# Default output path when --json is used
_JSON_OUTPUT = Path(__file__).parent.parent.parent / "Scan-Results" / "whois_results.json"


# ─── Colour helper ────────────────────────────────────────────────────────────

class C:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _c(self, code: str, text: Any) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else str(text)

    def bold(self, t: Any) -> str:    return self._c("1", t)
    def dim(self, t: Any) -> str:     return self._c("2", t)
    def red(self, t: Any) -> str:     return self._c("31", t)
    def green(self, t: Any) -> str:   return self._c("32", t)
    def yellow(self, t: Any) -> str:  return self._c("33", t)
    def blue(self, t: Any) -> str:    return self._c("34", t)
    def magenta(self, t: Any) -> str: return self._c("35", t)
    def cyan(self, t: Any) -> str:    return self._c("36", t)


# ─── Rendering ────────────────────────────────────────────────────────────────

def _val(v: Any, empty: str = "-") -> str:
    if v is None or v == "" or v == []:
        return empty
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else empty
    return str(v)


def _kv(col: C, key: str, value: Any, warn: bool = False) -> None:
    pretty = _val(value)
    if warn and pretty != "-":
        pretty = col.yellow(pretty)
    print(f"  {col.dim(key.ljust(18))} {pretty}")


def _contact(col: C, title: str, contact: Any) -> None:
    print(f"  {col.bold(title)}")
    d = contact.to_dict() if hasattr(contact, "to_dict") else (contact or {})
    if not d or not any(d.values()):
        print(f"    {col.dim('no data / redacted')}")
        return
    for k in ("name", "organization", "address", "country", "phone", "email"):
        if d.get(k):
            print(f"    {k.ljust(16)} {d[k]}")


def render(report: Report, col: C) -> None:
    line = "=" * 72
    print(col.cyan(line))
    print(col.bold(f" {TOOL.upper()}  v{VERSION}   Domain & IP Intelligence"))
    print(col.cyan(line))
    _kv(col, "Queried at", report.queried_at)
    _kv(col, "Domain", report.domain)
    _kv(col, "TLD", f".{report.tld}" if report.tld else None)

    if report.whois:
        w = report.whois
        print()
        print(col.bold("[ WHOIS / RDAP ]"))
        _kv(col, "Created", w.created)
        _kv(col, "Updated", w.updated)
        exp_s = w.expires
        if w.expires and w.days_until_expiry is not None:
            exp_s = f"{w.expires}  ({w.days_until_expiry} days left)"
        _kv(col, "Expires", exp_s, warn=w.expiry_warning)
        _kv(col, "Status", w.status)
        _kv(col, "Registrar", w.registrar)
        _kv(col, "IANA ID", w.registrar_iana_id)
        _kv(col, "DNSSEC", w.dnssec)
        _kv(col, "Sources", w.sources)
        priv = w.privacy
        if priv:
            flag = col.yellow("YES") if priv.enabled else col.green("NO")
            _kv(col, "Privacy/Guard", f"{flag}  {priv.note}")
            if priv.indicators:
                _kv(col, "Privacy hints", priv.indicators)

        print()
        print(col.bold("[ CONTACTS ]"))
        contacts = w.contacts or {}
        for role in ("registrant", "admin", "tech", "billing"):
            _contact(col, role.capitalize(), contacts.get(role))

    if report.dns:
        d = report.dns
        print()
        print(col.bold("[ DNS ]"))
        _kv(col, "A", d.a)
        _kv(col, "AAAA", d.aaaa)
        _kv(col, "NS", d.ns)
        _kv(col, "MX", d.mx)
        _kv(col, "CNAME", d.cname)
        if d.txt:
            _kv(col, "TXT", "; ".join(d.txt[:6]) + (" ..." if len(d.txt) > 6 else ""))

    if report.ips:
        print()
        print(col.bold("[ IP INTELLIGENCE ]"))
        for rec in report.ips:
            print(f"  {col.cyan(rec.ip)}")
            _kv(col, "PTR", rec.ptr)
            as_s = f"AS{rec.asn} {rec.as_name or ''}".strip() if rec.asn else rec.as_name
            _kv(col, "ASN", as_s)
            _kv(col, "Org", rec.org)
            _kv(col, "ISP", rec.isp)
            geo = ", ".join(x for x in (rec.city, rec.region, rec.country) if x)
            _kv(col, "GeoIP", geo or None)
            if rec.lat is not None and rec.lon is not None:
                _kv(col, "Coordinates", f"{rec.lat}, {rec.lon}  (approx.)")
            _kv(col, "Timezone", rec.timezone)
            _kv(col, "Usage type", rec.usage_type, warn=bool(rec.hosting) or "datacenter" in str(rec.usage_type))
            _kv(col, "Datacenter", "yes" if rec.hosting else "no / unclear")
            _kv(col, "Source", rec.source)

    if report.cdn_advanced:
        ca = report.cdn_advanced
        print()
        print(col.bold("[ CDN / WAF (ADVANCED) ]"))
        behind = col.yellow("YES") if ca.behind_cdn else col.green("NO")
        _kv(col, "Behind CDN", behind)
        _kv(col, "Vendor(s)", ca.vendors)
        if ca.waf_detected:
            _kv(col, "WAF detected", col.yellow(", ".join(ca.waf_detected)))
        _kv(col, "Anycast", col.yellow("YES") if ca.anycast else "no")
        _kv(col, "Note", ca.note)
        for vendor, ev in (ca.evidence or {}).items():
            print(f"    {col.magenta(vendor)}")
            for item in ev:
                print(f"      - {item}")
    elif report.cdn:
        cdn = report.cdn
        print()
        print(col.bold("[ CDN / EDGE ]"))
        behind = col.yellow("YES") if cdn.behind_cdn else col.green("NO")
        _kv(col, "Behind CDN", behind)
        _kv(col, "Vendor(s)", cdn.vendors)
        _kv(col, "Note", cdn.note)
        for vendor, ev in (cdn.evidence or {}).items():
            print(f"    {col.magenta(vendor)}")
            for item in ev:
                print(f"      - {item}")

    if report.http:
        print()
        print(col.bold("[ HTTP PROBE ]"))
        for p in report.http:
            _kv(col, p.url, f"{p.status or '-'} -> {p.final_url}")

    if report.blacklist:
        bl = report.blacklist
        print()
        print(col.bold("[ BLACKLIST / REPUTATION ]"))
        risk_color = {
            "clean":  col.green,
            "low":    col.yellow,
            "medium": col.yellow,
            "high":   col.red,
        }.get(bl.risk, col.dim)
        _kv(col, "Risk", risk_color(bl.risk.upper()))
        _kv(col, "Score", f"{bl.score} list(s) flagged")
        _kv(col, "IPs checked", bl.ips_checked)
        if bl.hits:
            print(f"  {col.bold('Hits:')}")
            for h in bl.hits:
                tag = col.red(f"[{h.type.upper()}]")
                print(f"    {tag} {h.list_name}  ({h.query} -> {h.response})")
        else:
            print(f"  {col.green('No blacklist hits')}")

    if report.cross_search:
        cs = report.cross_search
        print()
        print(col.bold("[ CROSS-SEARCH / PIVOT ]"))
        _kv(col, "Registrant email", cs.registrant_email)
        _kv(col, "Registrant org", cs.registrant_org)
        _kv(col, "Nameservers", cs.nameservers)
        _kv(col, "IPs pivoted", cs.ips_pivoted)
        _kv(col, "Pivots used", cs.pivots_used)
        seen_d: set[str] = set()
        related = []
        for r in cs.related_domains:
            if r.domain != cs.domain and r.domain not in seen_d:
                seen_d.add(r.domain)
                related.append(r)
        _kv(col, "Related domains", f"{len(related)} found")
        for rd in related[:20]:
            print(f"    {col.cyan(rd.domain)}  via {rd.pivot} ({rd.value})  [{rd.source}]")
        if len(related) > 20:
            print(f"    {col.dim(f'... and {len(related) - 20} more')}")

    if report.historical:
        hs = report.historical
        print()
        print(col.bold("[ HISTORICAL ]"))
        if hs.rdap_events:
            print(f"  {col.bold('RDAP Events:')}")
            for ev in hs.rdap_events:
                print(f"    {ev.get('action', '?').ljust(24)} {ev.get('date', '-')}")
        if hs.archive:
            _kv(col, "First archived", hs.archive.first_seen)
            _kv(col, "Last archived", hs.archive.last_seen)
            _kv(col, "Archive source", hs.archive.source)
        if hs.snapshots:
            print(f"  {col.bold('WHOIS Snapshots:')}")
            for snap in hs.snapshots[:5]:
                date_s = snap.date or snap.created or "-"
                reg_s  = snap.registrar or "-"
                ns_s   = ", ".join(snap.name_servers[:3]) or "-"
                print(f"    {date_s}  registrar={reg_s}  ns=[{ns_s}]  [{snap.source}]")
            if len(hs.snapshots) > 5:
                print(f"    {col.dim(f'... and {len(hs.snapshots) - 5} more snapshots')}")

    if report.errors:
        print()
        print(col.bold("[ ERRORS ]"))
        for e in report.errors:
            print(f"  {col.red(e)}")
    print()


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyze(
    net: Net,
    domain: Optional[str],
    ip_arg: Optional[str],
    do_whois: bool,
    do_ip: bool,
    do_http: bool,
    whois_server: Optional[str],
    do_blacklist: bool = False,
    do_cross_search: bool = False,
    do_historical: bool = False,
    do_cdn_advanced: bool = False,
) -> Report:
    report = Report(
        tool=TOOL,
        version=VERSION,
        queried_at=now_utc().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    if domain:
        domain = idna(domain)
        report.domain = domain
        report.tld = tld_of(domain)

    if do_whois and domain:
        try:
            report.whois = _whois.lookup(net, domain, whois_server)
            left = days_until(report.whois.expires)
            report.whois.days_until_expiry = left
            report.whois.expiry_warning = bool(left is not None and left <= 30)
        except Exception as exc:
            report.errors.append(f"whois: {exc}")

    dns_result = None
    if domain:
        dns_result = _dns.lookup(domain, net.timeout)
        if report.whois and not dns_result.ns:
            dns_result.ns = list(report.whois.name_servers or [])
        report.dns = dns_result

    targets: List[str] = []
    if ip_arg:
        targets.append(ip_arg)
    elif dns_result:
        targets.extend(dns_result.a)
        targets.extend(dns_result.aaaa)
    seen: set = set()
    unique_ips = [ip for ip in targets if not (ip in seen or seen.add(ip))]  # type: ignore

    http_probes = []
    if do_http and domain:
        try:
            http_probes = _http.probe(net, domain)
            report.http = http_probes
        except Exception as exc:
            report.errors.append(f"http: {exc}")

    if do_ip:
        for ip in unique_ips:
            try:
                report.ips.append(_ip.lookup(net, ip))
            except Exception as exc:
                report.errors.append(f"ip {ip}: {exc}")

    if domain and dns_result:
        if do_cdn_advanced:
            try:
                adv = _cdn_advanced.detect_advanced(domain, dns_result, report.ips, http_probes)
                report.cdn_advanced = adv
                report.cdn = adv.to_cdn_result()
            except Exception as exc:
                report.errors.append(f"cdn_advanced: {exc}")
                report.cdn = _cdn.detect(domain, dns_result, report.ips, http_probes)
        else:
            report.cdn = _cdn.detect(domain, dns_result, report.ips, http_probes)

    if do_blacklist and domain:
        try:
            report.blacklist = _blacklist.check(net, domain, dns_result, report.ips)
        except Exception as exc:
            report.errors.append(f"blacklist: {exc}")

    if do_cross_search and domain:
        try:
            whois_dict = report.whois.to_dict() if report.whois else None
            report.cross_search = _cross_search.search(
                net, domain, dns_result, report.ips, whois_data=whois_dict
            )
        except Exception as exc:
            report.errors.append(f"cross_search: {exc}")

    if do_historical and domain:
        try:
            report.historical = _historical.lookup(net, domain)
        except Exception as exc:
            report.errors.append(f"historical: {exc}")

    return report


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description="Domain WHOIS/RDAP + IP intelligence recon tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s -d example.com
  %(prog)s -d example.az -v
  %(prog)s -d example.com -p http://127.0.0.1:8080
  %(prog)s -d example.com --proxy socks5://127.0.0.1:9050 --json
  %(prog)s -d example.com --whois-only
  %(prog)s -i 1.1.1.1 --ip-only
  %(prog)s -f domains.txt --json
""",
    )
    p.add_argument("-d", "--domain", help="Target domain name")
    p.add_argument("-i", "--ip", dest="ip_addr", help="Target IP address")
    p.add_argument("-f", "--file", help="File with domains, one per line")
    p.add_argument("-p", "--proxy", help="Proxy URL (http:// or socks5://)")
    p.add_argument("-j", "--json", action="store_true",
                   help=f"Save JSON report to {_JSON_OUTPUT}")
    p.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"Network timeout in seconds (default {DEFAULT_TIMEOUT})")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logs to stderr")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress text report")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP(S) CDN probe")
    p.add_argument("--no-whois", action="store_true", help="Skip WHOIS/RDAP")
    p.add_argument("--whois-only", action="store_true", help="Only WHOIS/RDAP")
    p.add_argument("--ip-only", action="store_true", help="Only IP intelligence")
    p.add_argument("--whois-server", help="Force a specific WHOIS server")
    p.add_argument("--ua", default=DEFAULT_UA, help="Custom User-Agent string")
    p.add_argument("--no-blacklist", action="store_true",
                   help="Skip DNS blacklist / reputation check")
    p.add_argument("--no-cross-search", action="store_true",
                   help="Skip NS/IP pivot cross-search")
    p.add_argument("--no-historical", action="store_true",
                   help="Skip historical WHOIS and Wayback Machine lookup")
    p.add_argument("--no-cdn-advanced", action="store_true",
                   help="Use basic CDN detection instead of advanced WAF fingerprinting")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def load_targets(args: argparse.Namespace) -> List[Tuple[Optional[str], Optional[str]]]:
    targets: List[Tuple[Optional[str], Optional[str]]] = []
    if args.domain:
        targets.append((args.domain, args.ip_addr))
    elif args.ip_addr:
        targets.append((None, args.ip_addr))
    if getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                item = line.strip()
                if not item or item.startswith("#"):
                    continue
                targets.append((item, None))
    return targets


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    targets = load_targets(args)
    if not targets:
        parser.error("specify -d/--domain, -i/--ip or -f/--file")

    do_whois = not args.no_whois and not args.ip_only
    do_ip    = not args.whois_only
    do_http  = not args.no_http and not args.whois_only and not args.ip_only

    do_blacklist    = not getattr(args, "no_blacklist", False)
    do_cross_search = not getattr(args, "no_cross_search", False)
    do_historical   = not getattr(args, "no_historical", False)
    do_cdn_advanced = not getattr(args, "no_cdn_advanced", False)

    color_on = (
        not args.no_color
        and sys.stdout.isatty()
        and not args.json
        and not os.environ.get("NO_COLOR")
    )
    col = C(color_on)
    net = Net(proxy=args.proxy, timeout=args.timeout, ua=args.ua, verbose=args.verbose)

    reports: List[dict] = []
    rc = 0
    for domain, ip_addr in targets:
        try:
            report = analyze(
                net, domain, ip_addr, do_whois, do_ip, do_http, args.whois_server,
                do_blacklist=do_blacklist,
                do_cross_search=do_cross_search,
                do_historical=do_historical,
                do_cdn_advanced=do_cdn_advanced,
            )
            reports.append(report.to_dict())
            if not args.quiet and not args.json:
                render(report, col)
        except Exception as exc:
            rc = 1
            print(f"[-] failed {domain or ip_addr}: {exc}", file=sys.stderr)

    payload: Any = reports[0] if len(reports) == 1 else reports

    if args.json:
        out_path = _JSON_OUTPUT
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
            fh.write("\n")
        if not args.quiet:
            print(f"[+] saved {out_path}")

    return rc


if __name__ == "__main__":
    sys.exit(main())