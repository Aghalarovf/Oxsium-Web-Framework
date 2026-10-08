#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from typing import Optional

from core import normalize_domain, load_keys
from core.config import __version__
from sources import resolve_sources
from engine import (
    scan,
    resolve_hosts,
    detect_wildcard,
    check_status_codes,
    check_takeovers,
    emit_results,
    list_sources,
    run_health_check,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subdomain-hunter",
        description="Passive subdomain scanner - CT, passive DNS, archives & threat intel",
        epilog="Example: python subdomain-hunter.py -d example.com -c --takeover --json -o subs.txt",
    )
    parser.add_argument("-d", "--domain",
                        help="target domain (or pipe via stdin)")
    parser.add_argument("-s", "--sources",
                        help="comma-separated source names (default: all enabled)")
    parser.add_argument("-l", "--list-sources", action="store_true",
                        help="list available sources and exit")
    parser.add_argument("--health-check", action="store_true",
                        help="show sources with missing API keys, then continue scan")
    parser.add_argument("-o", "--output",
                        help="write results to file")
    parser.add_argument("--json", action="store_true",
                        help="emit structured JSON to stdout")
    parser.add_argument("--api-keys", metavar="PATH",
                        help="path to api_keys.json")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="per-source debug logging")
    parser.add_argument("--timeout", type=int, default=30,
                        help="HTTP timeout in seconds (default: 30)")
    parser.add_argument("--workers", type=int, default=5,
                        help="concurrent sources (default: 5)")
    parser.add_argument("-c", "--check-status", action="store_true",
                        help="probe each resolved subdomain over HTTP(S)")
    scheme_group = parser.add_mutually_exclusive_group()
    scheme_group.add_argument("--https-only", action="store_true")
    scheme_group.add_argument("--http-only", action="store_true")
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--status-workers", type=int, default=10,
                        help="concurrent DNS/HTTP probes (default: 10)")
    parser.add_argument("--resolve", action="store_true",
                        help="perform DNS resolution (default: names only)")
    parser.add_argument("--takeover", action="store_true",
                        help="check for subdomain takeover on dangling CNAMEs")
    parser.add_argument("--no-wildcard-filter", action="store_true",
                        help="skip automatic wildcard DNS filtering")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress all output except the final completion signal")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_sources:
        list_sources()
        return 0

    if not args.domain:
        if not sys.stdin.isatty():
            args.domain = sys.stdin.read().strip()
        else:
            build_parser().print_usage(sys.stderr)
            print("error: -d/--domain is required (or pipe a domain via stdin)", file=sys.stderr)
            return 2

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    keys = load_keys(args.api_keys)

    if args.health_check:
        run_health_check(keys)

    if args.verbose and not args.quiet:
        print(f"[*] target domain : {domain}", file=sys.stderr)
        print(f"[*] api key file  : {args.api_keys or 'default search'}", file=sys.stderr)
        print(f"[*] sources       : {args.sources or 'all enabled'}", file=sys.stderr)

    source_classes, skipped = resolve_sources(
        args.sources.split(",") if args.sources else None
    )
    if not args.quiet:
        for message in skipped:
            print(f"[!] {message}", file=sys.stderr)

    if not source_classes:
        print("error: no enabled sources to run", file=sys.stderr)
        return 1

    domain, results, unique = scan(
        domain,
        source_classes,
        max_workers=args.workers,
        timeout=args.timeout,
        verbose=args.verbose,
        keys=keys,
    )

    hosts = None
    did_status = False
    takeover_count = 0

    if unique and args.resolve:
        # Wildcard detection
        wildcard_ip: Optional[str] = None
        if not args.no_wildcard_filter:
            wildcard_ip = detect_wildcard(domain)
            if wildcard_ip and not args.quiet:
                print(f"[!] wildcard DNS detected ({wildcard_ip}) — filtering false positives", file=sys.stderr)

        if args.verbose and not args.quiet:
            print(f"[*] resolving {len(unique)} subdomains (workers={args.status_workers})", file=sys.stderr)

        hosts = resolve_hosts(unique, workers=args.status_workers, wildcard_ip=wildcard_ip)

        # HTTP status probing
        if args.check_status:
            schemes = ["https", "http"]
            if args.https_only:
                schemes = ["https"]
            elif args.http_only:
                schemes = ["http"]
            if args.verbose and not args.quiet:
                n = sum(1 for h in hosts.values() if h.ips)
                print(f"[*] probing {n} resolved hosts x {len(schemes)} scheme(s)", file=sys.stderr)
            check_status_codes(
                hosts,
                timeout=args.timeout,
                workers=args.status_workers,
                follow_redirects=args.follow_redirects,
                schemes=schemes,
            )
            did_status = True

        # Takeover detection
        if args.takeover:
            candidates = sum(1 for h in hosts.values() if not h.ips and h.cname_chain)
            if args.verbose and candidates and not args.quiet:
                print(f"[*] checking {candidates} dangling CNAME(s) for takeover", file=sys.stderr)
            takeover_count = check_takeovers(
                hosts,
                timeout=args.timeout,
                workers=args.status_workers,
            )

    elif args.check_status and not args.resolve and not args.quiet:
        print("[!] --check-status ignored because --resolve was not set", file=sys.stderr)

    out_file = None
    if args.output:
        try:
            out_file = open(args.output, "w", encoding="utf-8", newline="\n")
        except OSError as exc:
            print(f"error: cannot write output file {args.output}: {exc}\n", file=sys.stderr)
            return 1

    if not args.quiet:
        emit_results(
            domain, results, unique,
            as_json=args.json,
            out_file=out_file,
            hosts=hosts,
            did_status=did_status,
            takeover_count=takeover_count,
        )
    elif out_file is not None:
        emit_results(
            domain, results, unique,
            as_json=args.json,
            out_file=out_file,
            hosts=hosts,
            did_status=did_status,
            takeover_count=takeover_count,
        )

    if out_file is not None:
        out_file.close()

    if args.quiet:
        import json as _json
        print(_json.dumps({"event": "module_done", "module": "subdomains"}))

    return 0


if __name__ == "__main__":
    sys.exit(main())