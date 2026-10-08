#!/usr/bin/env python3

import sys
import io
from datetime import datetime, timezone

try:
    import dns.resolver
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[!] Run: pip install -r requirements.txt")
    sys.exit(1)

from core.cli     import parse_args
from core.network import build_resolver, get_session
from core.engine  import Engine
from core.exporter import export_json
from core.ui      import C, info, disable_color


def main():
    args = parse_args()

    domain = (
        args.domain
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
        .split("/")[0]
    )
    args.domain = domain

    _silent_mode = args.quiet or bool(args.output)
    _real_stdout = sys.stdout
    if _silent_mode:
        sys.stdout = io.StringIO()

    if args.no_color:
        disable_color()

    print(f"\n{C.BOLD}{C.CYAN}  ██████╗ ███╗   ██╗███████╗")
    print(f"  ██╔══██╗████╗  ██║██╔════╝")
    print(f"  ██║  ██║██╔██╗ ██║███████╗")
    print(f"  ██║  ██║██║╚██╗██║╚════██║")
    print(f"  ██████╔╝██║ ╚████║███████║")
    print(f"  ╚═════╝ ╚═╝  ╚═══╝╚══════╝  Enumerator{C.RESET}")
    print(f"\n  {C.DIM}Target : {C.RESET}{C.BOLD}{domain}{C.RESET}")
    print(f"  {C.DIM}Time   : {C.RESET}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {C.DIM}Port   : {C.RESET}{args.port}")
    if args.proxy:
        print(f"  {C.DIM}Proxy  : {C.RESET}{args.proxy}")

    resolver          = build_resolver(proxy=args.proxy, port=args.port)
    resolver.timeout  = args.timeout

    if args.nameserver:
        resolver.nameservers = [args.nameserver]
        info(f"Using custom nameserver: {args.nameserver}")

    session = get_session(proxy=args.proxy)

    engine = Engine(args, resolver, session)
    report = engine.run()

    if _silent_mode:
        sys.stdout = _real_stdout

    output_path = export_json(report, args.output if args.output else None)

    if not _silent_mode:
        print(f"\n{C.DIM}{'─' * 60}{C.RESET}\n")


if __name__ == "__main__":
    main()
