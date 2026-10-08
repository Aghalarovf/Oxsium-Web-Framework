#!/usr/bin/env python3
"""email_infra.py - Email Infrastructure Enumeration CLI Entry Point.

Parses command-line arguments and dispatches to the async Engine
orchestrator. Handles setup, teardown, result export, and exit codes.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import sys
from pathlib import Path

if hasattr(sys.stdout, 'buffer') and sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'buffer') and sys.stderr.encoding and sys.stderr.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
from typing import NoReturn

from core.cli import build_arg_parser, resolve_active_modules
from core.engine import Engine


JSON_OUTPUT_PATH = str(Path(__file__).resolve().parents[2] / "Scan-Results" / "email_infra.json")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments and return a validated namespace."""
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.domain:
        parser.error("the following arguments are required: -d/--domain")

    return args


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point that runs the engine and exports results."""
    active_modules = resolve_active_modules(args)

    engine = Engine(
        domains=args.domain,
        active_modules=active_modules,
        output_file=JSON_OUTPUT_PATH if args.json else None,
        color=not args.no_color,
        timeout=args.timeout,
        concurrency=args.concurrency,
        nameserver=args.nameserver,
    )

    try:
        results = await engine.run()
    except Exception as exc:
        print(f"[ERR] Engine run failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(f"  Results exported to {JSON_OUTPUT_PATH}")

    return 0


def main() -> NoReturn:
    """Synchronous entry point."""

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_args()
    exit_code = asyncio.run(async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()