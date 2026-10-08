#!/usr/bin/env python3
"""
appsec.py - Web Application Security Analysis Tool
Entry point: parses CLI arguments and dispatches to the core engine.
"""

from core.cli import build_parser
from core.engine import Engine
from core.logger import get_logger

log = get_logger("appsec")


def main() -> None:
    """Parse arguments, validate inputs, and run the analysis engine."""
    parser = build_parser()
    args = parser.parse_args()

    # At least one module must be selected
    if not any([args.waf, args.limit, args.captcha]):
        parser.error(
            "No analysis module selected. "
            "Use --waf, --limit, --captcha, or any combination."
        )

    log.info("=== AppSec Analysis Tool ===")
    log.info(f"Target domain : {args.domain}")
    log.info(
        f"Modules active: "
        f"{'WAF ' if args.waf else ''}"
        f"{'RateLimit ' if args.limit else ''}"
        f"{'Captcha' if args.captcha else ''}"
    )

    engine = Engine(args)
    engine.run()


if __name__ == "__main__":
    main()