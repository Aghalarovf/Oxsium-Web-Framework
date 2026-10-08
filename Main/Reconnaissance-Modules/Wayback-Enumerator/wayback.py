#!/usr/bin/env python3

import sys
import asyncio

from core.cli import build_parser
from core.logger import Logger
from core.engine import ArchiveEngine


def main():
    parser = build_parser()
    args = parser.parse_args()

    logger = Logger(verbose=args.verbose)
    logger.banner()

    if not args.domain:
        logger.error("Domain is required. Usage: webarchive.py -d example.com")
        parser.print_help()
        sys.exit(1)

    try:
        engine = ArchiveEngine(args=args, logger=logger)
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        logger.warning("\n[!] Stopped by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Critical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()