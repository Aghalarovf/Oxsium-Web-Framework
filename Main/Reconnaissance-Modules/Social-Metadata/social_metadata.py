import asyncio
import sys
import warnings


warnings.filterwarnings("ignore", category=ResourceWarning)


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


_configure_utf8_stdio()

from core.cli import CLIParser
from core.logger import Logger
from core.scanner import Scanner


def main():
    parser = CLIParser()
    parser.print_banner()

    try:
        config = parser.parse()
    except SystemExit as exc:
        sys.exit(exc.code)

    logger = Logger(
        verbose=config.verbose,
        no_color=config.no_color,
    )

    scanner = Scanner(config=config, logger=logger)

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        sys.exit(0)
    except Exception as exc:
        logger.critical(f"Unhandled error: {exc}")
        if config.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
