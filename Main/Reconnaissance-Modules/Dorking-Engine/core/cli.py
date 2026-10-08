import argparse
import sys
from core.engine import Engine
from core.logger import Logger


BANNER = r"""
  ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗███╗   ██╗ ██████╗
  ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║████╗  ██║██╔════╝
  ██║  ██║██║   ██║██████╔╝█████╔╝ ██║██╔██╗ ██║██║  ███╗
  ██║  ██║██║   ██║██╔══██╗██╔═██╗ ██║██║╚██╗██║██║   ██║
  ██████╔╝╚██████╔╝██║  ██║██║  ██╗██║██║ ╚████║╚██████╔╝
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝

  Google Dorking Reconnaissance Framework
  For authorized penetration testing only.
"""

FLAG_MODULE_MAP = {
    "api":       "apiandtestenv",
    "discovery": "fileanddirectory",
    "data":      "sensdata",
    "tech":      "serverandtech",
    "creds":     "credentialandauth",
}


class CLI:
    def __init__(self):
        self.logger = Logger()
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="dorking",
            description="Google Dorking Reconnaissance Framework",
            formatter_class=argparse.RawTextHelpFormatter,
        )

        parser.add_argument(
            "-d", "--domain",
            required=True,
            metavar="DOMAIN",
            help="Target domain (e.g. example.com)",
        )

        module_group = parser.add_argument_group(
            "scan modules",
            "Select one or more modules to run. Omit all to run every module.",
        )
        module_group.add_argument(
            "--api",
            action="store_true",
            help="API & test environment discovery (apiandtestenv)",
        )
        module_group.add_argument(
            "--discovery",
            action="store_true",
            help="File & directory discovery (fileanddirectory)",
        )
        module_group.add_argument(
            "--data",
            action="store_true",
            help="Sensitive data & OSINT (sensdata)",
        )
        module_group.add_argument(
            "--tech",
            action="store_true",
            help="Server & technology fingerprinting (serverandtech)",
        )
        module_group.add_argument(
            "--creds",
            action="store_true",
            help="Credentials & authentication discovery (credentialandauth)",
        )

        parser.add_argument(
            "-o", "--output",
            metavar="FILE",
            help="Output file path (optional)",
        )

        parser.add_argument(
            "-f", "--format",
            choices=["txt", "json", "csv", "html"],
            default="txt",
            metavar="FORMAT",
            help="Export format: txt, json, csv, html (default: txt)",
        )

        parser.add_argument(
            "--delay",
            type=float,
            default=2.0,
            metavar="SECONDS",
            help="Delay between requests in seconds (default: 2.0)",
        )

        parser.add_argument(
            "--timeout",
            type=int,
            default=10,
            metavar="SECONDS",
            help="Request timeout in seconds (default: 10)",
        )

        parser.add_argument(
            "--proxy",
            metavar="URL",
            help="Proxy URL (e.g. http://127.0.0.1:8080)",
        )

        parser.add_argument(
            "--serpapi-key",
            metavar="KEY",
            help="SerpAPI key for reliable Google results (no rate limits)",
        )

        parser.add_argument(
            "--no-banner",
            action="store_true",
            help="Suppress banner output",
        )

        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print generated dorks without making requests",
        )

        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose output",
        )

        return parser

    def _resolve_modules(self, args) -> list[str]:
        selected = [
            module_key
            for flag, module_key in FLAG_MODULE_MAP.items()
            if getattr(args, flag, False)
        ]
        if not selected:
            return list(FLAG_MODULE_MAP.values())
        return selected

    def run(self):
        args = self.parser.parse_args()

        if not args.no_banner:
            print(BANNER)

        self.logger.set_verbose(args.verbose)

        modules = self._resolve_modules(args)

        self.logger.info(f"Domain   : {args.domain}")
        self.logger.info(f"Modules  : {', '.join(modules)}")
        self.logger.info(f"Format   : {args.format}")

        if args.proxy:
            self.logger.info(f"Proxy    : {args.proxy}")

        if args.dry_run:
            self.logger.warning("Dry-run mode enabled. No requests will be made.")

        serpapi_key = getattr(args, "serpapi_key", None)

        if serpapi_key:
            self.logger.info("Mode     : SerpAPI (reliable)")
        else:
            self.logger.info("Mode     : Direct Google (may hit rate limits)")

        engine = Engine(
            target=args.domain,
            modules=modules,
            output=args.output,
            fmt=args.format,
            delay=args.delay,
            timeout=args.timeout,
            proxy=args.proxy,
            serpapi_key=serpapi_key,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )

        try:
            engine.run()
        except KeyboardInterrupt:
            self.logger.warning("\nInterrupted by user.")
            sys.exit(0)
        except Exception as exc:
            self.logger.error(f"Fatal error: {exc}")
            sys.exit(1)