import argparse
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from .intercept_reader import normalize_host


@dataclass
class ScanConfig:
    intercept: List[str] = field(default_factory=list)
    domain: Optional[str] = None
    headers: bool = False
    leak: bool = False
    leaks: bool = False
    cors: bool = False
    score: bool = False
    secure: bool = False
    ws: bool = False
    cookies: bool = False
    redirect: bool = False
    cache: bool = False
    ratelimit: bool = False
    output: Optional[str] = None
    output_format: str = "txt"
    verbose: bool = False


class CLIParser:
    def __init__(self):
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="headers_analyzer",
            description="Web Pentesting - Offline HTTP Headers Analysis Tool (Burp Suite traffic)",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  python headers_analyzer.py --intercept traffic.json --cors --score\n"
                "  python headers_analyzer.py --intercept a.json b.jsonl --all -o result.json\n"
                "  python headers_analyzer.py --intercept ./burp_exports/ --all -o report.html\n"
                "  python headers_analyzer.py --intercept traffic.json --ws\n"
                "  python headers_analyzer.py --intercept traffic.json --ws -o websocket.json\n"
                "  python headers_analyzer.py --intercept traffic.json --cookies\n"
                "  python headers_analyzer.py --intercept traffic.json --ratelimit\n"
                "  python headers_analyzer.py --intercept traffic.json --leaks\n"
                "  python headers_analyzer.py --intercept traffic.json -d example.com --all\n"
            ),
        )

        parser.add_argument(
            "--intercept",
            required=True,
            nargs="+",
            metavar="PATH",
            help="Burp Suite traffic file(s) (.json / .jsonl) or directories containing them"
        )

        parser.add_argument(
            "-d", "--domain",
            metavar="DOMAIN",
            default=None,
            help="Target domain; the intercept file is analyzed only if it contains traffic for this host (or its subdomains), otherwise the scan is aborted"
        )

        module_group = parser.add_argument_group("Module Selection")
        module_group.add_argument(
            "--secure",
            action="store_true",
            default=False,
            help="Run Security Headers analysis [sec_headers]"
        )
        module_group.add_argument(
            "--headers",
            action="store_true",
            default=False,
            help="Run Security Headers analysis"
        )
        module_group.add_argument(
            "--leak",
            action="store_true",
            default=False,
            help="Run Information Leakage analysis"
        )
        module_group.add_argument(
            "--leaks",
            action="store_true",
            default=False,
            help="Run Header Leak analysis (debug, credentials, topology, environment, identity, versions, tracing and secret values in headers)"
        )
        module_group.add_argument(
            "--cors",
            action="store_true",
            default=False,
            help="Run CORS & Cross-Domain analysis"
        )
        module_group.add_argument(
            "--score",
            action="store_true",
            default=False,
            help="Run Security Score evaluation"
        )
        module_group.add_argument(
            "--ws",
            action="store_true",
            default=False,
            help="Run WebSocket handshake analysis (101 detection, Origin/CSWSH, auth model, protocols)"
        )
        module_group.add_argument(
            "--cookies",
            action="store_true",
            default=False,
            help="Run Cookie & JWT analysis (attribute audit, JWT decoding, value classification)"
        )
        module_group.add_argument(
            "--redirect",
            action="store_true",
            default=False,
            help="Run Redirect analysis (open-redirect indicators, protocol downgrade, cross-host targets)"
        )
        module_group.add_argument(
            "--cache",
            action="store_true",
            default=False,
            help="Run Cache-Control analysis (sensitive responses exposed to caching)"
        )
        module_group.add_argument(
            "--ratelimit",
            action="store_true",
            default=False,
            help="Run Rate Limit analysis (X-RateLimit-*, RateLimit-*, Retry-After consistency and throttling signals)"
        )
        module_group.add_argument(
            "--all",
            action="store_true",
            default=False,
            help="Run all modules"
        )

        output_group = parser.add_argument_group("Output Options")
        output_group.add_argument(
            "-o", "--output",
            metavar="FILE",
            help="Output file path (.txt / .json / .html)"
        )
        output_group.add_argument(
            "-v", "--verbose",
            action="store_true",
            default=False,
            help="Enable verbose output"
        )

        return parser

    def parse(self, args=None) -> ScanConfig:
        parsed = self.parser.parse_args(args)

        output_format = "txt"
        if parsed.output:
            ext = parsed.output.rsplit(".", 1)[-1].lower()
            if ext in ("json", "html", "txt"):
                output_format = ext
            else:
                print(f"[ERROR] Unsupported output format '.{ext}'. Use .txt, .json, or .html")
                sys.exit(1)

        domain = None
        if parsed.domain is not None:
            domain = normalize_host(parsed.domain)
            if not domain:
                print(f"[ERROR] Invalid domain '{parsed.domain}'")
                sys.exit(1)

        run_all = parsed.all
        return ScanConfig(
            intercept=parsed.intercept,
            domain=domain,
            headers=run_all or parsed.headers,
            leak=run_all or parsed.leak,
            leaks=run_all or parsed.leaks,
            cors=run_all or parsed.cors,
            score=run_all or parsed.score,
            secure=run_all or parsed.secure,
            ws=run_all or parsed.ws,
            cookies=run_all or parsed.cookies,
            redirect=run_all or parsed.redirect,
            cache=run_all or parsed.cache,
            ratelimit=run_all or parsed.ratelimit,
            output=parsed.output,
            output_format=output_format,
            verbose=parsed.verbose,
        )
