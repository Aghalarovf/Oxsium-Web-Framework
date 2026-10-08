from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

from core.engine   import Engine
from core.reporter import Reporter
from modules.base  import Finding
from modules.secrets      import SecretsModule
from modules.endpoints    import EndpointsModule
from modules.sourcemaps   import SourceMapsModule
from modules.dom_xss      import DomXssModule
from modules.dependencies import DependenciesModule
from modules.routes       import RoutesModule
from modules.logic_vulns  import LogicVulnsModule
from modules.obfuscation  import ObfuscationModule
from modules.postmessage  import PostMessageModule
from modules.csp_sri      import CspSriModule


MODULE_REGISTRY = {
    "secrets":     SecretsModule,
    "endpoints":   EndpointsModule,
    "maps":        SourceMapsModule,
    "dom-xss":     DomXssModule,
    "deps":        DependenciesModule,
    "routes":      RoutesModule,
    "logic":       LogicVulnsModule,
    "obfuscation": ObfuscationModule,
    "postmessage": PostMessageModule,
    "csp":         CspSriModule,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="js_files",
        description="JS Analyzer – Deep JavaScript Security Inspection Engine",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("-d",      metavar="URL",  dest="url",  help="Single JS or HTML URL to scan")
    source.add_argument("--file",  metavar="FILE",              help="Local JS file to scan")
    source.add_argument("--dir",   metavar="DIR",               help="Directory of JS files to scan recursively")
    source.add_argument("--html",  metavar="URL",               help="HTML page – extract and scan all <script src=...>")

    modules = p.add_argument_group("modules")
    modules.add_argument("--secrets",     action="store_true", help="Run the Secrets module      (API keys, tokens, credentials)")
    modules.add_argument("--endpoints",   action="store_true", help="Run the Endpoints module    (REST routes, GraphQL ops, WebSockets)")
    modules.add_argument("--maps",        action="store_true", help="Run the Source Maps module  (source map detection and recovery)")
    modules.add_argument("--dom-xss",     action="store_true", help="Run the DOM XSS module      (dangerous sinks, eval chains, JSX injection)")
    modules.add_argument("--deps",        action="store_true", help="Run the Dependencies module (library fingerprinting, CVE lookup)")
    modules.add_argument("--routes",      action="store_true", help="Run the Routes module       (React/Vue router parsing, auth-gated paths)")
    modules.add_argument("--logic",       action="store_true", help="Run the Logic Vulns module  (client-side auth, hardcoded crypto, insecure storage)")
    modules.add_argument("--obfuscation", action="store_true", help="Run the Obfuscation module  (JSFuck, AAEncode, entropy scoring)")
    modules.add_argument("--postmessage", action="store_true", help="Run the PostMessage module  (wildcard targetOrigin, missing origin checks)")
    modules.add_argument("--csp",         action="store_true", help="Run the CSP & SRI module    (integrity attributes, nonce analysis, unsafe policies)")

    output = p.add_argument_group("output")
    output.add_argument("--output",    metavar="FILE",  help="Save JSON report to file")
    output.add_argument("--no-color",  action="store_true",   help="Disable ANSI color output")
    output.add_argument("--json-only", action="store_true",   help="Print only JSON output, no console table")
    output.add_argument("--severity",  metavar="LEVEL",       help="Minimum severity to display: critical|high|medium|low|info")

    runtime = p.add_argument_group("runtime")
    runtime.add_argument("--workers",     type=int, default=10, metavar="N", help="Async worker count (default: 10)")
    runtime.add_argument("--timeout",     type=int, default=20, metavar="S", help="HTTP timeout in seconds (default: 20)")
    runtime.add_argument("--no-beautify", action="store_true",                help="Skip JS beautification before analysis")
    runtime.add_argument("--quiet",       action="store_true",                help="Suppress all output except findings")
    runtime.add_argument("--verbose",     action="store_true",                help="Enable debug logging")

    return p


def setup_logger(verbose: bool, quiet: bool) -> logging.Logger:
    logger = logging.getLogger("js_analyzer")
    if quiet:
        logger.setLevel(logging.ERROR)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    return logger


def resolve_modules(args: argparse.Namespace) -> list:
    flag_map = {
        "secrets":     "secrets",
        "endpoints":   "endpoints",
        "maps":        "maps",
        "dom_xss":     "dom-xss",
        "deps":        "deps",
        "routes":      "routes",
        "logic":       "logic",
        "obfuscation": "obfuscation",
        "postmessage": "postmessage",
        "csp":         "csp",
    }
    selected = [
        MODULE_REGISTRY[registry_key]
        for attr, registry_key in flag_map.items()
        if getattr(args, attr, False)
    ]
    return selected or list(MODULE_REGISTRY.values())


def filter_by_severity(findings: list[Finding], level: str | None) -> list[Finding]:
    if not level:
        return findings
    threshold = SEVERITY_ORDER.get(level.lower(), 4)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 4) <= threshold]


async def run(args: argparse.Namespace) -> int:
    logger   = setup_logger(args.verbose, args.quiet)
    reporter = Reporter(use_color=not args.no_color)

    selected_modules = resolve_modules(args)

    engine = Engine(
        modules  = selected_modules,
        logger   = logger,
        workers  = args.workers,
        timeout  = args.timeout,
        beautify = not args.no_beautify,
    )

    results      = []
    target_label = ""

    if args.url:
        url = args.url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        target_label = url
        if url.lower().endswith((".js", ".mjs", ".cjs")):
            results = [await engine.scan_url(url)]
        else:
            results = await engine.scan_html(url)

    elif args.html:
        results      = await engine.scan_html(args.html)
        target_label = args.html

    elif args.file:
        results      = [await engine.scan_file(args.file)]
        target_label = args.file

    elif args.dir:
        results      = await engine.scan_directory(args.dir)
        target_label = args.dir

    all_findings: list[Finding] = []
    for r in results:
        if r.error:
            logger.error(f"Error scanning {r.target.value}: {r.error}")
            continue
        all_findings.extend(r.findings)

    all_findings = filter_by_severity(all_findings, args.severity)

    if args.json_only:
        print(reporter.to_json(all_findings, target_label))
    else:
        reporter.to_console_grouped(results, target_label)

    if args.output:
        reporter.save_json(all_findings, target_label, args.output)
        logger.info(f"JSON report saved → {args.output}")

    critical_or_high = sum(1 for f in all_findings if f.severity in ("critical", "high"))
    return 1 if critical_or_high else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))