"""
core/cli.py - Command-line interface definition.

Keeps all argparse logic in one place so appsec.py stays clean and each
module does not have to know how its flags are defined.
"""

import argparse


def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the top-level argument parser.

    Flags
    -----
    -d / --domain   Target host to analyse (required).
                    Accepts bare hostnames, full URLs, or IP addresses.

    --waf           Enable the WAF-detection module.
    --limit         Enable the rate-limit probing module.
    --captcha       Enable the CAPTCHA/bot-protection detection module.

    --timeout       Per-request HTTP timeout in seconds (default: 10).
    --threads       Number of concurrent request threads (default: 5).
    --output        Write a JSON report to this file path (optional).
    --verbose       Raise log verbosity to DEBUG level.

    Returns
    -------
    argparse.ArgumentParser
        Fully configured parser; call .parse_args() on it in the entry point.
    """
    parser = argparse.ArgumentParser(
        prog="appsec",
        description=(
            "Web Application Security Analysis Tool\n"
            "Probe a target domain for WAF presence, rate-limiting, "
            "and CAPTCHA/bot-protection mechanisms."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  appsec.py -d example.com --waf\n"
            "  appsec.py -d https://shop.example.com --waf --limit --captcha\n"
            "  appsec.py -d 10.0.0.5 --limit --output report.json\n"
        ),
    )

    # ── Target ───────────────────────────────────────────────────────────────
    parser.add_argument(
        "-d", "--domain",
        required=True,
        metavar="TARGET",
        help=(
            "Target domain, URL, or IP address to analyse. "
            "If no scheme is given, HTTPS is assumed."
        ),
    )

    # ── Module toggles ────────────────────────────────────────────────────────
    modules = parser.add_argument_group("analysis modules")

    modules.add_argument(
        "--waf",
        action="store_true",
        default=False,
        help="Detect Web Application Firewall (WAF) signatures.",
    )
    modules.add_argument(
        "--limit",
        action="store_true",
        default=False,
        help="Probe for rate-limiting and throttling behaviour.",
    )
    modules.add_argument(
        "--captcha",
        action="store_true",
        default=False,
        help="Identify CAPTCHA and bot-protection challenges.",
    )

    # ── Network / runtime options ─────────────────────────────────────────────
    runtime = parser.add_argument_group("runtime options")

    runtime.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10).",
    )
    runtime.add_argument(
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="Number of concurrent worker threads (default: 5).",
    )
    runtime.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Save the full JSON report to FILE (default: print to stdout).",
    )
    runtime.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose DEBUG output.",
    )

    return parser