import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        prog="tls-scanner",
        description="TLS/SSL Certificate and Security Scanner for Web Pentesting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python certificate-enumerator.py -d example.com
  python certificate-enumerator.py -d example.com --all
  python certificate-enumerator.py -d example.com --certs --protocols
  python certificate-enumerator.py -d example.com --all --json -o report.json
  python certificate-enumerator.py -d example.com --sni custom.example.com --certs
  python certificate-enumerator.py -d example.com -p 8443 --protocols --ciphers
        """,
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-d", "--domain",
        required=True,
        metavar="DOMAIN",
        help="Target domain or IP address to scan",
    )
    target_group.add_argument(
        "--sni",
        metavar="SNI_NAME",
        default=None,
        help="Override Server Name Indication (SNI) hostname",
    )
    target_group.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        metavar="PORT",
        help="Target port (default: 443)",
    )
    target_group.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 10)",
    )
    target_group.add_argument(
        "--starttls",
        choices=["smtp", "ftp", "imap", "pop3", "xmpp"],
        default=None,
        metavar="PROTOCOL",
        help="Use STARTTLS for the given protocol",
    )

    module_group = parser.add_argument_group("Scan Modules")
    module_group.add_argument(
        "--all",
        action="store_true",
        help="Run all available scan modules",
    )
    module_group.add_argument(
        "--certs",
        action="store_true",
        help="Certificate chain, details, SANs and CT log checks",
    )
    module_group.add_argument(
        "--protocols",
        action="store_true",
        help="TLS/SSL protocol support matrix, handshake details and ALPN",
    )
    module_group.add_argument(
        "--ciphers",
        action="store_true",
        help="Cipher suite inventory and security classification",
    )
    module_group.add_argument(
        "--pfs",
        action="store_true",
        help="Perfect Forward Secrecy and session resumption checks",
    )
    module_group.add_argument(
        "--headers",
        action="store_true",
        help="HTTP security headers audit and score breakdown",
    )
    module_group.add_argument(
        "--groups",
        action="store_true",
        help="Supported named groups and DH parameter details",
    )
    module_group.add_argument(
        "--fallback",
        action="store_true",
        help="Downgrade and fallback protection (TLS_FALLBACK_SCSV)",
    )
    module_group.add_argument(
        "--network",
        action="store_true",
        help="DNS, CAA, DANE/TLSA and network-level checks",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="Save results to file (JSON is selected for .json files or with --json)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output",
    )
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress banner and progress output",
    )

    args = parser.parse_args()

    if args.all:
        args.certs = True
        args.protocols = True
        args.ciphers = True
        args.pfs = True
        args.headers = True
        args.groups = True
        args.fallback = True
        args.network = True

    active_modules = [
        args.certs, args.protocols, args.ciphers, args.pfs,
        args.headers, args.groups,
        args.fallback, args.network,
    ]
    if not any(active_modules):
        parser.print_help()
        sys.exit(0)

    if args.sni is None:
        args.sni = args.domain

    return args