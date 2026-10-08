import argparse


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-infra-enum",
        description="Email infrastructure enumeration and reconnaissance tool.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  main.py -d example.com --dns-sec\n"
            "  main.py -d example.com --all --json\n"
            "  main.py -d a.com b.com --provider-gateways --harvest-recon\n"
            "  main.py -d example.com --breaches\n"
        ),
    )

    parser.add_argument(
        "-d", "--domain",
        nargs="+",
        required=True,
        metavar="DOMAIN",
        help="One or more target domains to enumerate.",
    )

    modules = parser.add_argument_group("Module Flags")

    modules.add_argument(
        "--dns-sec", "--ds",
        dest="dns_sec",
        action="store_true",
        help="Email DNS security & authentication (SPF, DKIM, DMARC, MX).",
    )
    modules.add_argument(
        "--provider-gateways", "--pg",
        dest="provider_gateways",
        action="store_true",
        help="Identify email providers, relays, and security gateways.",
    )
    modules.add_argument(
        "--harvest-recon", "--hr",
        dest="harvest_recon",
        action="store_true",
        help="Public email harvesting and OSINT reconnaissance.",
    )
    modules.add_argument(
        "--breaches",
        dest="breaches",
        action="store_true",
        help="Email breach and exposure analysis.",
    )
    modules.add_argument(
        "--service-config", "--sc",
        dest="service_config",
        action="store_true",
        help="Service configuration and delivery testing (SMTP, autodiscover, catch-all).",
    )
    modules.add_argument(
        "--history-subdomains", "--hs",
        dest="history_subdomains",
        action="store_true",
        help="Subdomain mail discovery and historical MX tracking.",
    )
    modules.add_argument(
        "--exchange",
        dest="exchange",
        action="store_true",
        help="Exchange & webmail recon — HudsonRock stealer exposure and compromised credential URLs.",
    )
    modules.add_argument(
        "--ntlm",
        dest="ntlm",
        action="store_true",
        help="OWA/ECP header & body fingerprinting (requires --exchange).",
    )
    modules.add_argument(
        "--all",
        action="store_true",
        help="Enable all enumeration modules.",
    )
    modules.add_argument(
        "--test-email",
        dest="test_email",
        metavar="EMAIL",
        default=None,
        help=(
            "Validate one or more emails against Exchange Autodiscover v2 "
            "(no credentials, no lockout risk). "
            "Accepts comma-separated list: user1@domain.com,user2@domain.com. "
            "Requires --exchange or --ntlm."
        ),
    )

    output = parser.add_argument_group("Output Options")

    output.add_argument(
        "--json",
        action="store_true",
        help="Export results as JSON to ../../../Scan-Results/email_infra.json.",
    )
    output.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in the terminal.",
    )
    output.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 10).",
    )
    output.add_argument(
        "--concurrency",
        type=int,
        default=10,
        metavar="N",
        help="Maximum concurrent requests (default: 10).",
    )
    output.add_argument(
        "--nameserver",
        metavar="IP",
        default=None,
        help="Custom DNS nameserver IP to use for resolution (default: system).",
    )

    return parser


_IMPLEMENTED_MODULES = {"dns_sec", "provider_gateways", "harvest_recon", "breaches"}


def resolve_active_modules(args: argparse.Namespace) -> dict[str, bool]:
    if args.all:
        test_emails_all: list[str] = []
        if args.test_email:
            test_emails_all = [e.strip() for e in args.test_email.split(",") if e.strip()]
        return {
            "dns_sec": True,
            "provider_gateways": True,
            "harvest_recon": True,
            "breaches": True,
            "service_config": True,
            "history_subdomains": False,
            "exchange": True,
            "ntlm": False,
            "test_emails": test_emails_all,
        }
    ntlm_active = args.ntlm and args.exchange
    test_emails: list[str] = []
    if args.test_email:
        test_emails = [e.strip() for e in args.test_email.split(",") if e.strip()]
    return {
        "dns_sec": args.dns_sec,
        "provider_gateways": args.provider_gateways,
        "harvest_recon": args.harvest_recon,
        "breaches": args.breaches,
        "service_config": args.service_config,
        "history_subdomains": False,
        "exchange": args.exchange,
        "ntlm": ntlm_active,
        "test_emails": test_emails,
    }