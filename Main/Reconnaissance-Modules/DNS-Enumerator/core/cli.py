import argparse


def parse_args():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Comprehensive DNS Enumeration & Security Analysis Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 main.py -d example.com --records --axfr --sec
  python3 main.py -d example.com --all -o results.json
  python3 main.py -d example.com --records --anomaly --proxy http://127.0.0.1:8080
  python3 main.py -d example.com --sec -p 5353
        """
    )

    p.add_argument("-d", "--domain",       required=True,  help="Target domain (e.g. example.com)")

    p.add_argument("-p", "--port",         type=int, default=53,
                   help="DNS port (default: 53)")
    p.add_argument("--proxy",              help="HTTP proxy for dangling checks (e.g. http://127.0.0.1:8080)")
    p.add_argument("--timeout",            type=int, default=5,
                   help="DNS query timeout in seconds (default: 5)")
    p.add_argument("--threads",            type=int, default=10,
                   help="Thread count for concurrent checks (default: 10)")
    p.add_argument("--nameserver",         nargs="+", metavar="NS",
                   help="Custom nameserver IP(s) (e.g. --nameserver 1.1.1.1 8.8.8.8)")

    p.add_argument("--records",            action="store_true", help="Query DNS records (A, AAAA, MX, NS, TXT, SOA, ...)")
    p.add_argument("--axfr",               action="store_true", help="Attempt zone transfer (AXFR)")
    p.add_argument("--reverse",            action="store_true", help="Reverse DNS (PTR) lookup")
    p.add_argument("--dangling",           action="store_true", help="Detect dangling DNS / subdomain takeover candidates")
    p.add_argument("--sec",                action="store_true", help="DNSSEC validation (DNSKEY, DS, RRSIG, NSEC/NSEC3)")
    p.add_argument("--anomaly",            action="store_true", help="TTL anomaly analysis (fast-flux detection)")

    p.add_argument("--all",                action="store_true", help="Run all modules")
    p.add_argument("--record-types",       default=None,
                   help="Comma-separated record types to query (default: all standard types)")

    p.add_argument("-o", "--output",       help="Save JSON results to file")
    p.add_argument("--no-color",           action="store_true", help="Disable ANSI color output")
    p.add_argument("--quiet",              action="store_true",
                   help="Suppress all terminal output; write only stderr progress signals "
                        "(JSON lines). Output is saved to Scan-Results/dns_enum.json "
                        "automatically — no -o flag needed.")

    return p.parse_args()