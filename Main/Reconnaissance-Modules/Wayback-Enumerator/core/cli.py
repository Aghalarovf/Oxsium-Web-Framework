import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webarchive",
        description="WebArchive Scanner — Passive Archive-Based Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webarchive.py -d example.com
  python webarchive.py -d example.com --sources --params
  python webarchive.py -d example.com --cdx --status 200
  python webarchive.py -d example.com --extract --extract-types robots,sitemap
  python webarchive.py -d example.com --urls --params -o results.json
  python webarchive.py -d example.com --all -o report
        """,
    )

    target = parser.add_argument_group("Target")
    target.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="Target domain (e.g., example.com)",
    )

    modules = parser.add_argument_group("Modules")
    modules.add_argument(
        "--sources",
        action="store_true",
        help="Run multi-source archive URL collector (Wayback, CommonCrawl, OTX, URLScan, VirusTotal, GhostArchive, Arquivo.pt, UKWA, Hudson Rock, IntelX)",
    )
    modules.add_argument(
        "--extract",
        action="store_true",
        help="Extract and parse historical critical files (robots.txt, sitemap.xml, security.txt, crossdomain.xml, ...) from Wayback snapshots",
    )
    modules.add_argument(
        "--urls",
        action="store_true",
        help="Run URL classifier and endpoint extractor",
    )
    modules.add_argument(
        "--params",
        action="store_true",
        help="Run historical parameter miner and sensitive data detector",
    )
    modules.add_argument(
        "--cdx",
        action="store_true",
        help="Run raw CDX query and filtering engine",
    )
    modules.add_argument(
        "--diff",
        action="store_true",
        help="Run snapshot date comparison module",
    )
    modules.add_argument(
        "--all",
        action="store_true",
        help="Run all modules simultaneously",
    )

    cdx_opts = parser.add_argument_group("CDX Filters")
    cdx_opts.add_argument(
        "--status",
        metavar="CODE",
        type=int,
        help="Filter by HTTP status code (e.g., 200, 301, 404)",
    )
    cdx_opts.add_argument(
        "--mime",
        metavar="TYPE",
        help="Filter by MIME type (e.g., application/json, text/html)",
    )
    cdx_opts.add_argument(
        "--wildcard",
        action="store_true",
        default=True,
        help="Enable wildcard query, *.domain.com/* (default: True)",
    )

    output = parser.add_argument_group("Output")
    output.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to file (e.g., results.json, report.csv, urls.txt)",
    )
    output.add_argument(
        "--format",
        choices=["json", "csv", "txt", "wordlist"],
        default="json",
        help="Output format (default: json)",
    )
    output.add_argument(
        "--wordlist",
        action="store_true",
        help="Export parameter wordlist for fuzzing",
    )

    extract = parser.add_argument_group("Extract")
    extract.add_argument(
        "--extract-limit",
        metavar="N",
        type=int,
        default=10,
        help="Maximum snapshots analyzed per file, sampled across the timeline (default: 10)",
    )
    extract.add_argument(
        "--extract-types",
        metavar="LIST",
        help="Comma-separated file types: robots,sitemap,security,crossdomain,clientaccess,humans,ads,wellknown (default: all)",
    )
    extract.add_argument(
        "--extract-raw",
        action="store_true",
        help="Include raw snapshot content in the exported results",
    )

    providers = parser.add_argument_group("Providers")
    providers.add_argument(
        "--providers",
        metavar="LIST",
        help=(
            "Comma-separated providers for --sources "
            "(wayback,commoncrawl,otx,urlscan,virustotal,ghostarchive,arquivo,ukwa,hudsonrock,intelx). "
            "Default: all except intelx"
        ),
    )
    providers.add_argument(
        "--api-keys",
        metavar="PATH",
        help="Path to api_keys.json (virustotal, intelx, intelx_host, urlscan, otx)",
    )

    perf = parser.add_argument_group("Performance")
    perf.add_argument(
        "--concurrency",
        metavar="N",
        type=int,
        default=5,
        help="Number of concurrent requests (default: 5)",
    )
    perf.add_argument(
        "--timeout",
        metavar="SEC",
        type=int,
        default=20,
        help="Timeout in seconds for each request (default: 20)",
    )
    perf.add_argument(
        "--retries",
        metavar="N",
        type=int,
        default=4,
        help="Number of retries for failed requests (default: 4)",
    )
    perf.add_argument(
        "--delay",
        metavar="SEC",
        type=float,
        default=1.0,
        help="Delay between requests in seconds (default: 1.0)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )

    return parser