import argparse
import sys
from core.engine import Engine
from core.logger import get_logger, set_quiet

logger = get_logger()

AVAILABLE_MODULES = {
    "webappanalyzer":  ("modules.webappanalyzer",   "WebAppAnalyzer"),
    "retire-js":       ("modules.retire_js",         "RetireJS"),
    "waf":             ("modules.wafw00f",            "WafW00f"),
    "headers":         ("modules.header_scanner",    "HeaderScanner"),
    "cmseek":          ("modules.cmseek",            "CMSeeK"),
    "wappalyzer-next": ("modules.wappalyzer_next",   "WappalyzerNext"),
    "favicon":         ("modules.favicon_recon",     "FaviconRecon"),
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="tech_fingerprint",
        description="Technology fingerprinting orchestrator"
    )
    parser.add_argument(
        "-d", "--domain",
        required="--list-modules" not in sys.argv,
        help="Target domain or URL (e.g. example.com or https://example.com)"
    )
    parser.add_argument(
        "--webappanalyzer",
        action="store_true",
        help="Run Wappalyzer technology detection module"
    )
    parser.add_argument(
        "--retire-js",
        action="store_true",
        dest="retire_js",
        help="Run Retire.js vulnerable library detection module"
    )
    parser.add_argument(
        "--waf",
        action="store_true",
        help="Run WAF detection module (wafw00f)"
    )
    parser.add_argument(
        "--headers",
        action="store_true",
        help="Run HTTP header fingerprinting module"
    )
    parser.add_argument(
        "--cmseek",
        action="store_true",
        help="Run CMSeeK CMS detection module"
    )
    parser.add_argument(
        "--wappalyzer-next",
        action="store_true",
        dest="wappalyzer_next",
        help="Run wappalyzer-next browser-based detection module"
    )
    parser.add_argument(
        "--wappalyzer-next-mode",
        dest="wappalyzer_next_mode",
        default="balanced",
        choices=["fast", "balanced", "full"],
        help="Scan mode for wappalyzer-next: fast | balanced | full (default: balanced)"
    )
    parser.add_argument(
        "--favicon",
        action="store_true",
        help="Run favicon recon module (hash, tech fingerprint, search queries)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available modules"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        default=None,
        help="Output JSON file path (default: tech_fingerprint.json in current directory)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress all output except the final JSON path"
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        dest="list_modules",
        help="List all available modules and exit"
    )
    return parser.parse_args()


def resolve_modules(args) -> list:
    selected = {}

    if args.list_modules:
        print("\nAvailable modules:")
        for name in AVAILABLE_MODULES:
            print(f"  --{name}")
        print()
        sys.exit(0)

    if args.all or args.webappanalyzer:
        selected["webappanalyzer"] = AVAILABLE_MODULES["webappanalyzer"]

    if args.all or args.retire_js:
        selected["retire-js"] = AVAILABLE_MODULES["retire-js"]

    if args.all or args.waf:
        selected["waf"] = AVAILABLE_MODULES["waf"]

    if args.all or args.headers:
        selected["headers"] = AVAILABLE_MODULES["headers"]

    if args.all or args.cmseek:
        selected["cmseek"] = AVAILABLE_MODULES["cmseek"]

    if args.all or args.wappalyzer_next:
        selected["wappalyzer-next"] = AVAILABLE_MODULES["wappalyzer-next"]

    if args.all or args.favicon:
        selected["favicon"] = AVAILABLE_MODULES["favicon"]

    if not selected:
        logger.error(
            "No modules selected. Use --webappanalyzer, --retire-js, --waf, "
            "--headers, --cmseek, --all, or --list-modules."
        )
        sys.exit(1)

    instances = []
    for key, (module_path, class_name) in selected.items():
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name)
            if key == "wappalyzer-next":
                instances.append(cls(mode=args.wappalyzer_next_mode))
            else:
                instances.append(cls())
            logger.info(f"Module loaded: {class_name}")
        except Exception as e:
            logger.error(f"Failed to load module '{key}': {e}")
            sys.exit(1)

    return instances


def main():
    args = parse_args()

    if args.quiet:
        set_quiet(True)

    modules = resolve_modules(args)

    engine = Engine(domain=args.domain, modules=modules, output_path=args.output)
    output = engine.run()

    print(f"Output saved to: {output['output_file']}")


if __name__ == "__main__":
    main()