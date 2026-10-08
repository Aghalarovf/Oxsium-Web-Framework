import argparse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanConfig:
    intercept_files: list[str]
    target: Optional[str] = None
    social: bool = False
    emails: bool = False
    meta: bool = False
    docs: bool = False
    all_modules: bool = False
    output_format: str = "json"
    json_output: bool = False
    verbose: bool = False
    no_color: bool = False


class CLIParser:
    BANNER = r"""
  _____ __  __ _____        ___  ____ ___ _   _ _____
 / ____|  \/  |  __ \      / _ \/ ___|_ _| \ | |_   _|
| (___ | \  / | |__) |    | | | \___ \| ||  \| | | |
 \___ \| |\/| |  _  /     | | | |___) | || |\  | | |
 ____) | |  | | | \ \     | |_| |____/___| | \  | | |
|_____/|_|  |_|_|  \_\     \___/            |_|  \_| |_|

          Social Metadata OSINT Tool v1.0.0
    """

    def __init__(self):
        self.parser = self._build_parser()

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="smosint",
            description="Offline OSINT analysis of captured traffic: social links, emails, HTML metadata and files",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self._build_epilog(),
        )

        input_group = parser.add_argument_group("Input")
        input_group.add_argument(
            "--intercept",
            metavar="FILE",
            dest="intercept_files",
            nargs="+",
            required=True,
            help="Captured traffic file(s): .json, .jsonl or .zip containing json/jsonl files. No network requests are ever sent.",
        )
        input_group.add_argument(
            "-d", "--target",
            metavar="URL",
            help="Optional URL or domain. Only records whose request URL host matches it are analysed.",
        )

        module_group = parser.add_argument_group("Modules (all run when none is selected)")
        module_group.add_argument(
            "--social",
            action="store_true",
            help="Social media profile links and app store links found in every captured body",
        )
        module_group.add_argument(
            "--emails",
            action="store_true",
            help="All email patterns found in every captured body",
        )
        module_group.add_argument(
            "--meta",
            action="store_true",
            help="Standard meta, Open Graph, Twitter Cards and HTML leak detection",
        )
        module_group.add_argument(
            "--docs",
            action="store_true",
            help="Files and file types found in request URLs and response bodies (static html/css/js excluded)",
        )
        module_group.add_argument(
            "-a", "--all",
            dest="all_modules",
            action="store_true",
            help="Run all modules",
        )

        output_group = parser.add_argument_group("Output")
        output_group.add_argument(
            "--json",
            dest="json_output",
            action="store_true",
            help="Save all module results to ../../../Scan-Results/social_metadata_results.json",
        )
        output_group.add_argument(
            "-f", "--format",
            dest="output_format",
            choices=["json", "html", "txt"],
            default="json",
            help="Output format (default: json)",
        )
        output_group.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Verbose output",
        )
        output_group.add_argument(
            "--no-color",
            action="store_true",
            help="Disable colored output",
        )

        return parser

    def _build_epilog(self) -> str:
        return """
Examples:
  smosint --intercept traffic.json
  smosint --intercept traffic.jsonl --social --emails
  smosint --intercept traffic.json traffic.jsonl -d example.com --docs --json
  smosint --intercept capture.zip --all --json
        """

    def parse(self, argv=None) -> ScanConfig:
        args = self.parser.parse_args(argv)

        target = args.target
        if target and not target.startswith(("http://", "https://")):
            target = "https://" + target

        return ScanConfig(
            intercept_files=args.intercept_files,
            target=target,
            social=args.social,
            emails=args.emails,
            meta=args.meta,
            docs=args.docs,
            all_modules=args.all_modules,
            output_format=args.output_format,
            json_output=args.json_output,
            verbose=args.verbose,
            no_color=args.no_color,
        )

    def print_banner(self):
        print(self.BANNER)
