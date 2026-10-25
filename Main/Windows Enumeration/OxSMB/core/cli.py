import argparse
import logging
import sys

from core.config import EngineConfig
from core.smb_targets import load_targets_from_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oxsmb.py",
        description="OxSMB - modular SMB enumeration toolkit",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "--host",
        action="append",
        default=[],
        help="Target host, IP, CIDR range or octet range (repeatable)",
    )
    target_group.add_argument(
        "--target-file",
        dest="target_file",
        help="File containing one target per line",
    )
    target_group.add_argument(
        "--port",
        "-P",
        type=int,
        default=445,
        help="SMB TCP port",
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--user", dest="username", default="", help="Username")
    auth_group.add_argument("-p", "--pass", dest="password", default="", help="Password")
    auth_group.add_argument(
        "-H", "--hash", dest="ntlm_hash", default="", help="NTLM hash, LM:NT or NT only"
    )
    auth_group.add_argument("-d", "--domain", dest="domain", default="", help="Authentication domain")

    module_group = parser.add_argument_group("Modules")
    module_group.add_argument(
        "--common",
        action="store_true",
        help="Run every module found under modules/common regardless of mode",
    )
    module_group.add_argument(
        "--custom",
        dest="custom_modules",
        default="",
        help="Comma separated module names to run in custom mode",
    )
    module_group.add_argument(
        "--info",
        dest="run_info",
        action="store_true",
        help="Run every module found under modules/system_info regardless of mode",
    )
    module_group.add_argument(
        "--dc",
        dest="run_dc",
        action="store_true",
        help="Run every module found under modules/domain_controller regardless of mode",
    )
    module_group.add_argument(
        "--vuln",
        dest="run_vuln",
        action="store_true",
        help="Run every module found under modules/vulnerabilities regardless of mode",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "-S", "--stealth", action="store_const", dest="mode", const="stealth",
        help="Stealth mode: single thread, high timeout, jitter delay",
    )
    mode_group.add_argument(
        "-A", "--aggressive", action="store_const", dest="mode", const="aggressive",
        help="Aggressive mode: high concurrency, low timeout",
    )
    mode_group.add_argument(
        "-UU", "--ultra", action="store_const", dest="mode", const="ultra",
        help="Ultra mode: maximum concurrency, fail-fast",
    )
    mode_group.add_argument(
        "-C", "--custom-mode", action="store_const", dest="mode", const="custom",
        help="Custom mode: run only the modules passed via --custom",
    )
    parser.set_defaults(mode="normal")

    tuning_group = parser.add_argument_group("Tuning overrides")
    tuning_group.add_argument("--threads", type=int, default=None, help="Override thread count")
    tuning_group.add_argument("--connect-timeout", type=float, default=None, help="Override connect timeout")
    tuning_group.add_argument("--read-timeout", type=float, default=None, help="Override read timeout")
    tuning_group.add_argument("--retries", type=int, default=None, help="Override retry count")

    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", dest="output_path", default=None, help="Write JSON report to file")
    output_group.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity")
    output_group.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    return parser


def parse_args(argv=None) -> EngineConfig:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = list(args.host)
    if args.target_file:
        targets.extend(load_targets_from_file(args.target_file))

    if not targets:
        parser.error("At least one --host or --target-file is required")

    custom_modules = [m.strip() for m in args.custom_modules.split(",") if m.strip()]

    mode_name = args.mode

    config = EngineConfig(
        targets=targets,
        port=args.port,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        domain=args.domain,
        mode_name=mode_name,
        run_common=args.common,
        run_info=args.run_info,
        run_dc=args.run_dc,
        run_vuln=args.run_vuln,
        custom_modules=custom_modules,
        output_path=args.output_path,
        verbosity=args.verbose,
    )

    if args.threads is not None:
        config.threads = args.threads
    if args.connect_timeout is not None:
        config.connect_timeout = args.connect_timeout
    if args.read_timeout is not None:
        config.read_timeout = args.read_timeout
    if args.retries is not None:
        config.retries = args.retries

    config.log_level = logging.ERROR if args.quiet else logging.INFO

    return config
