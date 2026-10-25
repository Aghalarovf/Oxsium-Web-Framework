#!/usr/bin/env python3
import logging
import os
import sys

sys.pycache_prefix = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PyCache")

import time

from core.animation import ScanAnimator
from core.cli import parse_args
from core.engine import Engine
from core.exceptions import ConfigError, OxSMBError
from core.logger import OxLogger
from core.output import HumanReporter
from modules.common import attack_vector, remediation

BANNER = r"""
   ____       _____ __  _______
  / __ \_  __/ ___//  |/  / __ )
 / / / / |/_/\__ \/ /|_/ / __  |
/ /_/ />  < ___/ / /  / / /_/ /
\____/_/|_|/____/_/  /_/_____/
"""

BANNER_TAGLINE = "Modular SMB Enumeration & Security Audit Toolkit"


def print_banner():
    sys.stdout.write(BANNER)
    sys.stdout.write(f"  {BANNER_TAGLINE}\n")
    sys.stdout.write("=" * 79 + "\n")


def build_security_analysis(output, verbosity: int) -> dict:
    security_by_target = {}
    if verbosity < 2:
        return security_by_target

    for entry in output.get_results():
        target = entry["target"]
        modules_list = entry["modules"]
        findings = attack_vector.evaluate_findings(modules_list)
        attack_vectors = attack_vector.evaluate_attack_vectors(modules_list, matched_findings=findings)
        remediations = remediation.evaluate_remediations(modules_list, matched_findings=findings)
        security_by_target[target] = {
            "findings": findings,
            "attack_vectors": attack_vectors,
            "remediations": remediations,
        }

    return security_by_target


def main():
    config = parse_args()

    logger = OxLogger.get(level=config.log_level)

    if config.log_level < logging.ERROR:
        print_banner()

    try:
        engine = Engine(config)
    except ConfigError as exc:
        logger.error(str(exc))
        sys.exit(1)

    start_time = time.time()

    animator = ScanAnimator(label="Scanning in progress")
    animator.start()

    try:
        output = engine.run(on_target_started=animator.set_total, on_target_done=lambda target: animator.tick())
    except ConfigError as exc:
        animator.stop()
        logger.error(str(exc))
        sys.exit(1)
    except OxSMBError as exc:
        animator.stop()
        logger.error(f"Fatal engine error: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        animator.stop()
        logger.warning("Interrupted by user")
        sys.exit(130)

    animator.stop()

    elapsed = time.time() - start_time

    meta = {
        "mode": engine.profile["name"],
        "threads": engine.profile["threads"],
        "modules": engine.profile["modules"],
        "target_count": len(config.targets),
        "elapsed_seconds": round(elapsed, 2),
    }

    security_by_target = build_security_analysis(output, config.verbosity)

    if config.output_path:
        output.write(meta=meta, security_by_target=security_by_target)
        logger.success(f"Report written to {config.output_path}")
    else:
        reporter = HumanReporter()
        reporter.print_report(
            output.get_results(),
            meta=meta,
            security_by_target=security_by_target,
            verbosity=config.verbosity,
        )

    logger.info(f"Finished in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
