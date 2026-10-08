"""
core/engine.py - Central orchestrator.

The Engine is responsible for:
  1. Normalising and validating the target URL.
  2. Instantiating the shared Requester and Report objects.
  3. Dynamically loading only the modules requested on the command line.
  4. Running modules concurrently using a thread pool.
  5. Merging all findings and dispatching to the Exporter.
"""

from __future__ import annotations

import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Type

from core.exporter import Finding, Report
from core.logger import get_logger
from core.requester import Requester

log = get_logger("engine")


class Engine:
    """
    Top-level controller that wires together the CLI args, HTTP client,
    analysis modules, and report writer.

    Parameters
    ----------
    args : Parsed argparse.Namespace produced by core.cli.build_parser().
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self.args   = args
        self.target = Requester.normalise_url(args.domain)

        # Raise log level to DEBUG when --verbose is set
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        self.requester = Requester(timeout=args.timeout)
        self.report    = Report(target=self.target)

    # ── Public interface ──────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Execute the selected modules and write the report.

        Modules run in parallel threads (up to --threads workers).
        Each module returns a list of Finding objects which are merged
        into the central Report before output.
        """
        modules = self._load_modules()

        if not modules:
            log.error("No modules were loaded – nothing to do.")
            return

        log.info(
            f"Running {len(modules)} module(s) with "
            f"{self.args.threads} worker thread(s) …"
        )

        # Execute modules concurrently; each module is a callable class
        with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
            future_map = {
                pool.submit(module.run): module
                for module in modules
            }

            for future in as_completed(future_map):
                module = future_map[future]
                module_name = type(module).__name__

                try:
                    findings: List[Finding] = future.result()
                    self.report.add_many(findings)
                    log.info(
                        f"{module_name} completed – "
                        f"{len(findings)} finding(s) added."
                    )
                except Exception as exc:
                    # A module crash must never abort the whole analysis
                    log.error(f"{module_name} raised an exception: {exc}")

        self.requester.close()
        self.report.write(output_path=self.args.output)

    # ── Module loading ────────────────────────────────────────────────────────

    def _load_modules(self) -> list:
        """
        Import and instantiate only the modules the user requested.

        Modules are imported lazily here so that the tool starts quickly
        even if not every dependency is present (e.g. only --waf is needed).

        Returns
        -------
        list
            A list of instantiated module objects, each exposing a .run()
            method that returns List[Finding].
        """
        instances = []

        if self.args.waf:
            from modules.waf import WAFModule
            instances.append(WAFModule(self.target, self.requester))
            log.debug("WAFModule loaded.")

        if self.args.limit:
            from modules.rate_limit import RateLimitModule
            instances.append(RateLimitModule(self.target, self.requester))
            log.debug("RateLimitModule loaded.")

        if self.args.captcha:
            from modules.captcha_bot import CaptchaBotModule
            instances.append(CaptchaBotModule(self.target, self.requester))
            log.debug("CaptchaBotModule loaded.")

        return instances