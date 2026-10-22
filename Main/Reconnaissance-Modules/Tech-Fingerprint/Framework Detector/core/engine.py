import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.intercept_reader import read_transactions
from core.logger import get_logger
from core.models import DetectionMatch, DetectionResult, Transaction
from modules.aggregator import Aggregator
from modules.base import BaseDetector
from modules.cookies_module import CookiesDetector
from modules.headers_module import HeadersDetector
from modules.html_meta_module import HtmlMetaDetector
from modules.scripts_module import ScriptsDetector

DEFAULT_DETECTORS: List[type] = [HeadersDetector, CookiesDetector, HtmlMetaDetector, ScriptsDetector]


_WORKER_TRANSACTIONS: List[Transaction] = []


def _init_worker(transactions: List[Transaction]) -> None:
    global _WORKER_TRANSACTIONS
    _WORKER_TRANSACTIONS = transactions


def _scan_group(
    detectors: List[BaseDetector],
    group_name: str,
    group: Dict[str, Dict[str, Any]],
    transactions: List[Transaction],
) -> List[DetectionMatch]:
    started = time.perf_counter()
    matches: List[DetectionMatch] = []
    for transaction in transactions:
        for detector in detectors:
            matches.extend(detector.detect(transaction, group))
    get_logger().debug(
        f"[{group_name}] {len(group)} signature(s) scanned in {time.perf_counter() - started:.2f}s, "
        f"{len(matches)} match(es)"
    )
    return matches


def _scan_group_in_process(group_name: str, group: Dict[str, Dict[str, Any]]) -> List[DetectionMatch]:
    detectors = [detector_cls() for detector_cls in DEFAULT_DETECTORS]
    return _scan_group(detectors, group_name, group, _WORKER_TRANSACTIONS)


class DetectionEngine:
    def __init__(self, signatures_path: Path, max_workers: Optional[int] = None, executor: str = "process"):
        self.signatures_path = signatures_path
        self.max_workers = max_workers
        self.executor = executor
        self.signatures: Dict[str, Dict[str, Any]] = {}
        # One entry per signature file; each one is scanned in its own thread.
        self.signature_groups: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.detectors: List[BaseDetector] = [detector_cls() for detector_cls in DEFAULT_DETECTORS]
        self.aggregator = Aggregator()

    def load_signatures(self) -> None:
        logger = get_logger()
        if not self.signatures_path.is_dir():
            raise FileNotFoundError(f"Signatures directory not found: {self.signatures_path}")

        loaded_files = 0
        for signature_file in sorted(self.signatures_path.glob("*.json")):
            try:
                content = json.loads(signature_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                logger.warning(f"Skipping invalid signature file {signature_file}: {error}")
                continue

            if not isinstance(content, dict):
                logger.warning(f"Skipping signature file {signature_file}: expected a JSON object")
                continue

            group: Dict[str, Dict[str, Any]] = {}
            for framework, signature in content.items():
                if framework in self.signatures:
                    logger.warning(f"Duplicate signature for {framework} in {signature_file}, overriding")
                    # Keep "last file wins" semantics: drop the older definition from its group.
                    for older_group in self.signature_groups.values():
                        older_group.pop(framework, None)
                self.signatures[framework] = signature
                group[framework] = signature
            self.signature_groups[signature_file.name] = group

            loaded_files += 1

        logger.info(f"Loaded {len(self.signatures)} signature(s) from {loaded_files} file(s)")

    def run(self, intercept_path: Path) -> List[DetectionResult]:
        logger = get_logger()
        if not self.signatures:
            self.load_signatures()

        transactions = read_transactions(intercept_path)

        # Parse shared per-transaction data once so worker threads only read it.
        for transaction in transactions:
            for detector in self.detectors:
                detector.prepare(transaction)

        groups = [(name, group) for name, group in self.signature_groups.items() if group]
        workers = self.max_workers or max(1, min(len(groups), os.cpu_count() or 1)) \
            if self.executor == "process" else (self.max_workers or max(1, len(groups)))
        logger.info(
            f"Scanning with {workers} {self.executor} worker(s), one task per signature file ({len(groups)} file(s))"
        )

        all_matches: List[DetectionMatch] = []
        if self.executor == "process":
            with ProcessPoolExecutor(
                max_workers=workers, initializer=_init_worker, initargs=(transactions,)
            ) as pool:
                futures = [pool.submit(_scan_group_in_process, name, group) for name, group in groups]
                for future in futures:  # submission order keeps results deterministic
                    all_matches.extend(future.result())
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sig") as pool:
                futures = [
                    pool.submit(_scan_group, [cls() for cls in DEFAULT_DETECTORS], name, group, transactions)
                    for name, group in groups
                ]
                for future in futures:
                    all_matches.extend(future.result())

        logger.info(f"Collected {len(all_matches)} raw match(es) across {len(transactions)} transaction(s)")

        return self.aggregator.aggregate(all_matches)
