from abc import ABC, abstractmethod
from typing import Any, Dict, List

from core.models import DetectionMatch, Transaction


class BaseDetector(ABC):
    name: str = "base"
    rule_key: str = ""

    def prepare(self, transaction: Transaction) -> None:
        """Optional hook: precompute shared per-transaction data before threads start."""

    @abstractmethod
    def detect(self, transaction: Transaction, signatures: Dict[str, Dict[str, Any]]) -> List[DetectionMatch]:
        raise NotImplementedError

    def iter_rules(self, signatures: Dict[str, Dict[str, Any]]):
        for framework, signature in signatures.items():
            category = signature.get("category", "unknown")
            rules = signature.get(self.rule_key, [])
            if not rules:
                continue
            for rule in rules:
                yield framework, category, rule
