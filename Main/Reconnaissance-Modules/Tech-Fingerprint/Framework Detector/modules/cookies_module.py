import re
from typing import Any, Dict, List

from core.models import DetectionMatch, Transaction
from modules.base import BaseDetector


class CookiesDetector(BaseDetector):
    name = "cookies"
    rule_key = "cookies"

    def detect(self, transaction: Transaction, signatures: Dict[str, Dict[str, Any]]) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        if not transaction.cookies:
            return matches

        for framework, category, rule in self.iter_rules(signatures):
            cookie_pattern = str(rule.get("name", "")).strip()
            if not cookie_pattern:
                continue

            confidence = int(rule.get("confidence", 50))
            value_pattern = rule.get("value_pattern")

            for cookie_name, cookie_value in transaction.cookies.items():
                if not re.search(cookie_pattern, cookie_name, re.IGNORECASE):
                    continue

                if value_pattern and not re.search(value_pattern, cookie_value, re.IGNORECASE):
                    continue

                matches.append(
                    DetectionMatch(
                        framework=framework,
                        category=category,
                        confidence=confidence,
                        module=self.name,
                        evidence=f"cookie {cookie_name}",
                        transaction_url=transaction.url,
                        transaction_source=transaction.source,
                    )
                )
                break

        return matches
