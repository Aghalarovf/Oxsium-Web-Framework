import re
from typing import Any, Dict, List

from core.models import DetectionMatch, Transaction
from modules.base import BaseDetector


class HeadersDetector(BaseDetector):
    name = "headers"
    rule_key = "headers"

    def detect(self, transaction: Transaction, signatures: Dict[str, Dict[str, Any]]) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        combined_headers = {**transaction.request_headers, **transaction.response_headers}

        for framework, category, rule in self.iter_rules(signatures):
            header_name = str(rule.get("name", "")).strip().lower()
            if not header_name:
                continue

            header_value = combined_headers.get(header_name)
            if header_value is None:
                continue

            pattern = rule.get("pattern")
            confidence = int(rule.get("confidence", 50))

            if pattern:
                if not re.search(pattern, header_value, re.IGNORECASE):
                    continue
                evidence = f"header {header_name}: {header_value.strip()}"
            else:
                evidence = f"header {header_name} present"

            matches.append(
                DetectionMatch(
                    framework=framework,
                    category=category,
                    confidence=confidence,
                    module=self.name,
                    evidence=evidence,
                    transaction_url=transaction.url,
                    transaction_source=transaction.source,
                )
            )

        return matches
