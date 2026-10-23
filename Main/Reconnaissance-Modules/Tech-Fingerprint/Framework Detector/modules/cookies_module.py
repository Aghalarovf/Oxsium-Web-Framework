import re
from typing import Any, Dict, List

from core.models import DetectionMatch, Transaction
from modules.base import BaseDetector

# Cookie names that are generic session-handling conventions shared by
# countless unrelated frameworks/apps (PHP's own session cookie is
# "PHPSESSID", but many hand-rolled apps just call theirs "sessionid",
# "session_id", etc.). A match on one of these, by itself, says nothing
# about which specific technology is running, and reporting it as a
# "finding" is noise rather than signal (see e.g. EGroupware vs Kerio
# Connect both "detected" off the same generic cookie). These are filtered
# out entirely rather than merely down-weighted, so they never surface as
# evidence for any framework.
GENERIC_COOKIE_DENYLIST = {
    "sessionid",
    "session_id",
    "sessid",
    "sess",
    "session",
}


def _is_generic_cookie_name(cookie_name: str) -> bool:
    return cookie_name.strip().lower() in GENERIC_COOKIE_DENYLIST


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
                if _is_generic_cookie_name(cookie_name):
                    continue

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
