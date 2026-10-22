from typing import Dict, List

from core.models import DetectionMatch, DetectionResult

MAX_EVIDENCE_ITEMS = 10
MULTI_EVIDENCE_BONUS_STEP = 5
MULTI_EVIDENCE_BONUS_CAP = 15
MULTI_MODULE_BONUS = 10


class Aggregator:
    def aggregate(self, matches: List[DetectionMatch]) -> List[DetectionResult]:
        grouped: Dict[str, List[DetectionMatch]] = {}
        categories: Dict[str, str] = {}

        for match in matches:
            grouped.setdefault(match.framework, []).append(match)
            categories.setdefault(match.framework, match.category)

        results: List[DetectionResult] = []
        for framework, framework_matches in grouped.items():
            base_confidence = max(item.confidence for item in framework_matches)
            distinct_evidence = sorted({item.evidence for item in framework_matches})
            distinct_modules = sorted({item.module for item in framework_matches})

            evidence_bonus = min(
                MULTI_EVIDENCE_BONUS_CAP,
                (len(distinct_evidence) - 1) * MULTI_EVIDENCE_BONUS_STEP,
            )
            module_bonus = MULTI_MODULE_BONUS if len(distinct_modules) > 1 else 0

            final_confidence = min(100, base_confidence + evidence_bonus + module_bonus)

            results.append(
                DetectionResult(
                    framework=framework,
                    category=categories[framework],
                    confidence=final_confidence,
                    occurrences=len(framework_matches),
                    modules=distinct_modules,
                    evidence=distinct_evidence[:MAX_EVIDENCE_ITEMS],
                )
            )

        results.sort(key=lambda item: (-item.confidence, item.framework.lower()))
        return results
