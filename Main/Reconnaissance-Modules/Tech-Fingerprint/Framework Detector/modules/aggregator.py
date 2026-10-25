from typing import Dict, List

from core.models import DetectionMatch, DetectionResult

MAX_EVIDENCE_ITEMS = 10
MULTI_EVIDENCE_BONUS_STEP = 5
MULTI_EVIDENCE_BONUS_CAP = 15
MULTI_MODULE_BONUS = 10

# How much a module's signal can be trusted on its own. headers/cookies are
# strong, first-party signals that are hard to spoof passively. scripts
# (asset-path matches) are a solid secondary signal. html_meta covers both
# <meta> tags and loose body-text/global-variable regexes, which are the
# easiest signals to produce false positives on -- generic libraries, shared
# JS globals (e.g. the "gon" Rails gem, not GitLab-specific), boilerplate
# meta tags -- so it gets the lowest weight.
MODULE_RELIABILITY = {
    "headers": 1.0,
    "cookies": 1.0,
    "scripts": 0.85,
    "html_meta": 0.55,
}
DEFAULT_MODULE_RELIABILITY = 0.7

# When html_meta is the ONLY module that produced evidence for a framework
# (no headers, cookies, or script matches backing it up), the detection is
# capped at a fixed, low confidence: a lone <meta>/body/global-var regex hit
# is too weak a signal to report with high confidence, however many times
# it was observed.
HTML_META_ONLY_CONFIDENCE = 40


class Aggregator:
    def aggregate(self, matches: List[DetectionMatch]) -> List[DetectionResult]:
        grouped: Dict[str, List[DetectionMatch]] = {}
        categories: Dict[str, str] = {}

        for match in matches:
            grouped.setdefault(match.framework, []).append(match)
            categories.setdefault(match.framework, match.category)

        results: List[DetectionResult] = []
        for framework, framework_matches in grouped.items():
            distinct_modules = sorted({item.module for item in framework_matches})

            # Case-insensitive, whitespace-normalized de-duplication so the
            # same underlying signal observed twice (e.g. the same body
            # pattern matched with different letter-casing, like "GON" vs
            # "Gon", or the same header seen on two transactions) is not
            # double-counted as independent corroborating evidence.
            evidence_seen: Dict[str, str] = {}
            for item in framework_matches:
                normalized = " ".join(item.evidence.split()).lower()
                evidence_seen.setdefault(normalized, item.evidence)
            distinct_evidence = sorted(evidence_seen.values())

            only_html_meta = distinct_modules == ["html_meta"]

            if only_html_meta:
                # Fixed, low-confidence verdict: html_meta alone never
                # proves a framework, regardless of how many duplicate/loose
                # body or meta-tag matches were found.
                final_confidence = HTML_META_ONLY_CONFIDENCE
            else:
                base_confidence = max(item.confidence for item in framework_matches)

                evidence_bonus = min(
                    MULTI_EVIDENCE_BONUS_CAP,
                    (len(distinct_evidence) - 1) * MULTI_EVIDENCE_BONUS_STEP,
                )

                # Corroboration across independent modules is only worth the
                # full bonus when the corroborating modules are themselves
                # reliable. A strong module (headers/cookies) backing up
                # another strong module earns the full +10; a weak html_meta
                # hit riding along a single strong module earns less, since
                # it adds little independent certainty.
                reliabilities = [
                    MODULE_RELIABILITY.get(module, DEFAULT_MODULE_RELIABILITY)
                    for module in distinct_modules
                ]
                if len(distinct_modules) > 1:
                    module_bonus = MULTI_MODULE_BONUS * (sum(reliabilities) / len(reliabilities))
                else:
                    module_bonus = 0

                final_confidence = min(100, round(base_confidence + evidence_bonus + module_bonus))

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
