"""Entropy estimation and predictability pattern detection for cookie values."""

import math
import re
from collections import Counter
from typing import Any, Dict, List, Tuple

_NUMERIC = re.compile(r"^[0-9]+$")
_HEX_LOWER = re.compile(r"^[0-9a-f]+$")
_HEX_UPPER = re.compile(r"^[0-9A-F]+$")
_HEX_MIXED = re.compile(r"^[0-9a-fA-F]+$")
_ALNUM_LOWER = re.compile(r"^[0-9a-z]+$")
_ALNUM_UPPER = re.compile(r"^[0-9A-Z]+$")
_ALNUM = re.compile(r"^[0-9a-zA-Z]+$")
_BASE64URL = re.compile(r"^[0-9a-zA-Z_-]+$")
_BASE64 = re.compile(r"^[0-9a-zA-Z+/=]+$")

# Ordered most-specific-first; alphabet size used for the theoretical bits/char bound.
_CHARSET_RULES: List[Tuple[re.Pattern, str, int]] = [
    (_NUMERIC, "numeric", 10),
    (_HEX_LOWER, "hex-lower", 16),
    (_HEX_UPPER, "hex-upper", 16),
    (_HEX_MIXED, "hex-mixed", 16),
    (_ALNUM_LOWER, "alnum-lower", 36),
    (_ALNUM_UPPER, "alnum-upper", 36),
    (_ALNUM, "alnum", 62),
    (_BASE64URL, "base64url", 64),
    (_BASE64, "base64", 64),
]


def classify_charset(value: str) -> Tuple[str, int]:
    for pattern, label, size in _CHARSET_RULES:
        if pattern.match(value):
            return label, size
    return "mixed", 95


def shannon_bits_per_char(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return 0.0 if abs(entropy) < 1e-12 else entropy


def _detect_patterns(value: str) -> List[str]:
    n = len(value)
    if n == 0:
        return []
    patterns = set()

    counts = Counter(value)
    dominant_char, dominant_count = counts.most_common(1)[0]
    if n >= 6 and dominant_count / n >= 0.5:
        patterns.add("dominant-character")

    for period in range(1, n // 2 + 1):
        block = value[:period]
        reps = (block * ((n // period) + 1))[:n]
        if reps == value:
            patterns.add("repeating-block")
            break

    best_run = 1
    current_run = 1
    for i in range(1, n):
        step = ord(value[i]) - ord(value[i - 1])
        if step in (1, -1):
            current_run += 1
            best_run = max(best_run, current_run)
        else:
            current_run = 1
    if best_run >= (4 if n < 16 else 6):
        patterns.add("sequential-run")

    return sorted(patterns)


def assess(value: str) -> Dict[str, Any]:
    n = len(value)
    charset, alphabet_size = classify_charset(value)
    shannon = shannon_bits_per_char(value)
    theoretical = math.log2(alphabet_size) if alphabet_size > 1 else 0.0
    uniformity = round(shannon / theoretical, 3) if theoretical > 0 else 0.0
    uniformity = 0.0 if abs(uniformity) < 1e-12 else uniformity
    per_char_bits = min(shannon, theoretical) if theoretical > 0 else shannon
    estimated_bits = round(per_char_bits * n, 1)
    return {
        "length": n,
        "charset": charset,
        "shannon_bits_per_char": round(shannon, 3),
        "uniformity": uniformity,
        "estimated_bits": estimated_bits,
        "patterns": _detect_patterns(value),
    }


def rate_strength(assessment: Dict[str, Any]) -> str:
    if assessment["patterns"]:
        return "predictable"
    if assessment["estimated_bits"] < 64:
        return "weak"
    return "strong"


def analyze_samples(samples: List[str]) -> List[Tuple[str, str]]:
    """Look for sequential/enumerable patterns across repeated observations of a cookie."""
    findings: List[Tuple[str, str]] = []
    numeric = [s for s in samples if s.isdigit()]
    if len(numeric) >= 3:
        ints = [int(v) for v in numeric]
        deltas = [b - a for a, b in zip(ints, ints[1:])]
        if deltas and all(d > 0 for d in deltas):
            if len(set(deltas)) == 1:
                findings.append((
                    "HIGH",
                    f"Observed decimal values increase by a constant step of {deltas[0]}; identifiers look sequential and can be enumerated",
                ))
            elif max(deltas) <= 50:
                findings.append((
                    "HIGH",
                    f"Observed decimal values increase predictably (deltas {min(deltas)}..{max(deltas)}); identifiers look sequential and can be enumerated",
                ))
    return findings
