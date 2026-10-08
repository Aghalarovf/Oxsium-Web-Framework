from typing import Dict, Any, List, Optional, Tuple

from .base import BaseModule
from core.network import ConnectionResult


# ──────────────────────────────────────────────
# Named Groups — curves and finite-field groups
# ──────────────────────────────────────────────

# TLS 1.3 recommended groups (strong)
TLS13_GROUPS_STRONG = [
    "x25519",
    "x448",
    "secp256r1",
    "secp384r1",
    "secp521r1",
]

# Additional FFDHE groups (RFC 7919) — strong
FFDHE_GROUPS_STRONG = [
    "ffdhe2048",
    "ffdhe3072",
    "ffdhe4096",
    "ffdhe6144",
    "ffdhe8192",
]

# Obsolete / legacy curves
OBSOLETE_CURVES = [
    "secp256k1",
    "secp224r1",
    "secp192r1",
    "prime192v1",
    "prime256v1",  # alias for secp256r1, but listed for detection
    "sect283k1",
    "sect283r1",
    "sect409k1",
    "sect409r1",
    "sect571k1",
    "sect571r1",
]

# Weak / broken curves (bits < 224)
WEAK_CURVES = [
    "secp160k1",
    "secp160r1",
    "secp160r2",
    "secp128r1",
    "secp128r2",
    "secp112r1",
    "secp112r2",
    "sect113r1",
    "sect113r2",
    "sect131r1",
    "sect131r2",
    "sect163k1",
    "sect163r1",
    "sect163r2",
]

# All groups in preferred probe order
ALL_GROUPS = (
    TLS13_GROUPS_STRONG
    + FFDHE_GROUPS_STRONG
    + OBSOLETE_CURVES
    + WEAK_CURVES
)

# Key size for each group (bits)
GROUP_KEY_BITS: Dict[str, int] = {
    "x25519":        256,
    "x448":          448,
    "secp256r1":     256,
    "secp384r1":     384,
    "secp521r1":     521,
    "ffdhe2048":    2048,
    "ffdhe3072":    3072,
    "ffdhe4096":    4096,
    "ffdhe6144":    6144,
    "ffdhe8192":    8192,
    "secp256k1":     256,
    "secp224r1":     224,
    "secp192r1":     192,
    "prime192v1":    192,
    "prime256v1":    256,
    "sect283k1":     283,
    "sect283r1":     283,
    "sect409k1":     409,
    "sect409r1":     409,
    "sect571k1":     571,
    "sect571r1":     571,
    "secp160k1":     160,
    "secp160r1":     160,
    "secp160r2":     160,
    "secp128r1":     128,
    "secp128r2":     128,
    "secp112r1":     112,
    "secp112r2":     112,
    "sect113r1":     113,
    "sect113r2":     113,
    "sect131r1":     131,
    "sect131r2":     131,
    "sect163k1":     163,
    "sect163r1":     163,
    "sect163r2":     163,
}

# Group type classification
GROUP_TYPE: Dict[str, str] = {
    "x25519":        "ecdhe",
    "x448":          "ecdhe",
    "secp256r1":     "ecdhe",
    "secp384r1":     "ecdhe",
    "secp521r1":     "ecdhe",
    "secp256k1":     "ecdhe",
    "secp224r1":     "ecdhe",
    "secp192r1":     "ecdhe",
    "prime192v1":    "ecdhe",
    "prime256v1":    "ecdhe",
    "sect283k1":     "ecdhe",
    "sect283r1":     "ecdhe",
    "sect409k1":     "ecdhe",
    "sect409r1":     "ecdhe",
    "sect571k1":     "ecdhe",
    "sect571r1":     "ecdhe",
    "secp160k1":     "ecdhe",
    "secp160r1":     "ecdhe",
    "secp160r2":     "ecdhe",
    "secp128r1":     "ecdhe",
    "secp128r2":     "ecdhe",
    "secp112r1":     "ecdhe",
    "secp112r2":     "ecdhe",
    "sect113r1":     "ecdhe",
    "sect113r2":     "ecdhe",
    "sect131r1":     "ecdhe",
    "sect131r2":     "ecdhe",
    "sect163k1":     "ecdhe",
    "sect163r1":     "ecdhe",
    "sect163r2":     "ecdhe",
    "ffdhe2048":     "ffdhe",
    "ffdhe3072":     "ffdhe",
    "ffdhe4096":     "ffdhe",
    "ffdhe6144":     "ffdhe",
    "ffdhe8192":     "ffdhe",
}

# Strength categories
STRONG_GROUPS = TLS13_GROUPS_STRONG + FFDHE_GROUPS_STRONG
# FFDHE groups with < 2048 bits are considered weak for DHE
WEAK_FFDHE_CUSTOM = ["dhe_512", "dhe_768", "dhe_1024"]

SECURITY_THRESHOLDS = {
    "strong_ecdhe": 256,    # ≥ 256-bit ECDHE
    "strong_ffdhe": 2048,   # ≥ 2048-bit FFDHE
    "weak_ecdhe": 224,      # < 224-bit ECDHE
    "weak_ffdhe": 1024,     # < 1024-bit FFDHE
}


# ──────────────────────────────────────────────
# Module
# ──────────────────────────────────────────────


class GroupsModule(BaseModule):
    name = "groups"
    description = "Supported named groups (ECDHE curves, FFDHE) and DH parameter analysis"

    def run(self) -> Dict[str, Any]:
        self.logger.section("Named Groups Module")

        self.logger.subsection("Named Groups Inventory")
        group_results = self._probe_all_groups()
        self._print_group_matrix(group_results)

        self.logger.subsection("Group Classification")
        classified = self._classify_groups(group_results)
        self._print_classification(classified)

        self.logger.subsection("Group Strength Analysis")
        strength_data = self._analyze_strength(classified)
        self._print_strength_analysis(strength_data)

        self.logger.subsection("DH Parameter Analysis (Custom DHE)")
        dhe_data = self._probe_dhe_params()
        self._print_dhe_analysis(dhe_data)

        self.logger.subsection("Groups Assessment")
        assessment = self._assess(classified, strength_data, dhe_data)
        self._print_assessment(assessment)

        return {
            "groups": group_results,
            "classification": classified,
            "strength_analysis": strength_data,
            "dhe_params": dhe_data,
            "assessment": assessment,
        }

    # ── Probing ─────────────────────────────────

    def _probe_all_groups(self) -> List[Dict[str, Any]]:
        """Probe every known named group via TLS handshake."""
        results = []
        for group_name in ALL_GROUPS:
            entry = self._probe_single_group(group_name)
            results.append(entry)
        return results

    def _probe_single_group(self, group_name: str) -> Dict[str, Any]:
        """Attempt a TLS handshake forcing a specific named group."""
        group_type = GROUP_TYPE.get(group_name, "unknown")

        if group_type == "ecdhe":
            result = self.connection.probe_ecdh_curve(group_name)
        elif group_type == "ffdhe":
            result = self.connection.probe_ffdhe_group(group_name)
        else:
            result = ConnectionResult(success=False, error=f"Unknown group type: {group_name}")

        supported = result.success

        entry: Dict[str, Any] = {
            "name": group_name,
            "type": group_type,
            "supported": supported,
            "error": result.error if not supported else None,
        }

        if supported:
            entry["key_bits"] = GROUP_KEY_BITS.get(group_name)
            entry["protocol"] = result.version
            if result.cipher:
                entry["cipher"] = result.cipher[0]
            entry["handshake_time_ms"] = result.handshake_time_ms

        return entry

    # ── Classification ──────────────────────────

    def _classify_groups(
        self, group_results: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Split groups into security categories."""
        supported = [g for g in group_results if g["supported"]]

        categories: Dict[str, List[Dict[str, Any]]] = {
            "strong_ecdhe":      [],
            "strong_ffdhe":      [],
            "obsolete_ecdhe":    [],
            "weak_ecdhe":        [],
            "custom_ffdhe":      [],
        }

        for group in supported:
            name = group["name"]
            gtype = group.get("type", "unknown")
            bits = group.get("key_bits", 0)

            if gtype == "ecdhe":
                if name in TLS13_GROUPS_STRONG:
                    categories["strong_ecdhe"].append(group)
                elif name in OBSOLETE_CURVES:
                    categories["obsolete_ecdhe"].append(group)
                elif name in WEAK_CURVES:
                    categories["weak_ecdhe"].append(group)
                else:
                    # Fallback by bit strength
                    if bits >= SECURITY_THRESHOLDS["strong_ecdhe"]:
                        categories["strong_ecdhe"].append(group)
                    elif bits >= SECURITY_THRESHOLDS["weak_ecdhe"]:
                        categories["obsolete_ecdhe"].append(group)
                    else:
                        categories["weak_ecdhe"].append(group)

            elif gtype == "ffdhe":
                if name in FFDHE_GROUPS_STRONG:
                    categories["strong_ffdhe"].append(group)
                else:
                    categories["custom_ffdhe"].append(group)

            else:
                categories["custom_ffdhe"].append(group)

        return categories

    # ── Strength analysis ───────────────────────

    def _analyze_strength(
        self, classified: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Determine best available group strength."""
        strong_ecdhe = classified.get("strong_ecdhe", [])
        strong_ffdhe = classified.get("strong_ffdhe", [])
        obsolete = classified.get("obsolete_ecdhe", [])
        weak = classified.get("weak_ecdhe", [])

        # Best group heuristic
        best_ecdhe = None
        if strong_ecdhe:
            # Prefer X25519 > P-256 > X448 > P-384 > P-521
            for preferred in ["x25519", "secp256r1", "x448", "secp384r1", "secp521r1"]:
                for g in strong_ecdhe:
                    if g["name"] == preferred:
                        best_ecdhe = g
                        break
                if best_ecdhe:
                    break
            if not best_ecdhe and strong_ecdhe:
                best_ecdhe = strong_ecdhe[0]

        best_ffdhe = None
        if strong_ffdhe:
            best_ffdhe = strong_ffdhe[0]

        # Strength level
        if best_ecdhe:
            strength_level = "strong"
        elif strong_ffdhe:
            strength_level = "strong"
        elif obsolete:
            strength_level = "moderate"
        elif weak:
            strength_level = "weak"
        else:
            strength_level = "none"

        return {
            "strength_level": strength_level,
            "best_ecdhe_group": best_ecdhe["name"] if best_ecdhe else None,
            "best_ecdhe_bits": best_ecdhe.get("key_bits") if best_ecdhe else None,
            "best_ffdhe_group": best_ffdhe["name"] if best_ffdhe else None,
            "best_ffdhe_bits": best_ffdhe.get("key_bits") if best_ffdhe else None,
            "ecdhe_strong_count": len(strong_ecdhe),
            "ecdhe_obsolete_count": len(obsolete),
            "ecdhe_weak_count": len(weak),
            "ffdhe_strong_count": len(strong_ffdhe),
        }

    # ── Custom DHE parameter analysis ──────────

    def _probe_dhe_params(self) -> Dict[str, Any]:
        """Probe custom (non-standard) DHE parameters if DHE is available.

        Note: RFC 7919 FFDHE groups are tested via _probe_all_groups.
        This method checks whether the server supports custom DHE
        parameters (not tied to a named FFDHE group) and their size.
        """
        result = self.connection.probe_dhe_handshake()

        if not result.success:
            return {
                "custom_dhe_supported": False,
                "error": result.error,
            }

        dhe_bits = None
        extra = getattr(result, "extra", {}) or {}
        dhe_bits = extra.get("dhe_bits")

        if dhe_bits is None and result.cipher and len(result.cipher) >= 3:
            if isinstance(result.cipher[2], int) and result.cipher[2] > 256:
                dhe_bits = result.cipher[2]

        if dhe_bits is None:
            return {
                "custom_dhe_supported": True,
                "dhe_bits": None,
                "strength": "unknown",
                "detail": "Custom DHE supported but parameter size unknown",
            }

        # Classify strength
        if dhe_bits >= 2048:
            strength = "strong"
        elif dhe_bits >= 1024:
            strength = "moderate"
        elif dhe_bits >= 512:
            strength = "weak"
        else:
            strength = "export"

        return {
            "custom_dhe_supported": True,
            "dhe_bits": dhe_bits,
            "strength": strength,
            "handshake_time_ms": result.handshake_time_ms,
        }

    # ── Assessment ─────────────────────────────

    def _assess(
        self,
        classified: Dict[str, List[Dict[str, Any]]],
        strength_data: Dict[str, Any],
        dhe_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        issues: List[str] = []
        warnings: List[str] = []
        notes: List[str] = []

        # ── Check weak ECDHE curves ──
        weak_ecdhe = classified.get("weak_ecdhe", [])
        if weak_ecdhe:
            weak_names = [g["name"] for g in weak_ecdhe]
            issues.append(f"Weak ECDHE curves supported: {', '.join(weak_names)}")

        # ── Check obsolete curves ──
        obsolete = classified.get("obsolete_ecdhe", [])
        if obsolete:
            obs_names = [g["name"] for g in obsolete]
            warnings.append(f"Obsolete ECDHE curves supported: {', '.join(obs_names)}")

        # ── No strong ECDHE ──
        strong_ecdhe = classified.get("strong_ecdhe", [])
        strong_ffdhe = classified.get("strong_ffdhe", [])
        if not strong_ecdhe and not strong_ffdhe:
            issues.append("No strong (≥256-bit ECDHE or ≥2048-bit FFDHE) groups supported")

        if not strong_ecdhe:
            warnings.append("No strong ECDHE curves (X25519 or P-256 or higher) supported")

        # ── FFDHE notes ──
        if strong_ffdhe:
            ffdhe_names = [g["name"] for g in strong_ffdhe]
            notes.append(f"Standard FFDHE groups supported: {', '.join(ffdhe_names)}")

        # ── Custom DHE ──
        if dhe_data.get("custom_dhe_supported"):
            dhe_strength = dhe_data.get("strength")
            dhe_bits = dhe_data.get("dhe_bits")
            if dhe_strength == "export":
                issues.append(f"Export-grade custom DHE parameters ({dhe_bits} bits)")
            elif dhe_strength == "weak":
                issues.append(f"Weak custom DHE parameters ({dhe_bits} bits)")
            elif dhe_strength == "moderate":
                warnings.append(f"Moderate custom DHE parameters ({dhe_bits} bits, < 2048)")
            else:
                notes.append(f"Strong custom DHE parameters ({dhe_bits} bits)")

        # ── Total groups count ──
        total_supported = (
            len(strong_ecdhe) + len(strong_ffdhe)
            + len(obsolete) + len(weak_ecdhe)
            + (1 if dhe_data.get("custom_dhe_supported") else 0)
        )
        notes.append(f"{total_supported} group(s) supported in total")

        # ── Grade ──
        grade = self._calculate_grade(issues, warnings, classified, dhe_data)

        return {
            "grade": grade,
            "total_supported": total_supported,
            "issues": issues,
            "warnings": warnings,
            "notes": notes,
        }

    # ── Helpers ─────────────────────────────────

    def _calculate_grade(
        self,
        issues: List[str],
        warnings: List[str],
        classified: Dict[str, List[Dict[str, Any]]],
        dhe_data: Dict[str, Any],
    ) -> str:
        """A–F grade based on group strength."""
        weak_ecdhe = classified.get("weak_ecdhe", [])
        strong_ecdhe = classified.get("strong_ecdhe", [])
        strong_ffdhe = classified.get("strong_ffdhe", [])

        # F — weak curves or export DH
        if weak_ecdhe:
            return "F"
        if dhe_data.get("strength") == "export":
            return "F"

        # D — no strong groups at all
        if not strong_ecdhe and not strong_ffdhe:
            return "D"

        # C — issues present (weak DH, etc.)
        if issues:
            return "C"

        # B — warnings only (obsolete curves, moderate DH)
        if warnings:
            return "B"

        # A — clean
        return "A"

    def _get_strength_label(self, bits: Optional[int]) -> str:
        """Human-readable strength label."""
        if bits is None:
            return "unknown"
        if bits >= 256 or bits >= 2048:
            return "strong"
        if bits >= 224 or bits >= 1024:
            return "moderate"
        return "weak"

    # ── Display ─────────────────────────────────

    def _print_group_matrix(self, results: List[Dict[str, Any]]) -> None:
        for entry in results:
            name = entry["name"]
            supported = entry["supported"]

            if not supported:
                self._skip(name, "Not supported")
                continue

            gtype = entry.get("type", "?")
            bits = entry.get("key_bits", "?")
            proto = entry.get("protocol", "?")
            hs = entry.get("handshake_time_ms")
            hs_str = f"  ({hs} ms)" if hs is not None else ""

            label = f"Supported{hs_str}  [{gtype} / {bits} bits / {proto}]"

            # Color by group strength
            if name in STRONG_GROUPS:
                self._pass(name, label)
            elif name in OBSOLETE_CURVES:
                self._warn(name, label)
            elif name in WEAK_CURVES:
                self._fail(name, label)
            else:
                self._info(name, label)

    def _print_classification(
        self, classified: Dict[str, List[Dict[str, Any]]]
    ) -> None:
        section_labels = {
            "strong_ecdhe":   ("PASS", "Strong ECDHE Curves (≥ 256-bit)"),
            "strong_ffdhe":   ("PASS", "Strong FFDHE Groups (≥ 2048-bit)"),
            "obsolete_ecdhe": ("WARN", "Obsolete ECDHE Curves"),
            "weak_ecdhe":     ("FAIL", "Weak ECDHE Curves (< 224-bit)"),
            "custom_ffdhe":   ("WARN", "Custom / Non-Standard DHE Groups"),
        }

        for cat_key, (status, label) in section_labels.items():
            groups = classified.get(cat_key, [])
            if not groups:
                continue

            names = [g["name"] for g in groups]
            bits_list = [str(g.get("key_bits", "?")) for g in groups]
            summary = f"{len(groups)} group(s): {', '.join(names)}"

            if status == "PASS":
                self._pass(label, summary)
            elif status == "WARN":
                self._warn(label, summary)
            else:
                self._fail(label, summary)

            # Per-group details
            for g in groups:
                bits = g.get("key_bits", "?")
                proto = g.get("protocol", "?")
                detail = f"  ├ {g['name']}  [{bits}b / {proto}]"
                self._info("", detail)

    def _print_strength_analysis(self, data: Dict[str, Any]) -> None:
        level = data.get("strength_level", "none")
        if level == "strong":
            self._pass("Group Strength", "Strong groups available")
        elif level == "moderate":
            self._warn("Group Strength", "Only moderate/obsolete groups available")
        elif level == "weak":
            self._fail("Group Strength", "Only weak groups available")
        else:
            self._fail("Group Strength", "No groups supported")

        best_ecdhe = data.get("best_ecdhe_group")
        best_ecdhe_bits = data.get("best_ecdhe_bits")
        if best_ecdhe:
            self._info("Best ECDHE", f"{best_ecdhe} ({best_ecdhe_bits} bits)")

        best_ffdhe = data.get("best_ffdhe_group")
        best_ffdhe_bits = data.get("best_ffdhe_bits")
        if best_ffdhe:
            self._info("Best FFDHE", f"{best_ffdhe} ({best_ffdhe_bits} bits)")

        self._info(
            "ECDHE Count",
            f"Strong: {data['ecdhe_strong_count']} | "
            f"Obsolete: {data['ecdhe_obsolete_count']} | "
            f"Weak: {data['ecdhe_weak_count']}",
        )

    def _print_dhe_analysis(self, data: Dict[str, Any]) -> None:
        if not data.get("custom_dhe_supported"):
            self._info("Custom DHE Parameters", "Not supported (only standard FFDHE groups)")
            return

        dhe_bits = data.get("dhe_bits")
        strength = data.get("strength", "unknown")

        if dhe_bits is None:
            self._warn("Custom DHE Parameters", "Supported but parameter size unknown")
            return

        label = f"{dhe_bits} bits"

        if strength == "strong":
            self._pass("Custom DHE Parameters", label)
        elif strength == "moderate":
            self._warn("Custom DHE Parameters", label)
        else:
            self._fail("Custom DHE Parameters", label)

        hs = data.get("handshake_time_ms")
        if hs is not None:
            self._info("DHE Handshake Time", f"{hs} ms")

    def _print_assessment(self, assessment: Dict[str, Any]) -> None:
        grade = assessment.get("grade", "?")
        if grade == "A":
            self._pass("Overall Grade", grade)
        elif grade == "B":
            self._warn("Overall Grade", grade)
        else:
            self._fail("Overall Grade", grade)

        for issue in assessment.get("issues", []):
            self._fail("Issue", issue)
        for warning in assessment.get("warnings", []):
            self._warn("Warning", warning)
        for note in assessment.get("notes", []):
            self._info("Note", note)