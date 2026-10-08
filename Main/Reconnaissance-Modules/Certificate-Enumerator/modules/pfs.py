from typing import Dict, Any, List, Optional, Tuple

from .base import BaseModule
from core.network import ConnectionResult


# ──────────────────────────────────────────────
# Constants — PFS key exchanges, curve tiers,
# DHE parameter strength, resumption modes
# ──────────────────────────────────────────────

# Key-exchange algorithms that provide PFS
PFS_KEY_EXCHANGE_ALGORITHMS = ["ECDHE", "DHE", "DHE_DSS", "DHE_RSA"]

# Non-PFS key exchanges
NON_PFS_KEY_EXCHANGE_ALGORITHMS = ["RSA", "ECDH", "DH_DSS", "DH_RSA", "PSK", "SRP"]

# ECDHE curves in order of preference
ECDHE_CURVES_PREFERRED = [
    "x25519",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "x448",
]

ECDHE_CURVES_OBSOLETE = [
    "secp256k1",
    "secp224r1",
    "secp192r1",
    "secp160r2",
    "secp160r1",
    "prime256v1",  # alias for secp256r1 — listed for reference
]

ECDHE_CURVES_WEAK = [
    "secp112r1",
    "secp112r2",
    "sect113r1",
    "sect113r2",
    "sect131r1",
    "sect131r2",
]

# DHE parameter strength thresholds (bits)
DHE_STRENGTH: Dict[str, int] = {
    "strong": 2048,
    "moderate": 1024,
    "weak": 512,
    "export": 512,  # <= 512 bits is export-grade
}

# Session resumption modes
SESSION_RESUMPTION_MODES = ["session_id", "session_ticket"]

# Session ticket lifetime recommendations
SESSION_TICKET_LIFETIME_MAX_RECOMMENDED_HOURS = 24  # RFC 5077 recommends max 24h

# Assessment labels
PFS_ASSESSMENT_LABELS: Dict[str, Tuple[str, str]] = {
    "pfs_preferred":     ("PASS", "PFS ciphers preferred over non-PFS"),
    "pfs_available":     ("PASS", "PFS key exchange available"),
    "pfs_not_preferred": ("WARN", "Non-PFS ciphers preferred or co-equal"),
    "pfs_unavailable":   ("FAIL", "No PFS key exchange supported"),
}

CURVE_ASSESSMENT_LABELS: Dict[str, Tuple[str, str]] = {
    "strong":   ("PASS", "Strong curves available"),
    "obsolete": ("WARN", "Obsolete curves supported"),
    "weak":     ("FAIL", "Weak curves supported"),
}

DHE_ASSESSMENT_LABELS: Dict[str, Tuple[str, str]] = {
    "strong":  ("PASS", "DHE parameters >= 2048 bits"),
    "moderate": ("WARN", "DHE parameters < 2048 bits"),
    "weak":    ("FAIL", "DHE parameters < 1024 bits"),
}

SESSION_RESUMPTION_LABELS: Dict[str, Tuple[str, str]] = {
    "session_id_ticket": ("Session ID + Ticket resumption supported", "PASS"),
    "session_id_only":   ("Only session ID resumption supported",      "WARN"),
    "ticket_only":       ("Only session ticket resumption supported",  "WARN"),
    "none":              ("No session resumption supported",           "FAIL"),
}


# ──────────────────────────────────────────────
# Module
# ──────────────────────────────────────────────


class PfsModule(BaseModule):
    name = "pfs"
    description = "Perfect Forward Secrecy & session resumption analysis"

    # ── Public API ──────────────────────────────

    def run(self) -> Dict[str, Any]:
        self.logger.section("PFS Module")

        self.logger.subsection("PFS Key-Exchange Support")
        pfs_support = self._probe_pfs_support()
        self._print_pfs_support(pfs_support)

        self.logger.subsection("ECDHE Curve Analysis")
        curve_data = self._probe_ecdh_curves()
        self._print_curve_analysis(curve_data)

        self.logger.subsection("DHE Parameter Analysis")
        dhe_data = self._probe_dhe_params()
        self._print_dhe_analysis(dhe_data)

        self.logger.subsection("Cipher Preference (PFS vs Non-PFS)")
        pref_data = self._analyze_cipher_preference()
        self._print_cipher_preference(pref_data)

        self.logger.subsection("Session Resumption")
        session_data = self._probe_session_resumption()
        self._print_session_resumption(session_data)

        self.logger.subsection("PFS & Session Assessment")
        assessment = self._assess(pfs_support, curve_data, dhe_data, pref_data, session_data)
        self._print_assessment(assessment)

        return {
            "pfs_support": pfs_support,
            "ecdh_curves": curve_data,
            "dhe_params": dhe_data,
            "cipher_preference": pref_data,
            "session_resumption": session_data,
            "assessment": assessment,
        }

    # ── PFS Support ────────────────────────────

    def _probe_pfs_support(self) -> Dict[str, Any]:
        """Check which key-exchange algorithms are supported."""
        supported_kex: List[str] = []
        unsupported_kex: List[str] = []

        all_kex = PFS_KEY_EXCHANGE_ALGORITHMS + NON_PFS_KEY_EXCHANGE_ALGORITHMS

        for kex in all_kex:
            result = self.connection.probe_key_exchange(kex)
            if result.success:
                supported_kex.append(kex)
            else:
                unsupported_kex.append(kex)

        pfs_supported_kex = [k for k in supported_kex if k in PFS_KEY_EXCHANGE_ALGORITHMS]

        return {
            "pfs_available": len(pfs_supported_kex) > 0,
            "pfs_supported_kex": pfs_supported_kex,
            "non_pfs_supported_kex": [k for k in supported_kex if k in NON_PFS_KEY_EXCHANGE_ALGORITHMS],
            "all_supported_kex": supported_kex,
            "unsupported_kex": unsupported_kex,
        }

    # ── ECDHE Curve Analysis ───────────────────

    def _probe_ecdh_curves(self) -> Dict[str, Any]:
        """Enumerate supported ECDHE curves and classify their strength."""
        all_curves = ECDHE_CURVES_PREFERRED + ECDHE_CURVES_OBSOLETE + ECDHE_CURVES_WEAK
        supported_curves: List[str] = []
        unsupported_curves: List[str] = []

        for curve in all_curves:
            result = self.connection.probe_ecdh_curve(curve)
            if result.success:
                supported_curves.append(curve)
            else:
                unsupported_curves.append(curve)

        strong = [c for c in supported_curves if c in ECDHE_CURVES_PREFERRED]
        obsolete = [c for c in supported_curves if c in ECDHE_CURVES_OBSOLETE]
        weak = [c for c in supported_curves if c in ECDHE_CURVES_WEAK]

        # Best available curve for grading
        best_curve = None
        if strong:
            best_curve = strong[0]
        elif obsolete:
            best_curve = obsolete[0]
        elif weak:
            best_curve = weak[0]

        return {
            "supported_curves": supported_curves,
            "unsupported_curves": unsupported_curves,
            "strong_curves": strong,
            "obsolete_curves": obsolete,
            "weak_curves": weak,
            "best_curve": best_curve,
            "curve_count": len(supported_curves),
        }

    # ── DHE Parameter Analysis ─────────────────

    def _probe_dhe_params(self) -> Dict[str, Any]:
        """Probe DHE parameter strength if DHE is supported."""
        # Try a DHE handshake and inspect the negotiated parameters
        result = self.connection.probe_dhe_handshake()

        if not result.success:
            return {
                "dhe_supported": False,
                "error": result.error,
            }

        dhe_bits = self._extract_dhe_bits(result)

        if dhe_bits is None:
            return {
                "dhe_supported": True,
                "dhe_bits": None,
                "error": "Could not determine DHE parameter size",
            }

        if dhe_bits >= DHE_STRENGTH["strong"]:
            strength = "strong"
        elif dhe_bits >= DHE_STRENGTH["moderate"]:
            strength = "moderate"
        elif dhe_bits > DHE_STRENGTH["weak"]:
            strength = "weak"
        else:
            strength = "export"

        return {
            "dhe_supported": True,
            "dhe_bits": dhe_bits,
            "strength": strength,
            "handshake_time_ms": result.handshake_time_ms,
        }

    # ── Cipher Preference Analysis ─────────────

    def _analyze_cipher_preference(self) -> Dict[str, Any]:
        """Determine whether the server prefers PFS ciphers over non-PFS."""
        # This assumes the backend can report cipher preference order
        result = self.connection.probe_cipher_preference()

        if not result.success:
            return {
                "preference_known": False,
                "error": result.error,
            }

        # result.preference is expected to be a list of cipher names
        # in server-preferred order
        preference = getattr(result, "preference", None)
        if not preference:
            return {
                "preference_known": False,
                "error": "Cipher preference list unavailable",
            }

        # Check if top cipher has PFS
        pfs_at_top = None
        pfs_count = 0
        non_pfs_count = 0

        for i, cipher_name in enumerate(preference):
            upper = cipher_name.upper()
            has_pfs = any(kex in upper for kex in PFS_KEY_EXCHANGE_ALGORITHMS)
            if has_pfs:
                pfs_count += 1
                if pfs_at_top is None:
                    pfs_at_top = i
            else:
                non_pfs_count += 1

        # Heuristic: PFS preferred if first cipher is PFS
        pfs_preferred = pfs_at_top == 0 if pfs_at_top is not None else False

        return {
            "preference_known": True,
            "pfs_preferred": pfs_preferred,
            "pfs_at_position": pfs_at_top,
            "pfs_cipher_count": pfs_count,
            "non_pfs_cipher_count": non_pfs_count,
            "preference": preference,
        }

    # ── Session Resumption ─────────────────────

    def _probe_session_resumption(self) -> Dict[str, Any]:
        """Test session ID and session ticket resumption."""
        results: Dict[str, Any] = {}

        for mode in SESSION_RESUMPTION_MODES:
            result = self.connection.test_session_resumption(mode=mode)
            results[mode] = {
                "supported": result.success,
                "error": result.error if not result.success else None,
            }

            if result.success:
                extra = getattr(result, "extra", {}) or {}
                if mode == "session_ticket":
                    results[mode]["ticket_present"] = extra.get("ticket_present", True)
                    results[mode]["ticket_lifetime_hours"] = extra.get("ticket_lifetime_hours")
                elif mode == "session_id":
                    results[mode]["session_id_present"] = extra.get("session_id_present", True)

        session_id_ok = results.get("session_id", {}).get("supported", False)
        ticket_ok = results.get("session_ticket", {}).get("supported", False)

        if session_id_ok and ticket_ok:
            mode_label = "session_id_ticket"
        elif session_id_ok:
            mode_label = "session_id_only"
        elif ticket_ok:
            mode_label = "ticket_only"
        else:
            mode_label = "none"

        # Check ticket lifetime
        ticket_lifetime = results.get("session_ticket", {}).get("ticket_lifetime_hours")
        lifetime_warning = None
        if ticket_lifetime is not None:
            if ticket_lifetime > SESSION_TICKET_LIFETIME_MAX_RECOMMENDED_HOURS:
                lifetime_warning = (
                    f"Session ticket lifetime ({ticket_lifetime}h) exceeds "
                    f"recommended max ({SESSION_TICKET_LIFETIME_MAX_RECOMMENDED_HOURS}h)"
                )

        return {
            "resumption_mode": mode_label,
            "session_id_supported": session_id_ok,
            "session_ticket_supported": ticket_ok,
            "ticket_lifetime_hours": ticket_lifetime,
            "ticket_lifetime_warning": lifetime_warning,
            "details": results,
        }

    # ── Assessment ─────────────────────────────

    def _assess(
        self,
        pfs_support: Dict[str, Any],
        curve_data: Dict[str, Any],
        dhe_data: Dict[str, Any],
        pref_data: Dict[str, Any],
        session_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        issues: List[str] = []
        warnings: List[str] = []
        notes: List[str] = []

        # ── PFS availability ──
        if not pfs_support.get("pfs_available"):
            issues.append("No Perfect Forward Secrecy key exchange supported")
        else:
            pfs_kex = pfs_support.get("pfs_supported_kex", [])
            notes.append(f"PFS key exchanges: {', '.join(pfs_kex)}")

        # ── ECDHE curve strength ──
        if curve_data.get("weak_curves"):
            issues.append(
                f"Weak ECDHE curves supported: {', '.join(curve_data['weak_curves'])}"
            )
        if curve_data.get("obsolete_curves"):
            warnings.append(
                f"Obsolete ECDHE curves supported: {', '.join(curve_data['obsolete_curves'])}"
            )
        if not curve_data.get("strong_curves") and curve_data.get("supported_curves"):
            warnings.append("No strong ECDHE curves available (prefer X25519 or secp256r1)")

        # ── DHE parameter strength ──
        dhe_strength = dhe_data.get("strength")
        if dhe_data.get("dhe_supported"):
            if dhe_strength == "export":
                issues.append(f"Export-grade DHE parameters ({dhe_data.get('dhe_bits')} bits)")
            elif dhe_strength == "weak":
                issues.append(f"Weak DHE parameters ({dhe_data.get('dhe_bits')} bits, < 1024)")
            elif dhe_strength == "moderate":
                warnings.append(
                    f"Moderate DHE parameters ({dhe_data.get('dhe_bits')} bits, < 2048)"
                )
            else:
                dhe_bits = dhe_data.get("dhe_bits")
                if dhe_bits is not None:
                    notes.append(f"Strong DHE parameters ({dhe_bits} bits)")

        # ── Cipher preference ──
        if pref_data.get("preference_known"):
            if pref_data.get("pfs_preferred"):
                notes.append("Server prefers PFS ciphers over non-PFS")
            else:
                pfs_pos = pref_data.get("pfs_at_position")
                if pfs_pos is not None:
                    warnings.append(f"Non-PFS cipher preferred before PFS (position {pfs_pos})")
                else:
                    warnings.append("No PFS ciphers found in server preference list")

        # ── Session resumption ──
        res_mode = session_data.get("resumption_mode", "none")
        if res_mode == "none":
            issues.append("No session resumption supported")
        elif res_mode == "session_id_only":
            warnings.append("Only session ID resumption supported (no session tickets)")
        elif res_mode == "ticket_only":
            warnings.append("Only session ticket resumption supported (no session IDs)")

        ticket_warning = session_data.get("ticket_lifetime_warning")
        if ticket_warning:
            warnings.append(ticket_warning)

        # ── Grade ──
        grade = self._calculate_grade(issues, warnings, pfs_support, curve_data, dhe_data)

        return {
            "grade": grade,
            "pfs_available": pfs_support.get("pfs_available", False),
            "issues": issues,
            "warnings": warnings,
            "notes": notes,
        }

    # ── Helpers ─────────────────────────────────

    def _extract_dhe_bits(self, result: ConnectionResult) -> Optional[int]:
        """Extract DHE parameter size in bits from a connection result."""
        extra = getattr(result, "extra", None)
        if extra and "dhe_bits" in extra:
            return extra["dhe_bits"]
        # Fallback: try parsing from cipher info
        cipher = result.cipher
        if cipher:
            # Some backends embed DH param size in the cipher tuple
            # e.g., ("DHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 2048)
            if len(cipher) >= 3 and isinstance(cipher[2], int):
                if cipher[2] > 256:  # Likely DH bits, not symmetric key bits
                    return cipher[2]
        return None

    def _calculate_grade(
        self,
        issues: List[str],
        warnings: List[str],
        pfs_support: Dict[str, Any],
        curve_data: Dict[str, Any],
        dhe_data: Dict[str, Any],
    ) -> str:
        """A–F grade based on PFS, curve, and DHE analysis."""
        # F — no PFS or export-grade/weak DH
        if not pfs_support.get("pfs_available"):
            return "F"
        if dhe_data.get("strength") in ("export", "weak"):
            return "F"
        if curve_data.get("weak_curves"):
            return "F"

        # D — obsolete curves only, no strong curves, or moderate DH
        if curve_data.get("supported_curves") and not curve_data.get("strong_curves"):
            return "D"
        if dhe_data.get("strength") == "moderate":
            return "D"

        # C — issues present (but PFS exists with strong curves)
        if issues:
            return "C"

        # B — warnings only
        if warnings:
            return "B"

        # A — clean
        return "A"

    # ── Display ─────────────────────────────────

    def _print_pfs_support(self, data: Dict[str, Any]) -> None:
        if data.get("pfs_available"):
            pfs_list = data.get("pfs_supported_kex", [])
            non_pfs_list = data.get("non_pfs_supported_kex", [])
            self._pass("PFS Available", f"Supported KEX: {', '.join(pfs_list)}")
            if non_pfs_list:
                self._warn(
                    "Non-PFS KEX Available",
                    f"Supported: {', '.join(non_pfs_list)}",
                )
        else:
            self._fail("PFS Available", "Not supported")
            supported = data.get("all_supported_kex", [])
            if supported:
                self._info("Fallback KEX", f"Non-PFS only: {', '.join(supported)}")

        unsupported = data.get("unsupported_kex", [])
        if unsupported:
            self._info("Unsupported KEX", ", ".join(unsupported))

    def _print_curve_analysis(self, data: Dict[str, Any]) -> None:
        supported = data.get("supported_curves", [])
        if not supported:
            self._warn("ECDHE Curves", "None supported (or ECDHE not available)")
            return

        strong = data.get("strong_curves", [])
        obsolete = data.get("obsolete_curves", [])
        weak = data.get("weak_curves", [])

        if strong:
            self._pass("Strong Curves", f"{len(strong)} supported: {', '.join(strong)}")
        if obsolete:
            self._warn("Obsolete Curves", f"{len(obsolete)} supported: {', '.join(obsolete)}")
        if weak:
            self._fail("Weak Curves", f"{len(weak)} supported: {', '.join(weak)}")

        best = data.get("best_curve")
        if best:
            self._info("Best Curve", best)

    def _print_dhe_analysis(self, data: Dict[str, Any]) -> None:
        if data.get("error"):
            self._skip("DHE Parameters", data["error"])
            return

        if not data.get("dhe_supported"):
            self._info("DHE Parameters", "Not supported")
            return

        dhe_bits = data.get("dhe_bits")
        strength = data.get("strength", "unknown")

        if dhe_bits is None:
            self._warn("DHE Parameters", "Supported but parameter size unknown")
            return

        label = f"{dhe_bits} bits"

        if strength == "strong":
            self._pass("DHE Parameters", label)
        elif strength == "moderate":
            self._warn("DHE Parameters", label)
        else:
            self._fail("DHE Parameters", label)

        hs = data.get("handshake_time_ms")
        if hs is not None:
            self._info("DHE Handshake Time", f"{hs} ms")

    def _print_cipher_preference(self, data: Dict[str, Any]) -> None:
        known = data.get("preference_known", False)
        if not known:
            self._skip("Cipher Preference", data.get("error", "Unknown"))
            return

        if data.get("pfs_preferred"):
            self._pass("Cipher Preference", "PFS ciphers preferred")
        else:
            pos = data.get("pfs_at_position")
            if pos is not None:
                self._warn("Cipher Preference", f"First PFS cipher at position {pos}")
            else:
                self._fail("Cipher Preference", "No PFS ciphers in server list")

        pfs_c = data.get("pfs_cipher_count", 0)
        non_pfs_c = data.get("non_pfs_cipher_count", 0)
        self._info("Cipher Count", f"{pfs_c} PFS, {non_pfs_c} non-PFS")

    def _print_session_resumption(self, data: Dict[str, Any]) -> None:
        mode = data.get("resumption_mode", "none")
        label, status = SESSION_RESUMPTION_LABELS.get(mode, ("INFO", "Unknown"))

        if status == "PASS":
            self._pass("Resumption Mode", label)
        elif status == "WARN":
            self._warn("Resumption Mode", label)
        elif status == "FAIL":
            self._fail("Resumption Mode", label)
        else:
            self._info("Resumption Mode", label)

        details = data.get("details", {})
        for mode_key in SESSION_RESUMPTION_MODES:
            mode_data = details.get(mode_key, {})
            if mode_data.get("supported"):
                self._pass(f"  {mode_key}", "Supported")
                if mode_key == "session_ticket":
                    lifetime = mode_data.get("ticket_lifetime_hours")
                    if lifetime is not None:
                        label_life = f"{lifetime}h lifetime"
                        if lifetime > SESSION_TICKET_LIFETIME_MAX_RECOMMENDED_HOURS:
                            self._warn("  Ticket Lifetime", label_life)
                        else:
                            self._pass("  Ticket Lifetime", label_life)
            else:
                err = mode_data.get("error", "Not supported")
                self._skip(f"  {mode_key}", err)

        lifetime_warning = data.get("ticket_lifetime_warning")
        if lifetime_warning:
            self._warn("Ticket Warning", lifetime_warning)

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