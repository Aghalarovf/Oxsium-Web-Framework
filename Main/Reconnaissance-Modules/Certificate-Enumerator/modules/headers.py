from typing import Dict, Any, List, Optional, Tuple
import re

from .base import BaseModule
from core.network import ConnectionResult


# ──────────────────────────────────────────────
# Certificate-related HTTP security headers
# ──────────────────────────────────────────────

HSTS_DEFINITION = {
    "name": "strict-transport-security",
    "description": "HTTP Strict-Transport-Security — enforces TLS for all subdomains",
    "max_score": 15,
}

EXPECT_CT_DEFINITION = {
    "name": "expect-ct",
    "description": "Expect-CT — Certificate Transparency enforcement (deprecated but still checked)",
    "max_score": 5,
}

HPKP_DEFINITION = {
    "name": "public-key-pins",
    "description": "Public-Key-Pins (HPKP) — deprecated, presence flagged as warning",
    "max_score": 0,  # no positive score; flagged as misconfiguration
}

CERT_HEADER_DEFINITIONS = [HSTS_DEFINITION, EXPECT_CT_DEFINITION, HPKP_DEFINITION]

MAX_SCORE = 20  # HSTS(15) + Expect-CT(5)

GRADE_THRESHOLDS: List[Tuple[str, int, str]] = [
    ("A", 18, "Certificate headers well-configured"),
    ("B", 14, "Acceptable, minor improvements possible"),
    ("C", 10, "Moderate, some headers missing"),
    ("D", 5,  "Poor, critical headers absent"),
    ("F", 0,  "No certificate-related security headers"),
]


class CertHeaderModule(BaseModule):
    name = "headers"
    description = "Certificate-related HTTP security headers (HSTS, Expect-CT, HPKP)"

    def run(self) -> Dict[str, Any]:
        self.logger.section("Certificate Headers Module")

        raw_headers = self._fetch_headers()

        if raw_headers is None:
            self.logger.error("Failed to retrieve HTTP response headers")
            return {
                "headers": None,
                "error": "Failed to retrieve HTTP response headers",
            }

        self.logger.subsection("Raw Headers")
        self._print_raw_headers(raw_headers)

        self.logger.subsection("HSTS Analysis")
        hsts_data = self._analyze_hsts(raw_headers)
        self._print_hsts(hsts_data)

        self.logger.subsection("Expect-CT Analysis")
        expect_ct_data = self._analyze_expect_ct(raw_headers)
        self._print_expect_ct(expect_ct_data)

        self.logger.subsection("HPKP Check (Deprecated)")
        hpkp_data = self._check_hpkp(raw_headers)
        self._print_hpkp(hpkp_data)

        self.logger.subsection("Certificate Headers Score")
        score_data = self._score(hsts_data, expect_ct_data, hpkp_data)
        self._print_score(score_data)

        return {
            "raw_headers": dict(raw_headers),
            "hsts": hsts_data,
            "expect_ct": expect_ct_data,
            "hpkp": hpkp_data,
            "score": score_data,
        }

    # ── Fetch ──────────────────────────────────

    def _fetch_headers(self) -> Optional[Dict[str, str]]:
        """Perform an HTTP GET to the target and return response headers."""
        result = self.connection.fetch_http_headers()
        if not result.success:
            return None

        raw = getattr(result, "headers", None)
        if raw and isinstance(raw, dict):
            return {k.lower(): v for k, v in raw.items()}
        return None

    # ── HSTS ────────────────────────────────────

    def _analyze_hsts(self, headers: Dict[str, str]) -> Dict[str, Any]:
        raw_value = headers.get("strict-transport-security")

        if raw_value is None:
            return {
                "present": False,
                "raw_value": None,
                "issues": ["HSTS header is missing"],
                "score": 0,
            }

        parsed = self._parse_hsts_directives(raw_value)
        issues: List[str] = []
        deductions = 0

        # max-age
        max_age = parsed.get("max-age")
        if max_age is None:
            issues.append("Missing max-age directive")
            deductions += 5
        elif not max_age.isdigit():
            issues.append(f"Non-numeric max-age value: {max_age}")
            deductions += 5
        else:
            max_age_sec = int(max_age)
            if max_age_sec == 0:
                issues.append("max-age=0 (HSTS is disabled)")
                deductions += 15
            elif max_age_sec < 10800:  # < 3 hours
                issues.append(f"Short max-age ({max_age_sec}s / {max_age_sec // 60}m)")
                deductions += 4
            elif max_age_sec < 86400:  # < 1 day
                issues.append(f"Moderate max-age ({max_age_sec}s / {max_age_sec // 86400}d)")
                deductions += 2
            elif max_age_sec < 31536000:  # < 1 year
                pass  # acceptable but not ideal
            # >= 1 year is ideal, no deduction

        # includeSubDomains
        if "includesubdomains" not in parsed:
            issues.append("Missing includeSubDomains directive")
            deductions += 3

        # preload
        preload = "preload" in parsed

        score = max(0, HSTS_DEFINITION["max_score"] - deductions)

        return {
            "present": True,
            "raw_value": raw_value,
            "parsed": parsed,
            "max_age_seconds": int(max_age) if max_age and max_age.isdigit() else None,
            "includes_subdomains": "includesubdomains" in parsed,
            "preload": preload,
            "issues": issues,
            "score": score,
        }

    def _parse_hsts_directives(self, value: str) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for part in value.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                result[key.strip().lower()] = val.strip()
            else:
                result[part.lower()] = "true"
        return result

    # ── Expect-CT ───────────────────────────────

    def _analyze_expect_ct(self, headers: Dict[str, str]) -> Dict[str, Any]:
        raw_value = headers.get("expect-ct")

        if raw_value is None:
            return {
                "present": False,
                "raw_value": None,
                "issues": ["Expect-CT header is missing (optional but recommended for CT enforcement)"],
                "score": 0,
            }

        parsed = self._parse_expect_ct_directives(raw_value)
        issues: List[str] = []
        deductions = 0

        max_age = parsed.get("max-age")
        if max_age is None:
            issues.append("Missing max-age directive in Expect-CT")
            deductions += 3
        elif not max_age.isdigit():
            issues.append(f"Non-numeric max-age in Expect-CT: {max_age}")
            deductions += 2
        else:
            max_age_sec = int(max_age)
            if max_age_sec == 0:
                issues.append("Expect-CT max-age=0 (enforcement disabled)")
                deductions += 5
            elif max_age_sec < 86400:
                deductions += 1

        enforce = "enforce" in parsed
        report_uri = parsed.get("report-uri")

        score = max(0, EXPECT_CT_DEFINITION["max_score"] - deductions)

        return {
            "present": True,
            "raw_value": raw_value,
            "parsed": parsed,
            "max_age_seconds": int(max_age) if max_age and max_age.isdigit() else None,
            "enforce": enforce,
            "report_uri": report_uri,
            "issues": issues,
            "score": score,
        }

    def _parse_expect_ct_directives(self, value: str) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for part in value.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                result[key.strip().lower()] = val.strip()
            else:
                result[part.lower()] = "true"
        return result

    # ── HPKP ────────────────────────────────────

    def _check_hpkp(self, headers: Dict[str, str]) -> Dict[str, Any]:
        raw_value = headers.get("public-key-pins")

        if raw_value is None:
            return {
                "present": False,
                "raw_value": None,
                "warning": None,
            }

        return {
            "present": True,
            "raw_value": raw_value,
            "warning": (
                "HPKP (Public-Key-Pins) is DEPRECATED (RFC 7469 obsoleted). "
                "Remove this header and rely on Certificate Transparency + HSTS instead."
            ),
        }

    # ── Scoring ─────────────────────────────────

    def _score(
        self,
        hsts_data: Dict[str, Any],
        expect_ct_data: Dict[str, Any],
        hpkp_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        hsts_score = hsts_data.get("score", 0)
        expect_ct_score = expect_ct_data.get("score", 0)

        total = hsts_score + expect_ct_score
        total = min(total, MAX_SCORE)

        # Determine grade
        grade = "F"
        for label, threshold, description in GRADE_THRESHOLDS:
            if total >= threshold:
                grade = label
                break

        # Collect all issues and warnings
        all_issues: List[str] = []
        all_warnings: List[str] = []
        all_notes: List[str] = []

        all_issues.extend(hsts_data.get("issues", []))
        all_issues.extend(expect_ct_data.get("issues", []))

        if hpkp_data.get("present"):
            all_warnings.append(hpkp_data["warning"])

        if hsts_data.get("preload"):
            all_notes.append("HSTS preload directive present — domain may be in Chrome/FF preload lists")

        return {
            "total_score": total,
            "max_score": MAX_SCORE,
            "hsts_score": hsts_score,
            "expect_ct_score": expect_ct_score,
            "grade": grade,
            "issues": all_issues,
            "warnings": all_warnings,
            "notes": all_notes,
        }

    # ── Display ─────────────────────────────────

    def _print_raw_headers(self, headers: Dict[str, str]) -> None:
        cert_relevant = {"strict-transport-security", "expect-ct", "public-key-pins"}
        shown = False
        for key, value in sorted(headers.items()):
            if key in cert_relevant:
                self._info(key, value)
                shown = True
        if not shown:
            self._skip("Certificate Headers", "None found in response")

    def _print_hsts(self, data: Dict[str, Any]) -> None:
        if not data["present"]:
            self._warn("HSTS", "Not set")
            return

        max_age = data.get("max_age_seconds")
        sub = data.get("includes_subdomains", False)
        preload = data.get("preload", False)

        parts = [f"max-age={max_age}s" if max_age else "max-age=?"]
        parts.append("includeSubDomains" if sub else "no includeSubDomains")
        if preload:
            parts.append("preload")

        score = data.get("score", 0)
        if score >= 12:
            self._pass("HSTS", ", ".join(parts))
        elif score >= 7:
            self._warn("HSTS", ", ".join(parts))
        else:
            self._fail("HSTS", ", ".join(parts))

        for issue in data.get("issues", []):
            if "missing" in issue.lower() or "disabled" in issue.lower():
                self._fail("  HSTS Issue", issue)
            else:
                self._warn("  HSTS Issue", issue)

    def _print_expect_ct(self, data: Dict[str, Any]) -> None:
        if not data["present"]:
            self._info("Expect-CT", "Not set (optional)")
            return

        max_age = data.get("max_age_seconds")
        enforce = data.get("enforce", False)
        report_uri = data.get("report_uri", None)

        parts = [f"max-age={max_age}s" if max_age else "max-age=?"]
        if enforce:
            parts.append("enforce")
        if report_uri:
            parts.append(f"report-uri={report_uri}")

        score = data.get("score", 0)
        if score >= 4:
            self._pass("Expect-CT", ", ".join(parts))
        elif score >= 2:
            self._warn("Expect-CT", ", ".join(parts))
        else:
            self._fail("Expect-CT", ", ".join(parts))

        for issue in data.get("issues", []):
            self._warn("  Expect-CT Issue", issue)

    def _print_hpkp(self, data: Dict[str, Any]) -> None:
        if not data["present"]:
            self._pass("HPKP", "Not set (correct — deprecated)")
            return

        self._fail("HPKP", "PRESENT — DEPRECATED, remove immediately")
        if data.get("warning"):
            self._warn("  ⚠", data["warning"])

    def _print_score(self, score_data: Dict[str, Any]) -> None:
        total = score_data["total_score"]
        max_s = score_data["max_score"]
        grade = score_data["grade"]

        self._info("Score Breakdown", f"HSTS: {score_data['hsts_score']}/{HSTS_DEFINITION['max_score']}  |  Expect-CT: {score_data['expect_ct_score']}/{EXPECT_CT_DEFINITION['max_score']}")
        self._info("Total", f"{total}/{max_s}")

        if grade in ("A", "A+"):
            self._pass("Grade", grade)
        elif grade == "B":
            self._warn("Grade", grade)
        else:
            self._fail("Grade", grade)

        for issue in score_data.get("issues", []):
            self._fail("Issue", issue)
        for warning in score_data.get("warnings", []):
            self._warn("Warning", warning)
        for note in score_data.get("notes", []):
            self._info("Note", note)