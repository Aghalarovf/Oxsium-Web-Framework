from typing import Dict, List, Optional, Tuple, Any, Set
import re

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
    "OK": 0.0,
}

HEADER_SCORE_BOOST = {
    "Strict-Transport-Security": 15,
    "Content-Security-Policy": 20,
    "X-Frame-Options": 8,
    "X-Content-Type-Options": 8,
    "Referrer-Policy": 6,
    "Permissions-Policy": 6,
    "Cache-Control": 5,
    "Access-Control-Allow-Origin": 3,
    "X-Powered-By": 0,
}

HEADER_RECOMMENDATIONS = {
    "Strict-Transport-Security": {
        "present": "Set Strict-Transport-Security with max-age=31536000; includeSubDomains; preload",
        "missing": "Missing Strict-Transport-Security — configure on HTTPS responses to enforce TLS",
        "weak": "Increase HSTS max-age to at least 31536000 (1 year) and add includeSubDomains",
    },
    "Content-Security-Policy": {
        "present": "Review CSP directives to ensure they follow least-privilege; avoid unsafe-inline and wildcards",
        "missing": "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection",
        "weak": "CSP contains unsafe sources ('unsafe-inline', 'unsafe-eval', or wildcard origins) — tighten directives",
    },
    "X-Frame-Options": {
        "present": "X-Frame-Options is set — consider also adding CSP frame-ancestors as a modern alternative",
        "missing": "Missing X-Frame-Options — page may be vulnerable to clickjacking attacks",
        "weak": "X-Frame-Options uses deprecated or permissive value — set to DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "present": "X-Content-Type-Options: nosniff is correctly configured",
        "missing": "Missing X-Content-Type-Options — browsers may MIME-sniff leading to content confusion attacks",
        "weak": "Invalid X-Content-Type-Options value — only 'nosniff' is valid",
    },
    "Referrer-Policy": {
        "present": "Referrer-Policy restricts referrer leakage",
        "missing": "Missing Referrer-Policy — browser default may leak full URL in Referer header",
        "weak": "Referrer-Policy uses unsafe value (unsafe-url or no-referrer-when-downgrade) — use strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "present": "Permissions-Policy restricts browser feature access",
        "missing": "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted",
        "weak": "Permissions-Policy does not restrict all sensitive features",
    },
    "X-Powered-By": {
        "present": "Remove or obfuscate X-Powered-By, X-AspNet-Version, and similar technology disclosure headers",
        "missing": "No technology disclosure headers detected — good practice",
        "weak": "Technology version exposed in headers — aids attacker reconnaissance",
    },
    "Cache-Control": {
        "present": "Cache-Control with no-store is configured for sensitive responses",
        "missing": "Missing Cache-Control for sensitive responses — data may be cached in browser or proxies",
        "weak": "Cache-Control allows public caching of sensitive data — set no-store for authenticated responses",
    },
    "Access-Control-Allow-Origin": {
        "present": "CORS is configured with explicit allowed origins",
        "missing": "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)",
        "weak": "CORS allows wildcard origin or origin reflection with credentials enabled — high risk of data exfiltration",
    },
}


class SecurityScoreAnalysis:
    def __init__(self):
        self.grade: str = "F"
        self.numeric_score: float = 0.0
        self.max_possible_score: float = 100.0
        self.present_headers: Set[str] = set()
        self.missing_headers: Set[str] = set()
        self.weak_headers: Set[str] = set()
        self.critical_findings: int = 0
        self.high_findings: int = 0
        self.medium_findings: int = 0
        self.low_findings: int = 0
        self.info_findings: int = 0
        self.ok_findings: int = 0
        self.total_findings: int = 0
        self.conflicts: List[Tuple[str, str, str]] = []
        self.recommendations: List[str] = []
        self.categorized_recommendations: Dict[str, List[str]] = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Informational": [],
        }
        self.grade_breakdown: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade,
            "numeric_score": round(self.numeric_score, 1),
            "max_possible_score": self.max_possible_score,
            "present_headers": sorted(self.present_headers),
            "missing_headers": sorted(self.missing_headers),
            "weak_headers": sorted(self.weak_headers),
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "info_findings": self.info_findings,
            "ok_findings": self.ok_findings,
            "total_findings": self.total_findings,
            "conflicts": self.conflicts,
            "recommendations": self.recommendations,
            "categorized_recommendations": self.categorized_recommendations,
            "grade_breakdown": self.grade_breakdown,
        }


class SecurityScoreModule(BaseHeaderModule):
    name = "Security Rating & Grade Calculator"
    description = "Aggregates all header analysis findings into a letter grade (A+ through F) with prioritized remediation recommendations."

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        headers = response.headers

        analysis = self.calculate_grade_from_headers(headers)
        self.generate_recommendations(analysis)

        raw_conflicts = self.detect_raw_misconfigurations(headers)
        analysis.conflicts = raw_conflicts
        for sev, header, detail in raw_conflicts:
            result.add_finding(sev, f"Header Conflict: {header}", detail)

        result.add_finding(
            "INFO",
            "Security Grade",
            f"Overall security rating: {analysis.grade} ({round(analysis.numeric_score, 1)}/{analysis.max_possible_score})"
        )

        for rec in analysis.recommendations:
            result.add_finding("INFO", "Recommendation", rec)

        result.metadata["score_summary"] = {
            "grade": analysis.grade,
            "score": round(analysis.numeric_score, 1),
            "recommendations": analysis.recommendations,
        }
        result.metadata["security_score"] = analysis.to_dict()
        return result

    def calculate_grade_from_headers(self, headers: Dict[str, str]) -> SecurityScoreAnalysis:
        analysis = SecurityScoreAnalysis()
        header_map = {k.lower(): v for k, v in headers.items()}

        for header, boost in HEADER_SCORE_BOOST.items():
            key = header.lower()
            value = header_map.get(key)

            if header == "X-Powered-By":
                if value:
                    analysis.weak_headers.add(header)
                    analysis.high_findings += 1
                    analysis.total_findings += 1
                else:
                    analysis.ok_findings += 1
                    analysis.present_headers.add(header)
                continue

            if value is None:
                analysis.missing_headers.add(header)
                analysis.high_findings += 1
                analysis.total_findings += 1
            else:
                weak = self._is_weak(header, value)
                if weak:
                    analysis.weak_headers.add(header)
                    analysis.medium_findings += 1
                    analysis.total_findings += 1
                else:
                    analysis.present_headers.add(header)
                    analysis.ok_findings += 1
                    analysis.total_findings += 1

        missing_penalty = sum(
            HEADER_SCORE_BOOST[h] for h in analysis.missing_headers if h in HEADER_SCORE_BOOST
        )
        weak_penalty = sum(
            HEADER_SCORE_BOOST.get(h, 0) * 0.4 for h in analysis.weak_headers
        )
        xpb_penalty = 10.0 if "X-Powered-By" in analysis.weak_headers else 0.0

        total_penalty = missing_penalty + weak_penalty + xpb_penalty

        coverage_bonus = sum(
            HEADER_SCORE_BOOST[h] for h in analysis.present_headers if h in HEADER_SCORE_BOOST
        )

        analysis.numeric_score = max(0.0, min(100.0, 100.0 - total_penalty))
        analysis.max_possible_score = 100.0
        analysis.grade = self._score_to_grade(analysis.numeric_score, analysis.critical_findings > 0)
        analysis.grade_breakdown = self._build_grade_breakdown(analysis)

        return analysis

    def _is_weak(self, header: str, value: str) -> bool:
        v = value.lower().strip()
        if header == "Strict-Transport-Security":
            import re as _re
            m = _re.search(r"max-age=(\d+)", v)
            if not m or int(m.group(1)) < 31536000:
                return True
            return False
        if header == "Content-Security-Policy":
            return any(x in v for x in ("unsafe-inline", "unsafe-eval", "*"))
        if header == "X-Frame-Options":
            return v not in ("deny", "sameorigin")
        if header == "X-Content-Type-Options":
            return v != "nosniff"
        if header == "Referrer-Policy":
            return v in ("unsafe-url", "no-referrer-when-downgrade", "")
        if header == "Cache-Control":
            return "no-store" not in v
        if header == "Access-Control-Allow-Origin":
            return v == "*"
        return False

    def calculate_grade(self, module_results: List[ModuleResult]) -> SecurityScoreAnalysis:
        return SecurityScoreAnalysis()

    def _score_to_grade(self, score: float, has_critical: bool) -> str:
        if has_critical:
            return "F"
        if score >= 95:
            return "A+"
        if score >= 85:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def _build_grade_breakdown(self, analysis: SecurityScoreAnalysis) -> str:
        parts = []
        parts.append(f"Grade: {analysis.grade} ({round(analysis.numeric_score, 1)}/100)")
        parts.append(f"Critical findings: {analysis.critical_findings}")
        parts.append(f"High findings: {analysis.high_findings}")
        parts.append(f"Medium findings: {analysis.medium_findings}")
        parts.append(f"Low findings: {analysis.low_findings}")
        parts.append(f"Info findings: {analysis.info_findings}")
        parts.append(f"Headers present: {len(analysis.present_headers)}")
        parts.append(f"Headers missing: {len(analysis.missing_headers)}")
        parts.append(f"Headers weak: {len(analysis.weak_headers)}")
        return "; ".join(parts)

    def _analyze_missing_headers(self, analysis: SecurityScoreAnalysis, module_results: List[ModuleResult]):
        observed_headers = set()
        for mod_result in module_results:
            for finding in mod_result.findings:
                if finding.severity == "OK":
                    observed_headers.add(finding.check_name)

        for header in HEADER_RECOMMENDATIONS:
            if header not in observed_headers:
                analysis.missing_headers.add(header)

    def generate_recommendations(self, analysis: SecurityScoreAnalysis):
        recs: List[str] = []

        if analysis.critical_findings > 0:
            msg = f"CRITICAL: Address {analysis.critical_findings} critical finding(s) immediately — these represent active exploitation vectors"
            recs.append(msg)
            analysis.categorized_recommendations["Critical"].append(msg)

        if analysis.high_findings > 0:
            msg = f"HIGH: Remediate {analysis.high_findings} high severity issue(s) as next priority"
            recs.append(msg)
            analysis.categorized_recommendations["High"].append(msg)

        for header in analysis.missing_headers:
            if header in HEADER_RECOMMENDATIONS:
                rec = HEADER_RECOMMENDATIONS[header]["missing"]
                recs.append(rec)
                analysis.categorized_recommendations["High"].append(rec)

        for header in analysis.weak_headers:
            if header in HEADER_RECOMMENDATIONS:
                rec = HEADER_RECOMMENDATIONS[header]["weak"]
                recs.append(rec)

                if "unsafe" in rec.lower() or "wildcard" in rec.lower() or "credentials" in rec.lower():
                    analysis.categorized_recommendations["High"].append(rec)
                else:
                    analysis.categorized_recommendations["Medium"].append(rec)

        for header in analysis.present_headers:
            if header in HEADER_RECOMMENDATIONS:
                rec = HEADER_RECOMMENDATIONS[header]["present"]
                if header not in analysis.weak_headers:
                    analysis.categorized_recommendations["Informational"].append(rec)

        if analysis.medium_findings > 0:
            msg = f"MEDIUM: Review {analysis.medium_findings} medium severity finding(s) in next sprint"
            recs.append(msg)
            analysis.categorized_recommendations["Medium"].append(msg)

        if analysis.low_findings > 0:
            msg = f"LOW: Address {analysis.low_findings} low severity finding(s) for defense-in-depth"
            recs.append(msg)
            analysis.categorized_recommendations["Low"].append(msg)

        if analysis.numeric_score >= 95:
            recs.append("Excellent security posture — maintain current policy and monitor for new header standards")
            analysis.categorized_recommendations["Informational"].append(
                "Excellent security posture — maintain current policy and monitor for new header standards"
            )

        analysis.recommendations = recs

    def detect_raw_misconfigurations(self, headers: Dict[str, str]) -> List[Tuple[str, str, str]]:
        conflicts: List[Tuple[str, str, str]] = []
        if not headers:
            return conflicts

        header_map = {k.lower(): v for k, v in headers.items()}

        hsts = header_map.get("strict-transport-security")
        if hsts and not any(hsts.lower().startswith("max-age=0") for hsts_version in [hsts]):
            location = header_map.get("location")
            if location and location.startswith("http://"):
                conflicts.append((
                    "MEDIUM",
                    "Strict-Transport-Security",
                    "HSTS is configured but a non-HTTPS redirect (http://) is present in Location header"
                ))

        csp = header_map.get("content-security-policy", "")
        xfo = header_map.get("x-frame-options", "")
        if csp and xfo:
            if "frame-ancestors" in csp and xfo.lower() in ("deny", "sameorigin"):
                conflicts.append((
                    "LOW",
                    "X-Frame-Options & CSP",
                    "Both X-Frame-Options and CSP frame-ancestors are set; modern browsers prefer frame-ancestors — redundant protection"
                ))

        cache_cc = header_map.get("cache-control", "")
        if cache_cc:
            cc_lower = cache_cc.lower()
            if "no-store" in cc_lower and "public" in cc_lower:
                conflicts.append((
                    "LOW",
                    "Cache-Control",
                    "Cache-Control contains both 'no-store' and 'public' — conflicting directives; no-store takes precedence but public should be removed"
                ))
            if "no-cache" in cc_lower and "max-age" in cc_lower:
                conflicts.append((
                    "INFO",
                    "Cache-Control",
                    "'no-cache' and 'max-age' together may produce inconsistent caching behavior across different browsers"
                ))

        csp_ro = header_map.get("content-security-policy-report-only", "")
        csp_enforce = header_map.get("content-security-policy", "")
        if csp_ro and csp_enforce:
            ro_directives = self._parse_csp_directives(csp_ro)
            en_directives = self._parse_csp_directives(csp_enforce)
            for directive in set(ro_directives.keys()) & set(en_directives.keys()):
                if ro_directives[directive] != en_directives[directive]:
                    conflicts.append((
                        "INFO",
                        "CSP Report-Only vs Enforce",
                        f"CSP directive '{directive}' differs between Report-Only and enforced policy — "
                        f"verify intent: Report-Only='{ro_directives[directive]}' vs Enforce='{en_directives[directive]}'"
                    ))

        acao = header_map.get("access-control-allow-origin", "")
        acac = header_map.get("access-control-allow-credentials", "")
        if acao.strip() == "*" and acac and acac.strip().lower() == "true":
            conflicts.append((
                "CRITICAL",
                "CORS",
                "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — spec-invalid but highly dangerous if processed"
            ))

        xpb = header_map.get("x-powered-by", "")
        server = header_map.get("server", "")
        if xpb and server:
            if "asp.net" in xpb.lower() and "microsoft-iis" in server.lower():
                conflicts.append((
                    "INFO",
                    "Technology Stack Consistency",
                    "X-Powered-By: ASP.NET and Server: Microsoft-IIS — consistent stack, but both leak technology information"
                ))

        pragma = header_map.get("pragma", "")
        if cache_cc and pragma:
            if "no-cache" in pragma.lower() and "no-store" not in cache_cc.lower():
                conflicts.append((
                    "LOW",
                    "Cache Directives",
                    "Pragma: no-cache without Cache-Control: no-store — HTTP/1.0 fallback does not prevent modern browser caching"
                ))

        multiple_hsts = [v for k, v in header_map.items() if k == "strict-transport-security"]
        if len(multiple_hsts) > 1:
            values = "; ".join(multiple_hsts[:3])
            conflicts.append((
                "MEDIUM",
                "Strict-Transport-Security",
                f"Multiple HSTS headers present ({len(multiple_hsts)}): '{values}' — only the first is processed"
            ))

        location = header_map.get("location")
        if location:
            stripped_location = location.strip()
            if stripped_location.lower().startswith("http://"):
                conflicts.append((
                    "MEDIUM",
                    "Redirect Security",
                    f"Location header redirects to non-HTTPS URL: '{stripped_location[:80]}' — redirect downgrade risk"
                ))

        set_cookie = header_map.get("set-cookie", "")
        if set_cookie and not csp:
            conflicts.append((
                "LOW",
                "Cookie without CSP",
                "Set-Cookie present but Content-Security-Policy is missing — cookies may be accessible to injected scripts"
            ))

        return conflicts

    def _parse_csp_directives(self, csp_value: str) -> Dict[str, Optional[str]]:
        directives = {}
        for segment in csp_value.split(";"):
            segment = segment.strip()
            if not segment:
                continue
            parts = segment.split(None, 1)
            directive_name = parts[0].lower()
            directive_value = parts[1] if len(parts) > 1 else None
            directives[directive_name] = directive_value
        return directives
