from typing import Any, Dict, List, Optional, Tuple

from .base import BaseModule
from core.network import TLS_VERSION_MAP, ConnectionResult


PROTOCOL_ORDER = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
SECURE_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}

ALPN_PROBES = [
    ["h2", "http/1.1"],
    ["h2"],
    ["http/1.1"],
    ["spdy/3.1"],
    ["ftp"],
    ["imap"],
    ["pop3"],
    ["smtp"],
    ["xmpp-client"],
    ["acme-tls/1"],
]

SECURITY_RATINGS = {
    "SSLv2":   ("CRITICAL", "Broken - practical attacks exist"),
    "SSLv3":   ("CRITICAL", "POODLE attack"),
    "TLSv1.0": ("WARN",     "Deprecated by RFC 8996"),
    "TLSv1.1": ("WARN",     "Deprecated by RFC 8996"),
    "TLSv1.2": ("PASS",     "Secure"),
    "TLSv1.3": ("PASS",     "Recommended"),
}


class ProtocolModule(BaseModule):
    name = "protocols"
    description = "TLS/SSL protocol support matrix, handshake details and ALPN"

    def run(self) -> Dict[str, Any]:
        self.logger.section("Protocol Module")

        self.logger.subsection("Protocol Support Matrix")
        protocol_results = self._probe_all_protocols()
        self._print_protocol_matrix(protocol_results)

        self.logger.subsection("Handshake Details")
        handshake_data = self._collect_handshake_details(protocol_results)
        self._print_handshake_details(handshake_data)

        self.logger.subsection("ALPN Negotiation")
        alpn_data = self._probe_alpn()
        self._print_alpn_results(alpn_data)

        self.logger.subsection("Protocol Assessment")
        assessment = self._assess(protocol_results, alpn_data)
        self._print_assessment(assessment)

        return {
            "protocols": protocol_results,
            "handshake": handshake_data,
            "alpn": alpn_data,
            "assessment": assessment,
        }

    def _probe_all_protocols(self) -> List[Dict[str, Any]]:
        results = []
        for version_name in PROTOCOL_ORDER:
            entry = self._probe_single_protocol(version_name)
            results.append(entry)
        return results

    def _probe_single_protocol(self, version_name: str) -> Dict[str, Any]:
        result = self.connection.probe_version(version_name)
        supported = result.success
        rating, reason = SECURITY_RATINGS.get(version_name, ("INFO", ""))

        entry: Dict[str, Any] = {
            "version": version_name,
            "supported": supported,
            "rating": rating,
            "rating_reason": reason,
            "error": result.error if not supported else None,
        }

        if supported:
            entry["negotiated_version"] = result.version
            entry["cipher"] = self._cipher_tuple_to_dict(result.cipher)
            entry["handshake_time_ms"] = result.handshake_time_ms

        return entry

    def _collect_handshake_details(
        self, protocol_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        best = self._pick_best_supported(protocol_results)
        if best is None:
            return {"error": "No supported protocol found"}

        version_enum = TLS_VERSION_MAP.get(best)
        if version_enum is None:
            return {"error": f"No TLS version mapping found for {best}"}

        result = self.connection.connect(
            min_version=version_enum,
            max_version=version_enum,
        )

        if not result.success:
            return {"error": result.error}

        return {
            "negotiated_version": result.version,
            "cipher": self._cipher_tuple_to_dict(result.cipher),
            "handshake_time_ms": result.handshake_time_ms,
            "session_ticket": self._detect_session_ticket(result),
        }

    def _probe_alpn(self) -> Dict[str, Any]:
        negotiated: Dict[str, Optional[str]] = {}
        supported_protocols: List[str] = []

        for probe in ALPN_PROBES:
            key = "+".join(probe)
            result = self.connection.connect(alpn_protocols=probe)
            if result.success:
                alpn = result.alpn_protocol
                negotiated[key] = alpn
                if alpn and alpn not in supported_protocols:
                    supported_protocols.append(alpn)
            else:
                negotiated[key] = None

        http2_supported = "h2" in supported_protocols
        http11_supported = "http/1.1" in supported_protocols

        return {
            "probe_results": negotiated,
            "supported_protocols": supported_protocols,
            "http2_supported": http2_supported,
            "http11_supported": http11_supported,
        }

    def _assess(
        self,
        protocol_results: List[Dict[str, Any]],
        alpn_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        issues: List[str] = []
        warnings: List[str] = []
        notes: List[str] = []

        supported_names = [
            p["version"] for p in protocol_results if p["supported"]
        ]

        has_critical = False
        for proto in supported_names:
            if proto in DEPRECATED_PROTOCOLS:
                rating, reason = SECURITY_RATINGS[proto]
                if rating == "CRITICAL":
                    issues.append(f"{proto} is supported ({reason})")
                    has_critical = True
                else:
                    warnings.append(f"{proto} is supported ({reason})")

        has_secure = any(p in supported_names for p in SECURE_PROTOCOLS)
        if not has_secure:
            issues.append("No secure TLS version (TLSv1.2 or TLSv1.3) is supported")

        if "TLSv1.3" not in supported_names:
            warnings.append("TLSv1.3 not supported (recommended)")

        if alpn_data.get("http2_supported"):
            notes.append("HTTP/2 (h2) negotiated via ALPN")
        else:
            notes.append("HTTP/2 (h2) not advertised via ALPN")

        if not supported_names:
            grade = "F"
        elif has_critical:
            grade = "F"
        elif issues:
            grade = "C"
        elif warnings:
            grade = "B"
        else:
            grade = "A"

        return {
            "grade": grade,
            "supported_protocols": supported_names,
            "issues": issues,
            "warnings": warnings,
            "notes": notes,
        }

    def _pick_best_supported(
        self, protocol_results: List[Dict[str, Any]]
    ) -> Optional[str]:
        supported = {p["version"] for p in protocol_results if p["supported"]}
        for version_name in reversed(PROTOCOL_ORDER):
            if version_name in supported:
                return version_name
        return None

    def _cipher_tuple_to_dict(
        self, cipher: Optional[Tuple]
    ) -> Optional[Dict[str, Any]]:
        if not cipher:
            return None
        name, protocol, bits = cipher[0], cipher[1], cipher[2]
        return {"name": name, "protocol": protocol, "bits": bits}

    def _detect_session_ticket(self, result: ConnectionResult) -> Optional[bool]:
        raw = getattr(result, "session_ticket", None)
        if raw is None:
            return None
        return bool(raw)

    def _print_protocol_matrix(self, results: List[Dict[str, Any]]) -> None:
        for entry in results:
            version = entry["version"]
            supported = entry["supported"]
            rating = entry["rating"]
            reason = entry["rating_reason"]
            hs_ms = entry.get("handshake_time_ms")

            if not supported:
                self._skip(version, f"Not supported  [{reason}]")
                continue

            hs_str = f"  ({hs_ms} ms)" if hs_ms is not None else ""
            label = f"Supported{hs_str}  [{reason}]"

            if rating == "PASS":
                self._pass(version, label)
            elif rating == "WARN":
                self._warn(version, label)
            else:
                self._fail(version, label)

    def _print_handshake_details(self, data: Dict[str, Any]) -> None:
        if data.get("error"):
            self._fail("Handshake", data["error"])
            return

        self._info("Negotiated Version", data.get("negotiated_version", "N/A"))

        cipher = data.get("cipher")
        if cipher:
            self._info("Cipher Suite", cipher.get("name", "N/A"))
            self._info("Cipher Bits", str(cipher.get("bits", "N/A")))

        hs_ms = data.get("handshake_time_ms")
        if hs_ms is not None:
            if hs_ms < 150:
                self._pass("Handshake Time", f"{hs_ms} ms")
            elif hs_ms < 500:
                self._warn("Handshake Time", f"{hs_ms} ms")
            else:
                self._fail("Handshake Time", f"{hs_ms} ms (slow)")

        session_ticket = data.get("session_ticket")
        if session_ticket is True:
            self._pass("Session Ticket", "Supported")
        elif session_ticket is False:
            self._info("Session Ticket", "Not supported")

    def _print_alpn_results(self, data: Dict[str, Any]) -> None:
        supported = data.get("supported_protocols", [])

        if not supported:
            self._warn("ALPN", "No ALPN protocols negotiated")
        else:
            self._pass("ALPN Protocols", ", ".join(supported))

        if data.get("http2_supported"):
            self._pass("HTTP/2 (h2)", "Supported via ALPN")
        else:
            self._info("HTTP/2 (h2)", "Not advertised")

        if data.get("http11_supported"):
            self._pass("HTTP/1.1", "Supported via ALPN")
        else:
            self._info("HTTP/1.1", "Not advertised")

        for probe_key, negotiated in data.get("probe_results", {}).items():
            if negotiated:
                self._info(f"  Probe [{probe_key}]", negotiated)

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