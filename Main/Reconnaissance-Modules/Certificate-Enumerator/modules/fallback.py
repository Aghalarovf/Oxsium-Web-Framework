import struct
import time
import socket
import ssl
from typing import Dict, Any, List, Optional, Tuple
from enum import IntEnum

from .base import BaseModule


VULNERABILITY_DB: Dict[str, Dict[str, Any]] = {
    "fallback_scsv_missing": {
        "cve": "CVE-2014-3566",
        "name": "TLS_FALLBACK_SCSV Not Enforced (POODLE)",
        "cvss": 3.4,
        "description": (
            "Server does not reject ClientHello messages that include TLS_FALLBACK_SCSV "
            "(RFC 7507) with a version lower than the server's maximum supported version. "
            "This allows an active MITM attacker to force a protocol downgrade to an older, "
            "weaker TLS/SSL version, enabling attacks such as POODLE (CVE-2014-3566)."
        ),
    },
    "version_downgrade": {
        "cve": "CVE-2014-3566",
        "name": "Protocol Version Downgrade",
        "cvss": 3.4,
        "description": (
            "Server accepts connections at a version lower than its own maximum, "
            "even when the client signals (via TLS_FALLBACK_SCSV) that the lower "
            "version was chosen due to a fallback, not a genuine version negotiation."
        ),
    },
    "sslv3_enabled": {
        "cve": "CVE-2014-3566",
        "name": "SSLv3 Enabled (POODLE)",
        "cvss": 3.4,
        "description": (
            "Server accepts SSLv3 connections. SSLv3 is cryptographically broken "
            "(POODLE attack) and must be disabled regardless of FALLBACK_SCSV support."
        ),
    },
    "tls10_downgrade": {
        "cve": "CVE-2011-3389",
        "name": "TLS 1.0 Downgrade (BEAST)",
        "cvss": 4.3,
        "description": (
            "Server accepts TLS 1.0 when a higher version is available. "
            "TLS 1.0 is vulnerable to the BEAST attack (CVE-2011-3389) and is "
            "deprecated by RFC 8996."
        ),
    },
    "tls11_downgrade": {
        "cve": "N/A",
        "name": "TLS 1.1 Downgrade",
        "cvss": 2.0,
        "description": (
            "Server accepts TLS 1.1 connections. TLS 1.1 is deprecated by RFC 8996 "
            "and should be disabled in favour of TLS 1.2 and TLS 1.3."
        ),
    },
}


class TLSAlert(IntEnum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    HANDSHAKE_FAILURE = 40
    PROTOCOL_VERSION = 70
    INAPPROPRIATE_FALLBACK = 86
    INTERNAL_ERROR = 80


CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HT_SERVER_HELLO = 2

TLS_FALLBACK_SCSV = b"\x56\x00"

VERSION_BYTES = {
    "SSLv3":   b"\x03\x00",
    "TLSv1.0": b"\x03\x01",
    "TLSv1.1": b"\x03\x02",
    "TLSv1.2": b"\x03\x03",
}

VERSION_NAMES = {v: k for k, v in VERSION_BYTES.items()}
VERSION_NAMES[b"\x03\x04"] = "TLSv1.3"

VERSION_ORDER = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


class FallbackModule(BaseModule):
    name = "fallback"
    description = (
        "Downgrade & Fallback Protection — TLS_FALLBACK_SCSV (RFC 7507), "
        "POODLE (CVE-2014-3566), version downgrade probes across SSLv3 / TLS 1.0–1.2"
    )

    def run(self) -> Dict[str, Any]:
        self.logger.section("Downgrade & Fallback Protection Module")

        results: Dict[str, Any] = {}

        self.logger.subsection("Detecting Highest Supported TLS Version")
        highest = self._detect_highest_version()
        self.logger.info(f"Highest version : {highest or 'unknown'}")

        self.logger.subsection("TLS_FALLBACK_SCSV Enforcement (RFC 7507 / CVE-2014-3566)")
        results["fallback_scsv_missing"] = self._check_fallback_scsv(highest)
        self._print_vuln_result("FALLBACK_SCSV", results["fallback_scsv_missing"])

        self.logger.subsection("SSLv3 Support (POODLE)")
        results["sslv3_enabled"] = self._check_version_accepted("SSLv3")
        self._print_vuln_result("SSLv3", results["sslv3_enabled"])

        self.logger.subsection("TLS 1.0 Downgrade (BEAST)")
        results["tls10_downgrade"] = self._check_version_accepted("TLSv1.0")
        self._print_vuln_result("TLS 1.0", results["tls10_downgrade"])

        self.logger.subsection("TLS 1.1 Downgrade")
        results["tls11_downgrade"] = self._check_version_accepted("TLSv1.1")
        self._print_vuln_result("TLS 1.1", results["tls11_downgrade"])

        self.logger.subsection("Vulnerability Assessment")
        assessment = self._assess(results)
        self._print_assessment(assessment)

        return {
            "highest_version": highest,
            "vulnerabilities": results,
            "assessment": assessment,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_host(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self.connection.host)
        except socket.gaierror:
            return None

    def _recv_all(self, sock: socket.socket, max_size: int) -> bytes:
        data = b""
        try:
            while len(data) < max_size:
                chunk = sock.recv(min(65536, max_size - len(data)))
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, BlockingIOError):
            pass
        return data

    def _parse_tls_records(self, data: bytes) -> List[Tuple[int, str, bytes]]:
        records: List[Tuple[int, str, bytes]] = []
        offset = 0
        while offset + 5 <= len(data):
            content_type = data[offset]
            version_raw = data[offset + 1: offset + 3]
            length = struct.unpack(">H", data[offset + 3: offset + 5])[0]
            end = offset + 5 + length
            if end > len(data):
                break
            records.append((
                content_type,
                VERSION_NAMES.get(version_raw, version_raw.hex()),
                data[offset + 5: end],
            ))
            offset = end
        return records

    def _build_client_hello(
        self,
        tls_version: bytes,
        cipher_suites: Optional[bytes] = None,
        extensions: Optional[bytes] = None,
    ) -> bytes:
        if cipher_suites is None:
            cipher_suites = (
                b"\xc0\x2f"  # ECDHE-RSA-AES128-GCM-SHA256
                b"\xc0\x2b"  # ECDHE-ECDSA-AES128-GCM-SHA256
                b"\x00\x9c"  # AES128-GCM-SHA256
                b"\x00\x2f"  # AES128-SHA
                b"\x00\x35"  # AES256-SHA
                b"\x00\x0a"  # SSL_RSA_WITH_3DES_EDE_CBC_SHA (for SSLv3 compat)
            )

        random_bytes = struct.pack(">I", int(time.time())) + b"\x00" * 28
        session_id = b"\x00"
        cipher_block = struct.pack(">H", len(cipher_suites)) + cipher_suites
        compression = b"\x01\x00"

        if extensions:
            ext_block = struct.pack(">H", len(extensions)) + extensions
        else:
            ext_block = b""

        body = (
            tls_version
            + random_bytes
            + session_id
            + cipher_block
            + compression
            + ext_block
        )

        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record_version = b"\x03\x01" if tls_version == b"\x03\x00" else tls_version
        record = (
            b"\x16"
            + record_version
            + struct.pack(">H", len(handshake))
            + handshake
        )
        return record

    def _raw_connect_and_send(
        self,
        host_ip: str,
        client_hello: bytes,
    ) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connection.timeout)
            sock.connect((host_ip, self.connection.port))
            sock.sendall(client_hello)
            time.sleep(0.3)
            response = self._recv_all(sock, 32768)
            sock.close()
            return response if response else None
        except (socket.timeout, OSError):
            return None

    def _response_has_server_hello(self, response: bytes) -> bool:
        for ct, ver, payload in self._parse_tls_records(response):
            if ct == CT_HANDSHAKE and len(payload) > 0 and payload[0] == HT_SERVER_HELLO:
                return True
        return False

    def _response_alert_code(self, response: bytes) -> Optional[int]:
        for ct, ver, payload in self._parse_tls_records(response):
            if ct == CT_ALERT and len(payload) >= 2:
                return payload[1]
        return None

    # ── Highest version detection ─────────────────────────────────────────────

    def _detect_highest_version(self) -> Optional[str]:
        host_ip = self._resolve_host()
        if not host_ip:
            return None

        for ver_name in reversed(VERSION_ORDER):
            if ver_name == "TLSv1.3":
                found = self._probe_tls13(host_ip)
            else:
                ver_bytes = VERSION_BYTES.get(ver_name)
                if not ver_bytes:
                    continue
                found = self._probe_version_raw(host_ip, ver_bytes, include_scsv=False)
            if found:
                return ver_name
        return None

    def _probe_tls13(self, host_ip: str) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            sock = socket.create_connection((host_ip, self.connection.port), timeout=self.connection.timeout)
            tls = ctx.wrap_socket(sock, server_hostname=self.connection.sni)
            ver = tls.version()
            tls.close()
            sock.close()
            return ver == "TLSv1.3"
        except Exception:
            return False

    def _probe_version_raw(self, host_ip: str, ver_bytes: bytes, include_scsv: bool) -> bool:
        cipher_suites = (
            b"\xc0\x2f"
            b"\xc0\x2b"
            b"\x00\x9c"
            b"\x00\x2f"
            b"\x00\x35"
            b"\x00\x0a"
        )
        if include_scsv:
            cipher_suites += TLS_FALLBACK_SCSV

        ch = self._build_client_hello(tls_version=ver_bytes, cipher_suites=cipher_suites)
        response = self._raw_connect_and_send(host_ip, ch)
        if not response:
            return False
        return self._response_has_server_hello(response)

    # ── TLS_FALLBACK_SCSV check ───────────────────────────────────────────────

    def _check_fallback_scsv(self, highest: Optional[str]) -> Dict[str, Any]:
        """Send a downgraded ClientHello with TLS_FALLBACK_SCSV included.

        RFC 7507 mandates that if the server supports a higher version than the
        one offered in the ClientHello, and the ClientHello contains FALLBACK_SCSV,
        the server MUST respond with an inappropriate_fallback alert (86).

        A server that instead responds with ServerHello is not enforcing the SCSV
        and is therefore susceptible to version downgrade attacks.
        """
        host_ip = self._resolve_host()
        if not host_ip:
            return {"vulnerable": False, "certainty": "unknown", "detail": "DNS resolution failed"}

        if not highest:
            return {
                "vulnerable": False,
                "certainty": "unknown",
                "detail": "Could not determine highest supported version; skipping SCSV check",
            }

        highest_idx = VERSION_ORDER.index(highest) if highest in VERSION_ORDER else -1

        if highest_idx <= 0:
            return {
                "vulnerable": False,
                "certainty": "safe",
                "detail": (
                    f"Server only supports {highest}; no lower version to downgrade to. "
                    "FALLBACK_SCSV enforcement is moot."
                ),
            }

        downgrade_name = VERSION_ORDER[highest_idx - 1]

        if downgrade_name == "TLSv1.3":
            return {
                "vulnerable": False,
                "certainty": "safe",
                "detail": "Downgrade target resolved to TLS 1.3; FALLBACK_SCSV not applicable.",
            }

        downgrade_bytes = VERSION_BYTES.get(downgrade_name)
        if not downgrade_bytes:
            return {
                "vulnerable": False,
                "certainty": "unknown",
                "detail": f"No raw bytes mapping for downgrade version {downgrade_name}",
            }

        cipher_suites = (
            b"\xc0\x2f"
            b"\xc0\x2b"
            b"\x00\x9c"
            b"\x00\x2f"
            b"\x00\x35"
            b"\x00\x0a"
            + TLS_FALLBACK_SCSV
        )

        ch = self._build_client_hello(tls_version=downgrade_bytes, cipher_suites=cipher_suites)
        response = self._raw_connect_and_send(host_ip, ch)

        if not response:
            return {
                "vulnerable": False,
                "certainty": "unknown",
                "detail": "No response received for FALLBACK_SCSV probe",
            }

        alert_code = self._response_alert_code(response)

        if alert_code == TLSAlert.INAPPROPRIATE_FALLBACK:
            return {
                "vulnerable": False,
                "certainty": "safe",
                "detail": (
                    f"Server correctly rejected the downgraded ClientHello "
                    f"({highest} → {downgrade_name}) with inappropriate_fallback alert (86). "
                    "RFC 7507 / TLS_FALLBACK_SCSV is properly enforced."
                ),
                "highest_version": highest,
                "downgrade_attempted": downgrade_name,
            }

        if self._response_has_server_hello(response):
            return {
                "vulnerable": True,
                "certainty": "confirmed",
                "detail": (
                    f"Server accepted a downgraded ClientHello ({highest} → {downgrade_name}) "
                    "that explicitly included TLS_FALLBACK_SCSV (0x5600). "
                    "Per RFC 7507, the server MUST respond with inappropriate_fallback (86) "
                    "but instead completed the handshake. An active MITM can exploit this "
                    "to force protocol downgrade."
                ),
                "highest_version": highest,
                "downgrade_accepted": downgrade_name,
            }

        if alert_code == TLSAlert.HANDSHAKE_FAILURE:
            return {
                "vulnerable": False,
                "certainty": "likely",
                "detail": (
                    f"Server rejected the downgraded ClientHello ({highest} → {downgrade_name}) "
                    "with a generic handshake_failure alert (40) rather than "
                    "inappropriate_fallback (86). The downgrade was blocked, but the server "
                    "may not implement RFC 7507 strictly."
                ),
                "highest_version": highest,
                "downgrade_attempted": downgrade_name,
            }

        if alert_code == TLSAlert.PROTOCOL_VERSION:
            return {
                "vulnerable": False,
                "certainty": "safe",
                "detail": (
                    f"Server rejected the downgraded ClientHello ({highest} → {downgrade_name}) "
                    "with a protocol_version alert (70). "
                    "The downgrade was blocked; the version is not supported at all."
                ),
                "highest_version": highest,
                "downgrade_attempted": downgrade_name,
            }

        return {
            "vulnerable": False,
            "certainty": "unknown",
            "detail": (
                f"Unexpected server response to FALLBACK_SCSV probe "
                f"(alert={alert_code}). Could not determine SCSV enforcement status."
            ),
            "highest_version": highest,
            "downgrade_attempted": downgrade_name,
        }

    # ── Per-version acceptance check ──────────────────────────────────────────

    def _check_version_accepted(self, ver_name: str) -> Dict[str, Any]:
        """Probe whether the server accepts a plain ClientHello at the given version.

        Unlike the SCSV check, this does NOT include TLS_FALLBACK_SCSV — we want
        to know whether the server genuinely supports the protocol version at all.
        """
        host_ip = self._resolve_host()
        if not host_ip:
            return {"vulnerable": False, "certainty": "unknown", "detail": "DNS resolution failed"}

        ver_bytes = VERSION_BYTES.get(ver_name)
        if not ver_bytes:
            return {
                "vulnerable": False,
                "certainty": "unknown",
                "detail": f"No byte mapping for version {ver_name}",
            }

        cipher_suites = (
            b"\xc0\x2f"
            b"\xc0\x2b"
            b"\x00\x9c"
            b"\x00\x2f"
            b"\x00\x35"
            b"\x00\x0a"
        )

        ch = self._build_client_hello(tls_version=ver_bytes, cipher_suites=cipher_suites)
        response = self._raw_connect_and_send(host_ip, ch)

        if not response:
            return {
                "vulnerable": False,
                "certainty": "safe",
                "detail": f"{ver_name} — no response (connection refused or version not supported)",
            }

        alert_code = self._response_alert_code(response)

        if self._response_has_server_hello(response):
            vuln_info = {
                "SSLv3":   ("confirmed", "SSLv3 is accepted. Immediately exploitable via POODLE."),
                "TLSv1.0": ("probable",  "TLS 1.0 is accepted. Vulnerable to BEAST (CBC); deprecated by RFC 8996."),
                "TLSv1.1": ("potential", "TLS 1.1 is accepted. Deprecated by RFC 8996; no known critical exploits, but should be disabled."),
            }
            certainty, detail = vuln_info.get(ver_name, ("potential", f"{ver_name} is accepted by the server."))
            return {
                "vulnerable": True,
                "certainty": certainty,
                "detail": detail,
                "version_accepted": ver_name,
            }

        if alert_code in (TLSAlert.PROTOCOL_VERSION, TLSAlert.HANDSHAKE_FAILURE):
            return {
                "vulnerable": False,
                "certainty": "safe",
                "detail": f"{ver_name} rejected by server (alert {int(alert_code)}).",
            }

        return {
            "vulnerable": False,
            "certainty": "unknown",
            "detail": f"{ver_name} — ambiguous response (alert={alert_code}); version likely not supported.",
        }

    # ── Assessment ────────────────────────────────────────────────────────────

    def _assess(self, results: Dict[str, Any]) -> Dict[str, Any]:
        confirmed_count = 0
        probable_count = 0
        potential_count = 0
        unknown_count = 0
        safe_count = 0

        issues: List[str] = []
        warnings: List[str] = []
        notes: List[str] = []

        for vuln_id, result in results.items():
            certainty = result.get("certainty", "unknown")
            vuln_info = VULNERABILITY_DB.get(vuln_id, {})
            cve = vuln_info.get("cve", vuln_id)
            cvss = vuln_info.get("cvss", 0)
            name = vuln_info.get("name", vuln_id)
            detail = result.get("detail", "")

            if certainty == "confirmed":
                confirmed_count += 1
                issues.append(f"{name} ({cve}, CVSS {cvss}) — {detail}")
            elif certainty == "probable":
                probable_count += 1
                issues.append(f"{name} ({cve}, CVSS {cvss}) — {detail}")
            elif certainty == "potential" or result.get("vulnerable") is True:
                potential_count += 1
                warnings.append(f"{name} ({cve}, CVSS {cvss}) — {detail}")
            elif certainty in ("safe", "likely"):
                safe_count += 1
            else:
                unknown_count += 1
                warnings.append(f"{name} ({cve}, CVSS {cvss}) — verification inconclusive: {detail}")

        total_checked = len(results)
        notes.append(
            f"{total_checked} checks: {confirmed_count} confirmed, {probable_count} probable, "
            f"{potential_count} potential, {unknown_count} unknown, {safe_count} safe"
        )

        if confirmed_count + probable_count == 0 and potential_count == 0 and unknown_count == 0:
            grade = "A"
        elif confirmed_count + probable_count == 0 and (potential_count + unknown_count) <= 2:
            grade = "B"
        elif confirmed_count + probable_count <= 2:
            grade = "C"
        elif confirmed_count + probable_count <= 4:
            grade = "D"
        else:
            grade = "F"

        return {
            "grade": grade,
            "confirmed_count": confirmed_count,
            "probable_count": probable_count,
            "potential_count": potential_count,
            "unknown_count": unknown_count,
            "safe_count": safe_count,
            "total_checked": total_checked,
            "issues": issues,
            "warnings": warnings,
            "notes": notes,
        }

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_vuln_result(self, name: str, result: Dict[str, Any]) -> None:
        certainty = result.get("certainty", "unknown")
        detail = result.get("detail", "")

        if certainty == "confirmed":
            self._fail(name, f"VULNERABLE [confirmed] — {detail}")
        elif certainty == "probable":
            self._fail(name, f"PROBABLE VULNERABILITY — {detail}")
        elif certainty == "potential":
            self._warn(name, f"POTENTIAL / RISK INDICATOR — {detail}")
        elif certainty == "unknown":
            self._info(name, f"UNKNOWN / NOT VERIFIED — {detail}")
        else:
            self._pass(name, f"Not vulnerable [{certainty}] — {detail}")

    def _print_assessment(self, assessment: Dict[str, Any]) -> None:
        grade = assessment.get("grade", "?")
        if grade == "A":
            self._pass("Overall Grade", grade)
        elif grade == "B":
            self._warn("Overall Grade", grade)
        else:
            self._fail("Overall Grade", grade)

        for issue in assessment.get("issues", []):
            self._fail("Vulnerability", issue)
        for warning in assessment.get("warnings", []):
            self._warn("Potential Vulnerability", warning)
        for note in assessment.get("notes", []):
            self._info("Note", note)