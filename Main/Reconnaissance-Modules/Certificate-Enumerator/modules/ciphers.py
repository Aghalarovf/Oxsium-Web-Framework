import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from .base import BaseModule
from core.network import TLS_VERSION_MAP, ConnectionResult


TLS13_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
]

ECDHE_AEAD_CIPHERS = [
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
]

ECDHE_CBC_CIPHERS = [
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
]

DHE_AEAD_CIPHERS = [
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
]

DHE_CBC_CIPHERS = [
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
]

RSA_GCM_CIPHERS = [
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
]

RSA_CBC_CIPHERS = [
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
]

STATIC_ECDH_CIPHERS = [
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
]

WEAK_CIPHERS = [
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_NULL_WITH_NULL_NULL",
    "SSL_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_WITH_NULL_SHA",
    "SSL_RSA_WITH_NULL_MD5",
]

ALL_CIPHERS = (
    TLS13_CIPHERS
    + ECDHE_AEAD_CIPHERS
    + ECDHE_CBC_CIPHERS
    + DHE_AEAD_CIPHERS
    + DHE_CBC_CIPHERS
    + RSA_GCM_CIPHERS
    + RSA_CBC_CIPHERS
    + STATIC_ECDH_CIPHERS
    + WEAK_CIPHERS
)

PFS_KEY_EXCHANGE = {"ECDHE", "DHE", "DHE_DSS", "DHE_RSA", "ECDHE_ECDSA", "ECDHE_RSA"}

AEAD_ENCRYPTION = {"GCM", "CCM", "CCM_8", "CHACHA20_POLY1305"}

_ENCRYPTION_STRENGTH: Dict[str, str] = {
    "AES_256_GCM":        "strong",
    "AES_128_GCM":        "strong",
    "AES_256_CCM_8":      "strong",
    "AES_256_CCM":        "strong",
    "AES_128_CCM_8":      "strong",
    "AES_128_CCM":        "strong",
    "CHACHA20_POLY1305":  "strong",
    "AES_256_CBC":        "moderate",
    "AES_128_CBC":        "moderate",
    "CAMELLIA_256_CBC":   "moderate",
    "CAMELLIA_128_CBC":   "moderate",
    "CAMELLIA_256":       "strong",
    "CAMELLIA_128":       "strong",
    "AES_256":            "strong",
    "AES_128":            "strong",
    "CHACHA20":           "strong",
    "3DES_EDE":           "weak",
    "3DES":               "weak",
    "DES":                "weak",
    "RC4":                "weak",
    "NULL":               "none",
}

_ISSUE_WEIGHT = 10
_WARNING_WEIGHT = 1
_GRADE_THRESHOLDS = [
    (0,  0,  "A"),
    (0,  5,  "B"),
    (0,  99, "B"),
    (1,  0,  "C"),
    (99, 0,  "C"),
]

_KEY_BITS_RE = re.compile(r"(?<!\d)(40|56|112|128|168|256)(?!\d)")


class CipherModule(BaseModule):
    name = "ciphers"
    description = "Cipher suite inventory, classification and strength analysis"

    def run(self) -> Dict[str, Any]:
        self.logger.section("Cipher Module")

        self.logger.subsection("Cipher Suite Inventory")
        cipher_results = self._probe_all_ciphers()
        self._print_cipher_matrix(cipher_results)

        self.logger.subsection("Cipher Classification")
        classification = self._classify_ciphers(cipher_results)
        self._print_classification(classification)

        self.logger.subsection("Key-Exchange & PFS Analysis")
        pfs_data = self._analyze_pfs(classification)
        self._print_pfs_analysis(pfs_data)

        self.logger.subsection("Cipher Assessment")
        assessment = self._assess(cipher_results, classification, pfs_data)
        self._print_assessment(assessment)

        return {
            "ciphers": cipher_results,
            "classification": classification,
            "pfs_analysis": pfs_data,
            "assessment": assessment,
        }

    def _probe_all_ciphers(self) -> List[Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=16) as pool:
            future_to_name = {
                pool.submit(self._probe_single_cipher, name): name
                for name in ALL_CIPHERS
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                results[name] = future.result()
        return [results[name] for name in ALL_CIPHERS]

    def _probe_single_cipher(self, cipher_name: str) -> Dict[str, Any]:
        result = self.connection.probe_cipher(cipher_name)
        supported = result.success

        entry: Dict[str, Any] = {
            "name": cipher_name,
            "supported": supported,
            "error": result.error if not supported else None,
        }

        if supported:
            entry["protocol"] = result.version
            cipher_tuple = result.cipher
            if cipher_tuple:
                entry["openssl_name"] = cipher_tuple[0]
                entry["protocol_version"] = cipher_tuple[1]
                entry["bits"] = cipher_tuple[2]
            entry["handshake_time_ms"] = result.handshake_time_ms

        return entry

    def _classify_ciphers(
        self, cipher_results: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        supported = [c for c in cipher_results if c["supported"]]

        categories: Dict[str, List[Dict[str, Any]]] = {
            "tls13":       [],
            "ecdhe_aead":  [],
            "ecdhe_cbc":   [],
            "dhe_aead":    [],
            "dhe_cbc":     [],
            "rsa_aead":    [],
            "rsa_cbc":     [],
            "static_ecdh": [],
            "weak":        [],
        }

        for cipher in supported:
            name = cipher["name"]
            attrs = self._classify_single(name)
            cat = attrs.get("category", "weak")
            bucket = cat if cat in categories else "weak"
            categories[bucket].append({**cipher, **attrs})

        return categories

    def _classify_single(self, cipher_name: str) -> Dict[str, Any]:
        upper = cipher_name.upper()

        kex = self._extract_key_exchange(upper)
        enc = self._extract_encryption(upper)
        mac = self._extract_mac(upper)
        pfs = kex in PFS_KEY_EXCHANGE or kex == "TLSv1.3"
        aead = any(e in upper for e in AEAD_ENCRYPTION)
        strength = self._grade_encryption(enc)
        category = self._assign_category(kex, enc, aead, cipher_name)
        bits = self._extract_bits(upper, enc)

        return {
            "key_exchange": kex,
            "encryption": enc,
            "mac": mac,
            "bits": bits,
            "pfs": pfs,
            "aead": aead,
            "strength": strength,
            "category": category,
        }

    def _analyze_pfs(
        self, classification: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        all_supported = [c for cat in classification.values() for c in cat]
        pfs_ciphers = [c for c in all_supported if c.get("pfs")]
        non_pfs_ciphers = [c for c in all_supported if not c.get("pfs")]

        return {
            "pfs_supported": len(pfs_ciphers) > 0,
            "pfs_count": len(pfs_ciphers),
            "non_pfs_count": len(non_pfs_ciphers),
            "pfs_cipher_names": [c["name"] for c in pfs_ciphers],
            "non_pfs_cipher_names": [c["name"] for c in non_pfs_ciphers],
        }

    def _assess(
        self,
        cipher_results: List[Dict[str, Any]],
        classification: Dict[str, List[Dict[str, Any]]],
        pfs_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        issues: List[str] = []
        warnings: List[str] = []
        notes: List[str] = []

        supported = [c for c in cipher_results if c["supported"]]

        for w in classification.get("weak", []):
            name = w["name"]
            enc = w.get("encryption", "UNKNOWN")
            upper = name.upper()
            if enc == "NULL":
                issues.append(f"NULL encryption cipher supported: {name}")
            elif "EXPORT" in upper:
                issues.append(f"EXPORT-grade cipher supported: {name}")
            elif "RC4" in upper:
                issues.append(f"RC4 cipher supported (broken): {name}")
            elif "DES" in upper and "3DES" not in upper:
                issues.append(f"Single-DES cipher supported: {name}")
            elif "3DES" in upper:
                warnings.append(f"3DES cipher supported (deprecated): {name}")
            else:
                warnings.append(f"Weak cipher supported: {name}")

        if not pfs_data.get("pfs_supported"):
            issues.append("No cipher with Perfect Forward Secrecy (PFS) supported")
        elif pfs_data.get("non_pfs_count", 0) > 0:
            non_pfs = pfs_data["non_pfs_cipher_names"]
            suffix = "..." if len(non_pfs) > 5 else ""
            warnings.append(
                f"{len(non_pfs)} cipher(s) without PFS supported: "
                f"{', '.join(non_pfs[:5])}{suffix}"
            )

        if len(classification.get("tls13", [])) == 0:
            warnings.append("No TLS 1.3 cipher suites supported")

        aead_available = any(
            c.get("aead") for cat in classification.values() for c in cat
        )
        if not aead_available:
            warnings.append("No AEAD cipher suites available")

        best_strength = self._best_available_strength(classification)
        if best_strength == "weak":
            issues.append("Only weak encryption ciphers are supported")
        elif best_strength == "moderate":
            warnings.append("Best available encryption is moderate (CBC mode)")

        cbc_count = sum(
            len(classification.get(k, []))
            for k in ("ecdhe_cbc", "dhe_cbc", "rsa_cbc")
        )
        if cbc_count > 0:
            notes.append(
                f"{cbc_count} CBC-mode cipher(s) supported (Lucky13 variants may apply)"
            )

        total = len(supported)
        notes.append(f"{total} cipher(s) supported in total")

        if total == 0:
            notes.append(
                "No ciphers matched the probe list — the server may use cipher suites "
                "that the local OpenSSL does not support (e.g. legacy RC4 or 3DES suites "
                "disabled by default). Results may be incomplete."
            )

        grade = self._calculate_grade(issues, warnings, classification)

        return {
            "grade": grade,
            "total_supported": total,
            "issues": issues,
            "warnings": warnings,
            "notes": notes,
        }

    def _extract_key_exchange(self, upper: str) -> str:
        if upper.startswith("TLS_AES_") or upper.startswith("TLS_CHACHA20"):
            return "TLSv1.3"
        for token, label in (
            ("ECDHE_ECDSA", "ECDHE_ECDSA"),
            ("ECDHE_RSA",   "ECDHE_RSA"),
            ("ECDHE",       "ECDHE"),
            ("DHE_DSS",     "DHE_DSS"),
            ("DHE_RSA",     "DHE_RSA"),
            ("DHE",         "DHE"),
            ("ECDH_ECDSA",  "ECDH_ECDSA"),
            ("ECDH_RSA",    "ECDH_RSA"),
            ("ECDH",        "ECDH"),
            ("DH_DSS",      "DH_DSS"),
            ("DH_RSA",      "DH_RSA"),
            ("RSA",         "RSA"),
            ("PSK",         "PSK"),
            ("SRP",         "SRP"),
        ):
            if token in upper:
                return label
        if upper.startswith(("SSL", "TLS")):
            return "RSA"
        return "UNKNOWN"

    def _extract_encryption(self, upper: str) -> str:
        for key in [
            "AES_256_GCM", "AES_128_GCM",
            "AES_256_CCM_8", "AES_256_CCM", "AES_128_CCM_8", "AES_128_CCM",
            "CHACHA20_POLY1305",
            "AES_256_CBC", "AES_128_CBC",
            "CAMELLIA_256_CBC", "CAMELLIA_128_CBC",
            "DES40", "DES_CBC", "DES",
            "3DES_EDE_CBC", "3DES_EDE", "3DES",
            "RC4_128", "RC4_40", "RC4",
            "IDEA_CBC", "IDEA",
            "SEED_CBC", "SEED",
            "NULL",
        ]:
            if key in upper:
                return key
        return "UNKNOWN"

    def _extract_mac(self, upper: str) -> str:
        if any(e in upper for e in AEAD_ENCRYPTION):
            return "AEAD"
        if "SHA384" in upper:
            return "SHA384"
        if "SHA256" in upper:
            return "SHA256"
        if "SHA" in upper:
            return "SHA"
        if "MD5" in upper:
            return "MD5"
        return "UNKNOWN"

    def _grade_encryption(self, enc: str) -> str:
        if enc in _ENCRYPTION_STRENGTH:
            return _ENCRYPTION_STRENGTH[enc]
        if "AES" in enc or "CHACHA20" in enc or "CAMELLIA" in enc:
            return "strong"
        return "unknown"

    def _assign_category(self, kex: str, enc: str, aead: bool, cipher_name: str = "") -> str:
        upper = cipher_name.upper()
        if enc == "NULL" or "EXPORT" in upper or enc in ("RC4", "RC4_128", "RC4_40") or enc in ("DES", "DES_CBC", "DES40"):
            return "weak"
        if kex == "TLSv1.3":
            return "tls13"
        if kex in {"ECDHE_ECDSA", "ECDHE_RSA", "ECDHE"}:
            return "ecdhe_aead" if aead else "ecdhe_cbc"
        if kex in {"DHE_RSA", "DHE_DSS", "DHE"}:
            return "dhe_aead" if aead else "dhe_cbc"
        if kex == "RSA":
            return "rsa_aead" if aead else "rsa_cbc"
        if kex in {"ECDH_ECDSA", "ECDH_RSA", "ECDH"}:
            return "static_ecdh"
        return "weak"

    def _extract_bits(self, upper: str, enc: str) -> int:
        if enc == "NULL":
            return 0
        if "3DES" in enc:
            return 112
        if enc in ("DES", "DES_CBC", "DES40"):
            return 40 if "40" in enc else 56
        if "RC4" in enc:
            return 40 if "40" in upper else 128
        match = _KEY_BITS_RE.search(enc)
        if match:
            raw = int(match.group(1))
            return 112 if raw == 168 else raw
        match = _KEY_BITS_RE.search(upper)
        if match:
            raw = int(match.group(1))
            return 112 if raw == 168 else raw
        return 0

    def _best_available_strength(
        self, classification: Dict[str, List[Dict[str, Any]]]
    ) -> str:
        order = ["none", "weak", "moderate", "strong"]
        best = "none"
        for cat_list in classification.values():
            for c in cat_list:
                s = c.get("strength", "none")
                if s in order and order.index(s) > order.index(best):
                    best = s
        return best

    def _calculate_grade(
        self,
        issues: List[str],
        warnings: List[str],
        classification: Dict[str, List[Dict[str, Any]]],
    ) -> str:
        all_ciphers = [c for cat in classification.values() for c in cat]
        if not all_ciphers:
            return "F"

        if any(c.get("encryption") == "NULL" for c in all_ciphers):
            return "F"
        if any("EXPORT" in c["name"].upper() for c in all_ciphers):
            return "F"
        if not any(c.get("pfs") for c in all_ciphers):
            return "D"

        if not issues and not warnings:
            return "A"
        if not issues and len(warnings) <= 2:
            return "B"
        if not issues:
            return "B"
        return "C"

    def _print_cipher_matrix(self, results: List[Dict[str, Any]]) -> None:
        for entry in results:
            name = entry["name"]
            if not entry["supported"]:
                self._skip(name, "Not supported")
                continue
            bits = entry.get("bits", "?")
            proto = entry.get("protocol_version", entry.get("protocol", "?"))
            hs = entry.get("handshake_time_ms")
            hs_str = f"  ({hs} ms)" if hs is not None else ""
            self._pass(name, f"Supported{hs_str}  [{proto} / {bits} bits]")

    def _print_classification(
        self, classification: Dict[str, List[Dict[str, Any]]]
    ) -> None:
        section_labels = {
            "tls13":       ("PASS", "TLS 1.3"),
            "ecdhe_aead":  ("PASS", "ECDHE + AEAD"),
            "ecdhe_cbc":   ("WARN", "ECDHE + CBC"),
            "dhe_aead":    ("PASS", "DHE + AEAD"),
            "dhe_cbc":     ("WARN", "DHE + CBC"),
            "rsa_aead":    ("WARN", "RSA KX + AEAD (no PFS)"),
            "rsa_cbc":     ("WARN", "RSA KX + CBC (no PFS)"),
            "static_ecdh": ("WARN", "Static ECDH (no PFS)"),
            "weak":        ("FAIL", "Weak / Broken"),
        }

        for cat_key, (status, label) in section_labels.items():
            ciphers = classification.get(cat_key, [])
            if not ciphers:
                continue
            names = [c["name"] for c in ciphers]
            summary = f"{len(ciphers)} suite(s): {', '.join(names)}"
            if status == "PASS":
                self._pass(label, summary)
            elif status == "WARN":
                self._warn(label, summary)
            else:
                self._fail(label, summary)
            for c in ciphers:
                detail = (
                    f"  \u251c {c['name']}"
                    f"  [{c.get('key_exchange', '?')} / "
                    f"{c.get('encryption', '?')} / "
                    f"{c.get('mac', '?')} / "
                    f"{c.get('bits', '?')}b]"
                )
                self._info("", detail)

    def _print_pfs_analysis(self, pfs_data: Dict[str, Any]) -> None:
        if pfs_data["pfs_supported"]:
            self._pass(
                "Perfect Forward Secrecy",
                f"Available ({pfs_data['pfs_count']} cipher(s))",
            )
        else:
            self._fail(
                "Perfect Forward Secrecy",
                "Not supported — all ciphers lack PFS",
            )
        if pfs_data["non_pfs_count"]:
            self._warn(
                "Non-PFS Ciphers",
                f"{pfs_data['non_pfs_count']} cipher(s) without PFS enabled",
            )

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

    def _pick_best_supported(
        self, cipher_results: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        for c in cipher_results:
            if c["supported"]:
                return c
        return None