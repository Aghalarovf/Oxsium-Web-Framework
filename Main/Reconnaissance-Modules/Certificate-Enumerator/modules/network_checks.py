"""DNS TLS checks module: CAA, DANE/TLSA, MTA-STS"""

import hashlib
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

from .base import BaseModule


# Optional dnspython
try:
    import dns.resolver
    import dns.exception
    import dns.name
    import dns.rdatatype
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


# TLSA usage labels
TLSA_USAGE_LABEL = {
    0: "CA constraint",
    1: "Service cert constraint",
    2: "Trust anchor assertion",
    3: "Domain-issued certificate",
}

# TLSA selector labels
TLSA_SELECTOR_LABEL = {
    0: "Full certificate",
    1: "SubjectPublicKeyInfo",
}

# TLSA matching type labels
TLSA_MATCHING_LABEL = {
    0: "Exact match",
    1: "SHA-256 hash",
    2: "SHA-512 hash",
}


class NetworkModule(BaseModule):
    name = "network_checks"
    description = "DNS TLS checks (CAA, DANE/TLSA, MTA-STS)"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_target_domain(self) -> Optional[str]:
        """Extract the target domain from the connection object."""
        host = getattr(self.connection, "host", None)
        if not host:
            host = getattr(self.connection, "hostname", None)
        if not host:
            host = getattr(self.connection, "target", None)
        if host:
            if ":" in host:
                host = host.split(":")[0]
            return host
        return None

    def _dns_query(self, qname: str, rtype: str) -> List:
        """Generic DNS lookup returning a list of rdata objects."""
        resolver = dns.resolver.Resolver()
        try:
            answers = resolver.resolve(qname, rtype, raise_on_no_answer=False)
            return list(answers)
        except (dns.exception.DNSException, Exception):
            return []

    def _get_peer_cert_der(self) -> Optional[bytes]:
        """Attempt a TLS handshake and return the leaf certificate DER."""
        try:
            tls_result = self.connection.connect(alpn_protocols=["h2", "http/1.1"])
            if tls_result.success and tls_result.peer_cert_chain:
                return tls_result.peer_cert_chain[0]
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # CAA
    # ------------------------------------------------------------------

    def _check_caa(self, domain: str) -> Dict[str, Any]:
        records_raw = self._dns_query(domain, "CAA")
        records = []
        for rdata in records_raw:
            records.append({
                "tag": rdata.tag,
                "value": rdata.value,
                "flags": rdata.flags,
                "critical": bool(rdata.flags & 1),
            })

        summary = ""
        if not records:
            summary = "No CAA records found (any CA may issue certificates)"
        else:
            issue = [r["value"] for r in records if r["tag"] == "issue"]
            wild = [r["value"] for r in records if r["tag"] == "issuewild"]
            parts = []
            if issue:
                parts.append(f"Restricted to: {', '.join(issue)}")
            if wild:
                parts.append(f"Wildcards: {', '.join(wild)}")
            summary = " | ".join(parts) if parts else "CAA records exist (uncommon tags)"

        return {
            "records": records,
            "summary": summary,
        }

    def _print_caa(self, caa: Dict[str, Any]) -> None:
        records = caa.get("records", [])
        if not records:
            self._warn("CAA Records", "None found")
            self._info("  Note", "Any CA may issue certificates for this domain")
            return
        self._pass("CAA Records", f"{len(records)} record(s)")
        for r in records:
            critical = " (critical)" if r["critical"] else ""
            self._info(f"  {r['tag']}{critical}", r["value"])

    # ------------------------------------------------------------------
    # DANE / TLSA
    # ------------------------------------------------------------------

    def _check_dane(self, domain: str, peer_der: Optional[bytes]) -> Dict[str, Any]:
        services = [
            ("_443._tcp",  443,  "HTTPS"),
            ("_25._tcp",   25,   "SMTP"),
            ("_143._tcp",  143,  "IMAP"),
            ("_993._tcp",  993,  "IMAPS"),
            ("_110._tcp",  110,  "POP3"),
            ("_995._tcp",  995,  "POP3S"),
        ]

        result: Dict[str, Any] = {"services": {}, "validation": {}}

        for prefix, port, label in services:
            qname = f"{prefix}.{domain}"
            answers = self._dns_query(qname, "TLSA")
            if not answers:
                continue

            parsed = []
            for rdata in answers:
                entry = {
                    "usage": rdata.usage,
                    "usage_label": TLSA_USAGE_LABEL.get(rdata.usage, f"Unknown ({rdata.usage})"),
                    "selector": rdata.selector,
                    "selector_label": TLSA_SELECTOR_LABEL.get(rdata.selector, f"Unknown ({rdata.selector})"),
                    "matching_type": rdata.matching_type,
                    "matching_label": TLSA_MATCHING_LABEL.get(rdata.matching_type, f"Unknown ({rdata.matching_type})"),
                    "cert_data_hex": rdata.cert.hex(),
                    "cert_data_truncated": rdata.cert.hex()[:64] + "..." if len(rdata.cert) > 32 else rdata.cert.hex(),
                }
                parsed.append(entry)

            svc_block = {
                "port": port,
                "qname": qname,
                "records": parsed,
                "record_count": len(parsed),
            }
            result["services"][label] = svc_block

            # DANE validation against the leaf certificate (HTTPS only)
            if peer_der is not None and label == "HTTPS":
                result["validation"][label] = self._validate_dane(parsed, peer_der)

        return result

    def _validate_dane(self, tlsa_records: List[Dict], peer_der: bytes) -> Dict[str, Any]:
        validation: Dict[str, Any] = {
            "matched": False,
            "checked": 0,
            "details": [],
        }

        try:
            cert = x509.load_der_x509_certificate(peer_der)
        except Exception as exc:
            validation["details"].append(f"Could not parse peer certificate: {exc}")
            return validation

        for rec in tlsa_records:
            validation["checked"] += 1
            usage = rec["usage"]
            selector = rec["selector"]
            match_type = rec["matching_type"]
            expected = bytes.fromhex(rec["cert_data_hex"])

            # Build the raw bytes to compare
            if selector == 0:
                raw = peer_der
            elif selector == 1:
                pub = cert.public_key()
                raw = pub.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            else:
                validation["details"].append(
                    f"  Selector {selector} not supported (skipped)"
                )
                continue

            # Apply hash if needed
            if match_type == 0:
                digest = raw
            elif match_type == 1:
                digest = hashlib.sha256(raw).digest()
            elif match_type == 2:
                digest = hashlib.sha512(raw).digest()
            else:
                validation["details"].append(
                    f"  Matching type {match_type} not supported (skipped)"
                )
                continue

            if digest == expected:
                validation["matched"] = True
                validation["details"].append(
                    f"  ✓ {rec['usage_label']} / {rec['selector_label']} / "
                    f"{rec['matching_label']} — MATCHES certificate"
                )
            else:
                validation["details"].append(
                    f"  ✗ {rec['usage_label']} / {rec['selector_label']} / "
                    f"{rec['matching_label']} — does NOT match"
                )

        return validation

    def _print_dane(self, dane: Dict[str, Any]) -> None:
        svcs = dane.get("services", {})
        if not svcs:
            self._warn("TLSA Records", "None found for common service ports")
            return

        for label, svc in svcs.items():
            if svc["record_count"] == 0:
                continue
            self._pass(f"TLSA {label} ({svc['qname']})", f"{svc['record_count']} record(s)")
            for rec in svc["records"]:
                self._info("  Usage", rec["usage_label"])
                self._info("  Selector", rec["selector_label"])
                self._info("  Matching", rec["matching_label"])
                self._info("  Cert Data", rec["cert_data_truncated"])

        # Validation results
        for label, val in dane.get("validation", {}).items():
            if val["checked"] == 0:
                continue
            for detail in val["details"]:
                if "MATCHES" in detail:
                    self._pass("DANE Validation", detail.strip())
                elif "does NOT match" in detail:
                    self._fail("DANE Validation", detail.strip())
                else:
                    self._info("DANE Valid.", detail.strip())

    # ------------------------------------------------------------------
    # MTA-STS
    # ------------------------------------------------------------------

    def _check_mta_sts(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "dns_record": None,
            "policy": None,
            "error": None,
        }

        # 1. DNS TXT record at _mta-sts.<domain>
        mta_domain = f"_mta-sts.{domain}"
        txt_answers = self._dns_query(mta_domain, "TXT")

        for rdata in txt_answers:
            # dnspython TXT rdata has .strings (tuple of bytes)
            txt_str = b"".join(rdata.strings).decode("utf-8", errors="replace")
            kv: Dict[str, str] = {}
            for part in txt_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    kv[k.strip()] = v.strip()

            if kv.get("v") == "STSv1" and "id" in kv:
                result["dns_record"] = {
                    "raw": txt_str,
                    "version": kv["v"],
                    "id": kv["id"],
                }
                break

        # 2. Fetch the policy over HTTPS
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            req = urllib.request.Request(
                policy_url,
                headers={"User-Agent": "TLS-Scanner/0.1"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read().decode("utf-8")
            result["policy"] = self._parse_mta_sts_policy(body)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                result["error"] = f"MTA-STS policy not found at {policy_url} (HTTP 404)"
            else:
                result["error"] = f"MTA-STS policy fetch failed: HTTP {exc.code}"
        except urllib.error.URLError as exc:
            result["error"] = f"MTA-STS policy fetch failed: {exc.reason}"
        except Exception as exc:
            result["error"] = f"MTA-STS policy fetch failed: {exc}"

        return result

    def _parse_mta_sts_policy(self, text: str) -> Dict[str, Any]:
        policy: Dict[str, Any] = {
            "raw": text,
            "version": None,
            "mode": None,
            "max_age": None,
            "mx": [],
        }
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key == "version":
                policy["version"] = value
            elif key == "mode":
                policy["mode"] = value
            elif key == "max_age":
                try:
                    policy["max_age"] = int(value)
                except ValueError:
                    pass
            elif key == "mx":
                policy["mx"].append(value)
        return policy

    def _print_mta_sts(self, mta_sts: Dict[str, Any]) -> None:
        dns_rec = mta_sts.get("dns_record")
        if dns_rec:
            self._pass("MTA-STS DNS", f"Found (id={dns_rec['id']})")
        else:
            self._warn("MTA-STS DNS", "No _mta-sts TXT record found")

        pol = mta_sts.get("policy")
        if pol:
            self._pass(
                "MTA-STS Policy",
                f"v={pol.get('version','?')}  mode={pol.get('mode','?')}  "
                f"max_age={pol.get('max_age','?')}",
            )
            if pol.get("mx"):
                for mx in pol["mx"]:
                    self._info("  MX", mx)
            else:
                self._warn("  MX", "No MX declarations in policy")
        else:
            err = mta_sts.get("error")
            if err:
                self._warn("MTA-STS Policy", err)

    # ------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------

    def _assess(self, data: Dict[str, Any]) -> Dict[str, Any]:
        issues: List[str] = []
        warnings: List[str] = []

        # CAA
        caa = data.get("caa", {})
        if not caa.get("records"):
            warnings.append("No CAA records published (any CA may issue certificates)")

        # DANE / TLSA
        dane = data.get("dane", {})
        has_any_tlsa = bool(dane.get("services", {}))
        if not has_any_tlsa:
            warnings.append("No TLSA (DANE) records found for any common service port")

        for label, val in dane.get("validation", {}).items():
            if val.get("checked", 0) > 0 and not val.get("matched"):
                issues.append(
                    f"DANE TLSA records for {label} do NOT match the served certificate"
                )

        # MTA-STS
        mta = data.get("mta_sts", {})
        if mta.get("dns_record") and mta.get("policy"):
            mode = mta["policy"].get("mode")
            if mode == "testing":
                warnings.append("MTA-STS is in testing mode (no enforcement)")
            elif mode == "none":
                warnings.append("MTA-STS mode is 'none' (no enforcement)")
        elif mta.get("dns_record") and not mta.get("policy"):
            warnings.append("MTA-STS DNS record exists but policy could not be fetched")
        else:
            warnings.append("No MTA-STS DNS record found")

        # Grade
        if issues:
            grade = "F"
        elif warnings:
            grade = "B"
        else:
            grade = "A"

        return {
            "grade": grade,
            "issues": issues,
            "warnings": warnings,
        }

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
        for warn in assessment.get("warnings", []):
            self._warn("Warning", warn)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        self.logger.section("Network Checks Module (CAA / DANE / MTA-STS)")

        if not HAVE_DNSPYTHON:
            self._fail(
                "Dependency",
                "dnspython is required — install with:  pip install dnspython",
            )
            return {"error": "dnspython not available"}

        domain = self._resolve_target_domain()
        if not domain:
            self._fail("Target", "Could not resolve domain from connection")
            return {"error": "No target domain"}

        self._info("Target Domain", domain)

        # Try to grab the leaf certificate for DANE validation
        peer_der = self._get_peer_cert_der()
        if peer_der:
            self._pass("TLS Handshake", "Certificate obtained for DANE validation")
        else:
            self._warn("TLS Handshake", "No certificate available (DANE validation skipped)")

        data: Dict[str, Any] = {
            "domain": domain,
            "caa": self._check_caa(domain),
            "dane": self._check_dane(domain, peer_der),
            "mta_sts": self._check_mta_sts(domain),
        }

        self.logger.subsection("CAA Records")
        self._print_caa(data["caa"])

        self.logger.subsection("DANE / TLSA Records")
        self._print_dane(data["dane"])

        self.logger.subsection("MTA-STS")
        self._print_mta_sts(data["mta_sts"])

        self.logger.subsection("Assessment")
        assessment = self._assess(data)
        data["assessment"] = assessment
        self._print_assessment(assessment)

        return data