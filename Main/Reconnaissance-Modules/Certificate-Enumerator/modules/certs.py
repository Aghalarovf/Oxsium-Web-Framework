import datetime
import urllib.request
import urllib.error
import json
from typing import Dict, Any, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import load_der_ocsp_response, OCSPResponseStatus

from .base import BaseModule


WEAK_KEY_SIZES = {
    "RSA": 2048,
    "DSA": 2048,
    "EC":  224,
}

SIGNATURE_ALGORITHMS_WEAK = {
    "md5", "sha1",
}

CT_LOG_SEARCH_URL = "https://crt.sh/?q={}&output=json"


class CertificateModule(BaseModule):
    name = "certificates"
    description = "Certificate chain, details, SANs and CT log checks"

    def run(self) -> Dict[str, Any]:
        self.logger.section("Certificate Module")

        result = self.connection.connect(alpn_protocols=["h2", "http/1.1"])
        if not result.success:
            self._fail("Connection", result.error)
            return {"error": result.error}

        chain_ders = result.peer_cert_chain
        if not chain_ders:
            self._fail("Certificate chain", "No certificates received")
            return {"error": "No certificates received"}

        leaf_cert = x509.load_der_x509_certificate(chain_ders[0])
        original_chain_len = len(chain_ders)

        if len(chain_ders) < 2:
            fetched_issuer = self._fetch_issuer_from_aia(leaf_cert)
            if fetched_issuer is not None:
                chain_ders = list(chain_ders) + [
                    fetched_issuer.public_bytes(serialization.Encoding.DER)
                ]

        aia_fetch_index = len(chain_ders) - 1 if len(chain_ders) > original_chain_len else -1

        chain_data = []
        for idx, der in enumerate(chain_ders):
            cert = x509.load_der_x509_certificate(der)
            data = self._analyze_cert(cert, idx, len(chain_ders), aia_fetched=(idx == aia_fetch_index))
            chain_data.append(data)

        leaf_data = chain_data[0]

        self.logger.subsection("Leaf Certificate")
        self._print_leaf_summary(leaf_data)

        self.logger.subsection("Certificate Chain")
        self._print_chain_summary(chain_data)

        self.logger.subsection("Subject Alternative Names")
        self._print_sans(leaf_data.get("sans", []))

        self.logger.subsection("Certificate Transparency")
        ct_data = self._check_ct(leaf_cert)
        self._print_ct(ct_data)

        self.logger.subsection("OCSP / Revocation")
        ocsp_data = self._check_ocsp(leaf_cert, chain_ders)
        self._print_ocsp(ocsp_data)

        self.logger.subsection("Trust & Validity Assessment")
        assessment = self._assess(leaf_data, chain_data)
        self._print_assessment(assessment)

        return {
            "chain": chain_data,
            "ct": ct_data,
            "ocsp": ocsp_data,
            "assessment": assessment,
        }

    def _analyze_cert(self, cert: x509.Certificate, idx: int, chain_len: int, aia_fetched: bool = False) -> Dict[str, Any]:
        is_leaf = idx == 0
        is_root = (idx == chain_len - 1) and not aia_fetched

        subject = self._name_to_dict(cert.subject)
        issuer = self._name_to_dict(cert.issuer)

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (not_after - now).days
        expired = now > not_after
        not_yet_valid = now < not_before

        pub_key = cert.public_key()
        key_info = self._key_info(pub_key)

        sig_alg = cert.signature_hash_algorithm
        sig_alg_name = sig_alg.name if sig_alg else "unknown"

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append({"type": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    sans.append({"type": "IP", "value": str(name.value)})
                elif isinstance(name, x509.RFC822Name):
                    sans.append({"type": "Email", "value": name.value})
                elif isinstance(name, x509.UniformResourceIdentifier):
                    sans.append({"type": "URI", "value": name.value})
        except x509.ExtensionNotFound:
            pass

        fingerprints = {
            "sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
            "sha1":   cert.fingerprint(hashes.SHA1()).hex(":"),
        }

        basic_constraints = None
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc.value.ca
            basic_constraints = {"ca": bc.value.ca, "path_length": bc.value.path_length}
        except x509.ExtensionNotFound:
            pass

        key_usage = []
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            for attr in ["digital_signature", "key_encipherment", "key_agreement",
                         "key_cert_sign", "crl_sign", "content_commitment",
                         "data_encipherment", "decipher_only", "encipher_only"]:
                try:
                    if getattr(ku.value, attr, False):
                        key_usage.append(attr)
                except Exception:
                    pass
        except x509.ExtensionNotFound:
            pass

        ext_key_usage = []
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for usage in eku.value:
                ext_key_usage.append(usage.dotted_string)
        except x509.ExtensionNotFound:
            pass

        ocsp_urls = []
        ca_issuer_urls = []
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access in aia.value:
                if access.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(access.access_location.value)
                elif access.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuer_urls.append(access.access_location.value)
        except x509.ExtensionNotFound:
            pass

        sct_list = []
        try:
            sct_ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
            sct_list = [str(sct) for sct in sct_ext.value]
        except (x509.ExtensionNotFound, Exception):
            pass

        serial_hex = format(cert.serial_number, "x")

        return {
            "index": idx,
            "role": "leaf" if is_leaf else ("root" if is_root else "intermediate"),
            "subject": subject,
            "issuer": issuer,
            "serial": serial_hex,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "expired": expired,
            "not_yet_valid": not_yet_valid,
            "key": key_info,
            "signature_algorithm": sig_alg_name,
            "sans": sans,
            "fingerprints": fingerprints,
            "is_ca": is_ca,
            "basic_constraints": basic_constraints,
            "key_usage": key_usage,
            "extended_key_usage": ext_key_usage,
            "ocsp_urls": ocsp_urls,
            "ca_issuer_urls": ca_issuer_urls,
            "sct_count": len(sct_list),
            "self_signed": subject == issuer,
        }

    def _key_info(self, pub_key) -> Dict[str, Any]:
        if isinstance(pub_key, rsa.RSAPublicKey):
            return {
                "type": "RSA",
                "bits": pub_key.key_size,
                "weak": pub_key.key_size < WEAK_KEY_SIZES["RSA"],
            }
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            curve = pub_key.curve.name
            bits = pub_key.key_size
            return {
                "type": "EC",
                "curve": curve,
                "bits": bits,
                "weak": bits < WEAK_KEY_SIZES["EC"],
            }
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return {
                "type": "DSA",
                "bits": pub_key.key_size,
                "weak": pub_key.key_size < WEAK_KEY_SIZES["DSA"],
            }
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            return {"type": "Ed25519", "bits": 256, "weak": False}
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            return {"type": "Ed448", "bits": 448, "weak": False}
        else:
            return {"type": "Unknown", "bits": 0, "weak": True}

    def _name_to_dict(self, name: x509.Name) -> Dict[str, str]:
        mapping = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
            NameOID.EMAIL_ADDRESS: "emailAddress",
        }
        result = {}
        for attr in name:
            label = mapping.get(attr.oid, attr.oid.dotted_string)
            result[label] = attr.value
        return result

    def _fetch_issuer_from_aia(self, leaf: x509.Certificate) -> Optional[x509.Certificate]:
        try:
            aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            return None

        for access in aia.value:
            if access.access_method != AuthorityInformationAccessOID.CA_ISSUERS:
                continue
            url = access.access_location.value
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "TLS-Scanner/0.1"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = resp.read()
                try:
                    return x509.load_der_x509_certificate(data)
                except Exception:
                    return x509.load_pem_x509_certificate(data)
            except Exception:
                continue

        return None

    def _check_ct(self, cert: x509.Certificate) -> Dict[str, Any]:
        cn = ""
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            pass

        ct_result = {
            "queried_domain": cn,
            "source": None,
            "entries": [],
            "total_found": 0,
            "error": None,
        }

        if not cn:
            ct_result["error"] = "No common name found in certificate"
            return ct_result

        result = self._ct_query_crtsh(cn)
        if result is not None:
            ct_result.update(result)
            ct_result["source"] = "crt.sh"
            return ct_result

        result = self._ct_query_sslmate(cn)
        if result is not None:
            ct_result.update(result)
            ct_result["source"] = "sslmate"
            return ct_result

        ct_result["error"] = "All CT sources unavailable (crt.sh, SSLMate)"
        return ct_result

    def _ct_query_crtsh(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            url = CT_LOG_SEARCH_URL.format(domain)
            req = urllib.request.Request(url, headers={"User-Agent": "TLS-Scanner/0.1"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            entries = []
            seen = set()
            for entry in data[:20]:
                serial = entry.get("serial_number", "")
                if serial in seen:
                    continue
                seen.add(serial)
                entries.append({
                    "id": str(entry.get("id", "")),
                    "logged_at": entry.get("entry_timestamp"),
                    "not_before": entry.get("not_before"),
                    "not_after": entry.get("not_after"),
                    "common_name": entry.get("common_name"),
                    "issuer": entry.get("issuer_name"),
                })
            return {"entries": entries, "total_found": len(data)}
        except Exception:
            return None

    def _ct_query_sslmate(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            url = (
                f"https://api.certspotter.com/v1/issuances"
                f"?domain={domain}&include_subdomains=false"
                f"&expand=dns_names&expand=issuer"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "TLS-Scanner/0.1"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if not isinstance(data, list):
                return None
            entries = []
            for item in data[:20]:
                issuer_obj = item.get("issuer") or {}
                entries.append({
                    "id": str(item.get("id", "")),
                    "logged_at": None,
                    "not_before": item.get("not_before"),
                    "not_after": item.get("not_after"),
                    "common_name": (item.get("dns_names") or [domain])[0],
                    "issuer": issuer_obj.get("friendly_name") or issuer_obj.get("name"),
                })
            return {"entries": entries, "total_found": len(data)}
        except Exception:
            return None

    def _check_ocsp(self, leaf: x509.Certificate, chain_ders: List[bytes]) -> Dict[str, Any]:
        from cryptography.x509 import ocsp as crypto_ocsp
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.x509.ocsp import OCSPCertStatus

        result = {
            "status": "unknown",
            "responder": None,
            "this_update": None,
            "next_update": None,
            "issuer_source": None,
            "error": None,
        }

        ocsp_urls = []
        try:
            aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access in aia.value:
                if access.access_method == AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(access.access_location.value)
        except x509.ExtensionNotFound:
            result["error"] = "No OCSP URL in certificate AIA extension"
            return result

        if not ocsp_urls:
            result["error"] = "No OCSP URLs found"
            return result

        issuer_cert = None

        if len(chain_ders) >= 2:
            issuer_cert = x509.load_der_x509_certificate(chain_ders[1])
            result["issuer_source"] = "chain"
        else:
            issuer_cert = self._fetch_issuer_from_aia(leaf)
            if issuer_cert is not None:
                result["issuer_source"] = "aia_download"
            else:
                result["error"] = "Could not obtain issuer certificate (chain incomplete, AIA download failed)"
                return result

        from cryptography.hazmat.primitives.hashes import SHA1

        def _build_request(url: str, hash_alg) -> bytes:
            builder = crypto_ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(leaf, issuer_cert, hash_alg)
            req = builder.build()
            req_data = req.public_bytes(serialization.Encoding.DER)
            http_req = urllib.request.Request(
                url,
                data=req_data,
                headers={
                    "Content-Type": "application/ocsp-request",
                    "User-Agent": "TLS-Scanner/0.1",
                },
            )
            with urllib.request.urlopen(http_req, timeout=8) as resp:
                return load_der_ocsp_response(resp.read())

        def _try_url(url: str) -> Optional[Any]:
            try:
                resp = _build_request(url, SHA1())
                if resp.response_status == OCSPResponseStatus.MALFORMED_REQUEST:
                    resp = _build_request(url, SHA256())
                return resp
            except Exception:
                return None

        ocsp_resp = None
        for url in ocsp_urls:
            ocsp_resp = _try_url(url)
            if ocsp_resp is not None:
                result["responder"] = url
                break

        if ocsp_resp is None:
            result["responder"] = ocsp_urls[0]
            result["error"] = f"All {len(ocsp_urls)} OCSP responder(s) failed or were unreachable"
            return result

        try:
            if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL:
                responses = list(ocsp_resp.responses)
                single = responses[0] if responses else None
                if single:
                    status = single.certificate_status
                    if status == OCSPCertStatus.GOOD:
                        result["status"] = "good"
                    elif status == OCSPCertStatus.REVOKED:
                        result["status"] = "revoked"
                        result["revocation_time"] = single.revocation_time_utc.isoformat() if single.revocation_time_utc else None
                        result["revocation_reason"] = str(single.revocation_reason) if single.revocation_reason else None
                    else:
                        result["status"] = "unknown"
                    result["this_update"] = single.this_update_utc.isoformat() if single.this_update_utc else None
                    result["next_update"] = single.next_update_utc.isoformat() if single.next_update_utc else None
            elif ocsp_resp.response_status == OCSPResponseStatus.UNAUTHORIZED:
                result["error"] = "OCSP responder rejected request (authentication required or certificate unknown to this responder)"
            elif ocsp_resp.response_status == OCSPResponseStatus.TRY_LATER:
                result["error"] = "OCSP responder temporarily unavailable (try later)"
            elif ocsp_resp.response_status == OCSPResponseStatus.SIG_REQUIRED:
                result["error"] = "OCSP responder requires a signed request"
            else:
                result["error"] = f"OCSP responder returned non-successful status: {ocsp_resp.response_status.name}"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _assess(self, leaf: Dict, chain: List[Dict]) -> Dict[str, Any]:
        issues = []
        warnings = []

        CRITICAL_KEYWORDS = ("EXPIRED", "Weak key", "self-signed", "Weak signature")

        if leaf.get("expired"):
            issues.append("Certificate is EXPIRED")
        elif leaf.get("days_remaining", 999) < 14:
            issues.append(f"Certificate expires in {leaf['days_remaining']} days (critical)")
        elif leaf.get("days_remaining", 999) < 30:
            warnings.append(f"Certificate expires in {leaf['days_remaining']} days")

        if leaf.get("not_yet_valid"):
            issues.append("Certificate is not yet valid")

        key = leaf.get("key", {})
        if key.get("weak"):
            issues.append(f"Weak key: {key.get('type')} {key.get('bits')} bits")

        sig_alg = leaf.get("signature_algorithm", "").lower()
        for weak in SIGNATURE_ALGORITHMS_WEAK:
            if weak in sig_alg:
                issues.append(f"Weak signature algorithm in leaf: {sig_alg}")
                break

        for c in chain[1:]:
            c_sig = c.get("signature_algorithm", "").lower()
            c_cn = c.get("subject", {}).get("CN", "?")
            for weak in SIGNATURE_ALGORITHMS_WEAK:
                if weak in c_sig:
                    issues.append(f"Weak signature algorithm in intermediate '{c_cn}': {c_sig}")
                    break

        if leaf.get("self_signed") and not leaf.get("is_ca"):
            issues.append("Leaf certificate is self-signed")

        if leaf.get("sct_count", 0) == 0:
            warnings.append("No embedded SCTs (Certificate Transparency) found in leaf cert")

        chain_complete = len(chain) >= 2
        if not chain_complete:
            warnings.append("Certificate chain may be incomplete (only leaf received)")

        for c in chain[1:]:
            if not c.get("is_ca"):
                issues.append(f"Intermediate cert '{c['subject'].get('CN','?')}' missing CA:TRUE")

        grade = "A"
        if issues:
            grade = "F" if any(
                any(kw in i for kw in CRITICAL_KEYWORDS) for i in issues
            ) else "C"
        elif warnings:
            grade = "B"

        return {
            "grade": grade,
            "issues": issues,
            "warnings": warnings,
            "chain_complete": chain_complete,
        }

    def _print_leaf_summary(self, d: Dict) -> None:
        subj = d.get("subject", {})
        key = d.get("key", {})
        self._info("Subject CN", subj.get("CN", "N/A"))
        self._info("Subject O", subj.get("O", "N/A"))
        issuer = d.get("issuer", {})
        self._info("Issuer CN", issuer.get("CN", "N/A"))
        self._info("Serial", d.get("serial", "N/A"))
        self._info("Not Before", d.get("not_before", "N/A"))
        self._info("Not After", d.get("not_after", "N/A"))

        days = d.get("days_remaining", 0)
        if d.get("expired"):
            self._fail("Validity", "EXPIRED")
        elif days < 14:
            self._fail("Days Remaining", str(days))
        elif days < 30:
            self._warn("Days Remaining", str(days))
        else:
            self._pass("Days Remaining", str(days))

        key_str = f"{key.get('type','?')} {key.get('bits','?')} bits"
        if key.get("weak"):
            self._fail("Public Key", key_str + " (WEAK)")
        else:
            self._pass("Public Key", key_str)

        sig = d.get("signature_algorithm", "unknown")
        if any(w in sig.lower() for w in SIGNATURE_ALGORITHMS_WEAK):
            self._fail("Signature Algorithm", sig + " (WEAK)")
        else:
            self._pass("Signature Algorithm", sig)

        scts = d.get("sct_count", 0)
        if scts > 0:
            self._pass("Embedded SCTs", str(scts))
        else:
            self._warn("Embedded SCTs", "0 (CT transparency not embedded in cert)")

        fingerprint = d.get("fingerprints", {}).get("sha256", "N/A")
        self._info("SHA-256 Fingerprint", fingerprint)

    def _print_chain_summary(self, chain: List[Dict]) -> None:
        for c in chain:
            role = c.get("role", "unknown").upper()
            cn = c.get("subject", {}).get("CN", "N/A")
            days = c.get("days_remaining", 0)
            expired = c.get("expired", False)
            status = "EXPIRED" if expired else f"{days}d remaining"
            self._info(f"[{role}] {cn}", status)

    def _print_sans(self, sans: List[Dict]) -> None:
        if not sans:
            self._warn("SANs", "None found")
            return
        self._info("SAN Count", str(len(sans)))
        for san in sans:
            self._info(f"  {san['type']}", san['value'])

    def _print_ct(self, ct: Dict) -> None:
        if ct.get("error"):
            self._warn("CT Log Query", ct["error"])
            return
        source = ct.get("source", "unknown")
        total = ct.get("total_found", 0)
        self._pass(f"CT Entries Found ({source})", str(total))
        for entry in ct.get("entries", [])[:5]:
            cn = entry.get("common_name", "N/A")
            logged = entry.get("logged_at") or entry.get("not_before", "N/A")
            self._info("  Entry", f"{cn} (logged: {logged})")

    def _print_ocsp(self, ocsp: Dict) -> None:
        if ocsp.get("error"):
            self._warn("OCSP", ocsp["error"])
            return
        status = ocsp.get("status", "unknown")
        responder = ocsp.get("responder", "N/A")
        source = ocsp.get("issuer_source", "unknown")
        self._info("OCSP Responder", responder)
        self._info("Issuer Source", source)
        if status == "good":
            self._pass("OCSP Status", "GOOD")
        elif status == "revoked":
            self._fail("OCSP Status", f"REVOKED ({ocsp.get('revocation_reason','?')})")
            if ocsp.get("revocation_time"):
                self._info("Revocation Time", ocsp["revocation_time"])
        else:
            self._warn("OCSP Status", status.upper())

    def _print_assessment(self, assessment: Dict) -> None:
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