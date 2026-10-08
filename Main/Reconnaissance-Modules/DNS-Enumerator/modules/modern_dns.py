from datetime import datetime, timezone

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

from modules.base import BaseDNSModule
from core.ui import C, ok, fail, warn, info, banner


SSHFP_ALGORITHMS = {1: "RSA", 2: "DSA", 3: "ECDSA", 4: "Ed25519"}
SSHFP_FP_TYPES   = {1: "SHA-1", 2: "SHA-256"}

TLSA_PORTS = [
    ("_443._tcp", "HTTPS"),
    ("_80._tcp",  "HTTP"),
    ("_25._tcp",  "SMTP"),
]


class ModernDNSModule(BaseDNSModule):

    def _query_rrsig(self, name: str) -> list:
        rrsigs = []
        for ns_ip in ["8.8.8.8", "1.1.1.1"]:
            try:
                req = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
                req.flags |= dns.flags.CD
                resp = dns.query.udp(req, ns_ip, timeout=5)
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        for rdata in rrset:
                            rrsigs.append(rdata)
                if rrsigs:
                    break
            except Exception:
                continue
        return rrsigs

    def _check_nsec_walking(self) -> list:
        print(f"\n  {C.BOLD}NSEC Zone Walking{C.RESET}")
        discovered = []

        try:
            self.resolver.resolve(self.domain, "NSEC3")
            warn("NSEC3 present — zone walking not possible (use NSEC3 hash cracking instead)")
            return discovered
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass

        try:
            answers = self.resolver.resolve(self.domain, "NSEC")
        except Exception:
            ok("No NSEC record — zone walking not applicable")
            return discovered

        warn("NSEC present — zone walking possible")
        current   = self.domain
        seen      = set()
        MAX_STEPS = 50

        while len(discovered) < MAX_STEPS:
            if current in seen:
                break
            seen.add(current)
            try:
                answers = self.resolver.resolve(current, "NSEC")
                for rdata in answers:
                    next_name = str(rdata.next).rstrip(".")
                    discovered.append(current)
                    info(f"NSEC walk: {current}  →  {next_name}")
                    current = next_name
                    break
                else:
                    break
            except Exception:
                break

        if len(discovered) >= MAX_STEPS:
            warn(f"Zone walk stopped at {MAX_STEPS} steps — zone may be much larger")
        if discovered:
            warn(f"Zone walk revealed {len(discovered)} name(s)")
        return discovered

    def _check_nsec3_optout(self) -> dict:
        print(f"\n  {C.BOLD}NSEC3 Opt-Out & Parameters{C.RESET}")
        result = {}
        try:
            answers = self.resolver.resolve(self.domain, "NSEC3PARAM")
            for rdata in answers:
                flags      = rdata.flags
                iterations = rdata.iterations
                opt_out    = bool(flags & 0x01)
                result = {
                    "flags":      flags,
                    "iterations": iterations,
                    "opt_out":    opt_out,
                }
                if opt_out:
                    warn(f"NSEC3 opt-out ENABLED (flags={flags}) — unsigned delegations excluded from chain")
                else:
                    ok(f"NSEC3 opt-out disabled (flags={flags})")
                if iterations > 100:
                    warn(f"iterations={iterations} — HIGH: RFC 9276 recommends 0; high values degrade "
                         f"resolver performance without meaningful security gain")
                elif iterations > 0:
                    warn(f"iterations={iterations} — RFC 9276 recommends 0 for modern deployments")
                else:
                    ok(f"iterations=0 — optimal per RFC 9276")
        except dns.resolver.NoAnswer:
            ok("No NSEC3PARAM record — NSEC3 not in use")
        except Exception as e:
            fail(f"NSEC3PARAM query failed: {e}")
        return result

    def _check_sshfp(self, dnssec_valid: bool) -> list:
        print(f"\n  {C.BOLD}SSHFP Records{C.RESET}")
        findings = []
        try:
            answers = self.resolver.resolve(self.domain, "SSHFP")
            for rdata in answers:
                algo    = SSHFP_ALGORITHMS.get(rdata.algorithm, str(rdata.algorithm))
                fp_type = SSHFP_FP_TYPES.get(rdata.fp_type, str(rdata.fp_type))
                fp_hex  = rdata.fingerprint.hex()
                entry   = {
                    "algorithm":        algo,
                    "fingerprint_type": fp_type,
                    "fingerprint":      fp_hex,
                }
                findings.append(entry)
                if rdata.fp_type == 1:
                    warn(f"SSHFP {algo} / {fp_type} — SHA-1 is weak, upgrade to SHA-256")
                else:
                    ok(f"SSHFP {algo} / {fp_type}  |  {fp_hex}")

            if not dnssec_valid:
                warn("CRITICAL — SSHFP records present but DNSSEC chain invalid: MITM via DNS poisoning possible")

        except dns.resolver.NoAnswer:
            ok("No SSHFP records found")
        except Exception as e:
            fail(f"SSHFP query failed: {e}")
        return findings

    def _check_rrsig_expiry(self) -> list:
        print(f"\n  {C.BOLD}RRSIG Expiry{C.RESET}")
        findings = []
        now  = datetime.now(timezone.utc)
        sigs = self._query_rrsig(self.domain)
        if not sigs:
            fail("No RRSIG records found")
            return findings
        for sig in sigs:
            exp_dt    = datetime.fromtimestamp(sig.expiration, tz=timezone.utc)
            days_left = (exp_dt - now).days
            covered   = dns.rdatatype.to_text(sig.type_covered)
            exp_str   = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
            entry     = {
                "type_covered": covered,
                "expires":      exp_str,
                "days_left":    days_left,
            }
            findings.append(entry)
            if days_left < 0:
                fail(f"RRSIG {covered} — EXPIRED since {exp_str}")
            elif days_left < 3:
                warn(f"RRSIG {covered} — CRITICAL: expires in {days_left}d ({exp_str})")
            elif days_left < 7:
                warn(f"RRSIG {covered} — WARNING: expires in {days_left}d ({exp_str})")
            else:
                ok(f"RRSIG {covered} — OK: {days_left}d remaining ({exp_str})")
        return findings

    def _check_tlsa_dane(self, dnssec_valid: bool) -> list:
        print(f"\n  {C.BOLD}TLSA / DANE{C.RESET}")
        findings = []
        for prefix, label in TLSA_PORTS:
            name = f"{prefix}.{self.domain}"
            try:
                answers = self.resolver.resolve(name, "TLSA")
                for rdata in answers:
                    cert_hex = rdata.cert.hex()
                    entry    = {
                        "name":      name,
                        "service":   label,
                        "usage":     rdata.usage,
                        "selector":  rdata.selector,
                        "mtype":     rdata.mtype,
                        "cert_hash": cert_hex,
                    }
                    findings.append(entry)
                    ok(
                        f"TLSA {label} ({name})  |  "
                        f"usage={rdata.usage}  selector={rdata.selector}  "
                        f"mtype={rdata.mtype}  hash={cert_hex[:16]}..."
                    )
                if not dnssec_valid:
                    warn(f"CRITICAL — TLSA present for {label} but DNSSEC invalid: forged certificate acceptance possible")
            except dns.resolver.NoAnswer:
                ok(f"No TLSA record for {label} ({name})")
            except dns.resolver.NXDOMAIN:
                ok(f"No TLSA record for {label} ({name})")
            except Exception as e:
                fail(f"TLSA query failed for {name}: {e}")
        return findings

    def validate_dnssec(self) -> dict:
        banner("DNSSEC Validation")
        results = {
            "dnskey": False, "ds": False,
            "rrsig":  False, "nsec": False,
            "chain_valid": False,
        }

        print(f"\n  {C.BOLD}DNSKEY{C.RESET}")
        try:
            dnskeys = self.resolver.resolve(self.domain, "DNSKEY")
            results["dnskey"] = True
            for key in dnskeys:
                is_ksk = bool(key.flags & 0x0001)
                ok(f"DNSKEY found — flags={key.flags}  algo={key.algorithm}  {'KSK' if is_ksk else 'ZSK'}")
        except dns.resolver.NoAnswer:
            fail("No DNSKEY record — DNSSEC not enabled")
        except Exception as e:
            fail(f"DNSKEY query failed: {e}")

        print(f"\n  {C.BOLD}DS Record{C.RESET}")
        try:
            ds_records = self.resolver.resolve(self.domain, "DS")
            results["ds"] = True
            for ds in ds_records:
                ok(f"DS record — keytag={ds.key_tag}  algo={ds.algorithm}  digest_type={ds.digest_type}")
        except dns.resolver.NoAnswer:
            warn("No DS record found — chain of trust not delegated")
        except Exception as e:
            fail(f"DS query failed: {e}")

        print(f"\n  {C.BOLD}RRSIG (Signature){C.RESET}")
        rrsigs = self._query_rrsig(self.domain)
        if rrsigs:
            results["rrsig"] = True
            for sig in rrsigs:
                exp_dt = datetime.fromtimestamp(sig.expiration, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                ok(f"RRSIG covers {dns.rdatatype.to_text(sig.type_covered)}  |  expires {exp_dt}")
        else:
            fail("No RRSIG records found")

        print(f"\n  {C.BOLD}NSEC / NSEC3{C.RESET}")
        for rtype in ("NSEC", "NSEC3"):
            try:
                self.resolver.resolve(self.domain, rtype)
                results["nsec"] = True
                ok(f"{rtype} record present — authenticated denial of existence enabled")
                break
            except Exception:
                pass
        if not results["nsec"]:
            warn("No NSEC/NSEC3 records found — authenticated denial unavailable")

        print(f"\n  {C.BOLD}Chain of Trust{C.RESET}")
        if results["dnskey"] and results["ds"] and results["rrsig"]:
            results["chain_valid"] = True
            ok("Chain of trust appears intact (DNSKEY + DS + RRSIG present)")
        else:
            missing = [k for k in ("dnskey", "ds", "rrsig") if not results[k]]
            fail(f"Incomplete chain — missing: {', '.join(missing).upper()}")

        dnssec_valid = results["chain_valid"]

        results["nsec_walk"]    = self._check_nsec_walking()
        results["nsec3_optout"] = self._check_nsec3_optout()
        results["sshfp"]        = self._check_sshfp(dnssec_valid)
        results["rrsig_expiry"] = self._check_rrsig_expiry()
        results["tlsa"]         = self._check_tlsa_dane(dnssec_valid)

        return results