import re
import socket
import time
import random

import dns.message
import dns.query
import dns.flags
import dns.rdatatype

from modules.base import BaseDNSModule
from core.ui import C, ok, fail, warn, info, banner


FAST_FLUX_THRESHOLD_LOW  = 300
FAST_FLUX_THRESHOLD_VERY = 60
FAST_FLUX_IP_COUNT_WARN  = 4
FAST_FLUX_IP_COUNT_CRIT  = 8
FAST_FLUX_PROBE_COUNT    = 5
FAST_FLUX_PROBE_DELAY    = 2


class TTLAnomalyModule(BaseDNSModule):

    def _get_authoritative_ns_ips(self) -> list:
        ns_ips = []
        try:
            ns_answers = self.resolver.resolve(self.domain, "NS")
            for ns_rdata in ns_answers:
                ns_host = str(ns_rdata.target).rstrip(".")
                try:
                    ns_ips.append(socket.gethostbyname(ns_host))
                except Exception:
                    pass
        except Exception:
            pass
        return ns_ips or self.resolver.nameservers

    def _fresh_resolve(self, rtype: str, nameservers: list) -> tuple:
        ns  = random.choice(nameservers)
        req = dns.message.make_query(self.domain, rtype, use_edns=True)
        req.flags &= ~dns.flags.RD
        resp    = dns.query.udp(req, ns, timeout=5)
        records = []
        ttl     = 0
        for rrset in resp.answer:
            if dns.rdatatype.from_text(rtype) == rrset.rdtype:
                ttl = rrset.ttl
                for rdata in rrset:
                    records.append(rdata.to_text())
        return records, ttl

    def _probe_ip_rotation(self, rtype: str, ns_ips: list) -> dict:
        all_ips      = set()
        ttls         = []
        record_counts= []
        rounds       = []

        for i in range(FAST_FLUX_PROBE_COUNT):
            try:
                records, ttl = self._fresh_resolve(rtype, ns_ips)
                all_ips.update(records)
                ttls.append(ttl)
                record_counts.append(len(records))
                rounds.append({"round": i + 1, "ttl": ttl, "ips": records})
            except Exception as e:
                rounds.append({"round": i + 1, "error": str(e)})

            if i < FAST_FLUX_PROBE_COUNT - 1:
                time.sleep(FAST_FLUX_PROBE_DELAY)

        return {
            "all_ips":       all_ips,
            "ttls":          ttls,
            "record_counts": record_counts,
            "rounds":        rounds,
        }

    def check_ttl_anomalies(self) -> list:
        banner("TTL Anomaly Analysis (Fast-Flux Detection)")
        anomalies   = []
        check_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        print(f"\n  {C.BOLD}[ 1 / 4 ]  TTL Threshold Check{C.RESET}")
        print(f"\n  {'Record':<30} {'Type':<8} {'TTL (s)':>8}  {'Status'}")
        print(f"  {'─'*30} {'─'*8} {'─'*8}  {'─'*28}")

        ttl_snapshot = {}

        for rtype in check_types:
            try:
                rrset = self.resolver.resolve(self.domain, rtype)
                ttl   = rrset.rrset.ttl
                recs  = [r.to_text() for r in rrset]
                ttl_snapshot[rtype] = (ttl, recs)

                for value in recs:
                    short         = value[:38]
                    anomaly_label = ""
                    if ttl == 0 or ttl == 1:
                        anomaly_label = f"{C.RED}CRITICAL — TTL={ttl} (malicious){C.RESET}"
                    elif ttl < FAST_FLUX_THRESHOLD_VERY:
                        anomaly_label = f"{C.RED}Very Low TTL — possible fast-flux{C.RESET}"
                    elif ttl < FAST_FLUX_THRESHOLD_LOW:
                        anomaly_label = f"{C.YELLOW}Low TTL — worth monitoring{C.RESET}"

                    flag = "⚠" if anomaly_label else " "
                    print(f"  {flag} {short:<29} {rtype:<8} {ttl:>8}  "
                          f"{anomaly_label or C.GREEN + 'OK' + C.RESET}")

                    if anomaly_label:
                        anomalies.append({
                            "check":   "ttl_threshold",
                            "name":    self.domain,
                            "type":    rtype,
                            "ttl":     ttl,
                            "value":   value,
                            "anomaly": anomaly_label.replace(C.RED, "").replace(C.YELLOW, "").replace(C.RESET, ""),
                        })
            except Exception:
                pass

        flux_types = [t for t in ("A", "AAAA") if t in ttl_snapshot]

        if not flux_types:
            print(f"\n  {C.DIM}No A/AAAA records found — skipping rotation probes{C.RESET}")
        else:
            ns_ips = self._get_authoritative_ns_ips()
            info(f"Authoritative NS IPs for probing: {', '.join(ns_ips)}")

            for rtype in flux_types:
                base_ttl, base_recs = ttl_snapshot[rtype]

                print(f"\n  {C.BOLD}[ 2 / 4 ]  IP Rotation Check  ({rtype})  "
                      f"— {FAST_FLUX_PROBE_COUNT} probes × {FAST_FLUX_PROBE_DELAY}s{C.RESET}")
                info(f"Querying authoritative NS directly ({FAST_FLUX_PROBE_COUNT}×) — bypassing resolver cache …")

                probe         = self._probe_ip_rotation(rtype, ns_ips)
                all_ips       = probe["all_ips"]
                ttls          = probe["ttls"]
                record_counts = probe["record_counts"]
                rounds        = probe["rounds"]

                for r in rounds:
                    if "error" in r:
                        warn(f"  Round {r['round']}: error — {r['error']}")
                    else:
                        ips_str = ", ".join(r["ips"]) or "—"
                        print(f"    Round {r['round']:>2}  TTL={r['ttl']:>6}s  "
                              f"IPs ({len(r['ips'])}): {ips_str[:70]}")

                unique_count = len(all_ips)
                print(f"\n    Unique IPs observed across all rounds: {C.BOLD}{unique_count}{C.RESET}")
                print(f"    Full IP set: {', '.join(sorted(all_ips))}")

                rotation_anomaly = ""
                if unique_count >= FAST_FLUX_IP_COUNT_CRIT:
                    rotation_anomaly = (f"FAST-FLUX CONFIRMED — {unique_count} unique IPs "
                                        f"(≥{FAST_FLUX_IP_COUNT_CRIT})")
                    fail(rotation_anomaly)
                elif unique_count >= FAST_FLUX_IP_COUNT_WARN:
                    rotation_anomaly = (f"Suspicious IP rotation — {unique_count} unique IPs "
                                        f"(≥{FAST_FLUX_IP_COUNT_WARN})")
                    warn(rotation_anomaly)
                else:
                    ok(f"IP pool stable — {unique_count} unique IP(s)")

                if rotation_anomaly:
                    anomalies.append({
                        "check":        "ip_rotation",
                        "name":         self.domain,
                        "type":         rtype,
                        "unique_ips":   sorted(all_ips),
                        "probe_rounds": rounds,
                        "anomaly":      rotation_anomaly,
                    })

                print(f"\n  {C.BOLD}[ 3 / 4 ]  Record-Count Check  ({rtype}){C.RESET}")
                max_count = max(record_counts, default=0)
                avg_count = sum(record_counts) / len(record_counts) if record_counts else 0
                print(f"    Max records in a single response : {max_count}")
                print(f"    Avg records per response         : {avg_count:.1f}")

                count_anomaly = ""
                if max_count >= 10:
                    count_anomaly = f"Very large record set ({max_count} records) — double-flux indicator"
                    fail(count_anomaly)
                elif max_count >= 5:
                    count_anomaly = f"Large record set ({max_count} records) — worth investigating"
                    warn(count_anomaly)
                else:
                    ok(f"Record count normal ({max_count} max)")

                if count_anomaly:
                    anomalies.append({
                        "check":         "record_count",
                        "name":          self.domain,
                        "type":          rtype,
                        "max_count":     max_count,
                        "avg_count":     round(avg_count, 1),
                        "record_counts": record_counts,
                        "anomaly":       count_anomaly,
                    })

                print(f"\n  {C.BOLD}[ 4 / 4 ]  TTL Variance Check  ({rtype}){C.RESET}")
                valid_ttls = [t for t in ttls if isinstance(t, int)]
                if valid_ttls:
                    ttl_min  = min(valid_ttls)
                    ttl_max  = max(valid_ttls)
                    ttl_span = ttl_max - ttl_min
                    print(f"    TTL range across probes: {ttl_min}s – {ttl_max}s  (span={ttl_span}s)")

                    expected_max_drift = FAST_FLUX_PROBE_COUNT * FAST_FLUX_PROBE_DELAY + 10
                    variance_anomaly   = ""
                    if ttl_span > expected_max_drift and ttl_min < FAST_FLUX_THRESHOLD_LOW:
                        variance_anomaly = (f"TTL jumped by {ttl_span}s across probes — "
                                            f"different backends responding (fast-flux indicator)")
                        warn(variance_anomaly)
                    elif ttl_span > expected_max_drift:
                        variance_anomaly = (f"Unexpected TTL variance ({ttl_span}s span) — "
                                            f"possible load-balanced or rotating backend")
                        info(f"TTL variance: {variance_anomaly}")
                    else:
                        ok(f"TTL counts down normally (span={ttl_span}s ≤ {expected_max_drift}s expected)")

                    if variance_anomaly:
                        anomalies.append({
                            "check":    "ttl_variance",
                            "name":     self.domain,
                            "type":     rtype,
                            "ttl_min":  ttl_min,
                            "ttl_max":  ttl_max,
                            "ttl_span": ttl_span,
                            "anomaly":  variance_anomaly,
                        })
                else:
                    warn("No valid TTL values collected during probes")

        anomalies.extend(self._check_extended_anomalies())
        return anomalies


    def _check_negative_ttl(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}Negative TTL (SOA MINIMUM){C.RESET}")
        try:
            answers = self.resolver.resolve(self.domain, "SOA")
            for rdata in answers:
                minimum = rdata.minimum
                if minimum > 3600:
                    label = "HIGH"
                    fn = warn
                    msg = f"SOA MINIMUM={minimum}s — HIGH: poisoned NXDOMAIN may persist in cache after takeover"
                elif minimum > 300:
                    label = "MEDIUM"
                    fn = warn
                    msg = f"SOA MINIMUM={minimum}s — MEDIUM"
                else:
                    label = "OK"
                    fn = ok
                    msg = f"SOA MINIMUM={minimum}s — OK"
                fn(msg)
                if label != "OK":
                    findings.append({"check": "negative_ttl", "minimum": minimum, "severity": label})
        except Exception as e:
            fail(f"SOA query failed: {e}")
        return findings

    def _check_dnskey_algorithm(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}DNSKEY Algorithm Check{C.RESET}")
        WEAK   = {5, 7}
        STRONG = {8, 10, 13, 14, 15}
        NAMES  = {
            5: "RSASHA1", 7: "RSASHA1-NSEC3", 8: "RSASHA256",
            10: "RSASHA512", 13: "ECDSAP256SHA256",
            14: "ECDSAP384SHA384", 15: "ED25519",
        }
        try:
            answers = self.resolver.resolve(self.domain, "DNSKEY")
            algos = set()
            for rdata in answers:
                algos.add(rdata.algorithm)
                name = NAMES.get(rdata.algorithm, str(rdata.algorithm))
                is_ksk = bool(rdata.flags & 0x0001)
                ok(f"DNSKEY algo={rdata.algorithm} ({name})  {'KSK' if is_ksk else 'ZSK'}")
            weak_present   = algos & WEAK
            strong_present = algos & STRONG
            if weak_present and strong_present:
                msg = f"Mixed algorithms — downgrade possible: weak={{{', '.join(NAMES.get(a, str(a)) for a in weak_present)}}}"
                warn(msg)
                findings.append({"check": "dnskey_algorithm", "severity": "WARNING", "weak": list(weak_present), "strong": list(strong_present)})
            elif weak_present:
                msg = f"Only weak algorithm(s) present: {{{', '.join(NAMES.get(a, str(a)) for a in weak_present)}}}"
                warn(msg)
                findings.append({"check": "dnskey_algorithm", "severity": "HIGH", "weak": list(weak_present)})
            else:
                ok("All DNSKEY algorithms are strong")
        except Exception:
            ok("No DNSKEY records — DNSSEC not in use")
        return findings

    def _check_ds_dnskey_mismatch(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}DS / DNSKEY Consistency{C.RESET}")
        has_dnskey = False
        has_ds     = False
        try:
            self.resolver.resolve(self.domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            pass
        try:
            self.resolver.resolve(self.domain, "DS")
            has_ds = True
        except Exception:
            pass
        if has_dnskey and not has_ds:
            msg = "DNSKEY present but no DS record — zone is technically insecure (unsigned delegation)"
            warn(msg)
            findings.append({"check": "ds_dnskey_mismatch", "severity": "WARNING", "detail": msg})
        elif has_dnskey and has_ds:
            ok("DNSKEY and DS both present — delegation consistent")
        else:
            ok("DNSSEC not in use — no mismatch possible")
        return findings

    def _check_fast_flux(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}Fast-Flux Detection (A / NS TTL){C.RESET}")
        try:
            a_answers  = self.resolver.resolve(self.domain, "A")
            a_ttl      = a_answers.rrset.ttl
            a_ips_1    = [r.to_text() for r in a_answers]
            if a_ttl <= 60:
                severity = "CRITICAL"
                fn = fail
            elif a_ttl <= 300:
                severity = "WARNING"
                fn = warn
            else:
                severity = "OK"
                fn = ok
            fn(f"A record TTL={a_ttl}s — {severity}")

            time.sleep(3)
            ns_ips_flux = self._get_authoritative_ns_ips()
            a_ips_2, _ = self._fresh_resolve("A", ns_ips_flux)
            changed    = set(a_ips_1) != set(a_ips_2)
            if changed:
                warn(f"IP set changed between queries — fast-flux CONFIRMED")
                warn(f"  Round 1: {', '.join(a_ips_1)}")
                warn(f"  Round 2: {', '.join(a_ips_2)}")
                findings.append({
                    "check": "fast_flux", "severity": "CRITICAL",
                    "ips_round1": a_ips_1, "ips_round2": a_ips_2,
                    "detail": "IP rotation confirmed"
                })
            else:
                ok(f"A records stable across two queries: {', '.join(a_ips_1)}")
                if severity != "OK":
                    findings.append({
                        "check": "fast_flux", "severity": severity,
                        "ttl": a_ttl, "ips": a_ips_1,
                        "detail": f"Low TTL={a_ttl}s but IPs stable"
                    })

            try:
                ns_answers = self.resolver.resolve(self.domain, "NS")
                ns_ttl     = ns_answers.rrset.ttl
                if ns_ttl <= 300 and a_ttl <= 300:
                    warn(f"NS TTL={ns_ttl}s also low — double-flux indicator")
                    findings.append({
                        "check": "double_flux", "severity": "HIGH",
                        "a_ttl": a_ttl, "ns_ttl": ns_ttl,
                        "detail": "Both A and NS TTLs below 300s"
                    })
                else:
                    ok(f"NS TTL={ns_ttl}s — OK")
            except Exception:
                pass
        except Exception as e:
            fail(f"Fast-flux check failed: {e}")
        return findings

    def _check_ttl_consistency(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}TTL Consistency Across Record Types{C.RESET}")
        ttl_map = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                ttl_map[rtype] = answers.rrset.ttl
            except Exception:
                pass
        if len(ttl_map) < 2:
            ok("Not enough record types to compare TTLs")
            return findings
        for rtype, ttl in ttl_map.items():
            print(f"    {rtype:<8} TTL={ttl}s")
        min_rtype = min(ttl_map, key=ttl_map.get)
        max_rtype = max(ttl_map, key=ttl_map.get)
        min_ttl   = ttl_map[min_rtype]
        max_ttl   = ttl_map[max_rtype]
        ratio     = (max_ttl / min_ttl) if min_ttl > 0 else float("inf")
        if ratio > 1000:
            severity = "HIGH"
            fn = fail
        elif ratio > 100:
            severity = "MEDIUM"
            fn = warn
        else:
            severity = "OK"
            fn = ok
        fn(f"TTL ratio max/min = {ratio:.0f}x ({max_rtype}={max_ttl}s / {min_rtype}={min_ttl}s) — {severity}")
        if min_ttl < 300:
            warn(f"Lowest TTL: {min_rtype}={min_ttl}s — possible active manipulation indicator")
        if severity != "OK":
            findings.append({
                "check": "ttl_consistency", "severity": severity,
                "ratio": round(ratio, 1), "min_type": min_rtype,
                "min_ttl": min_ttl, "max_type": max_rtype, "max_ttl": max_ttl,
            })
        return findings

    def _check_caa_records(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}CAA Records{C.RESET}")
        try:
            answers   = self.resolver.resolve(self.domain, "CAA")
            has_issue = False
            has_wild  = False
            has_iodef = False
            for rdata in answers:
                tag   = rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag
                value = rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value
                ok(f"CAA tag={tag}  value={value}")
                if tag == "issue":
                    has_issue = True
                elif tag == "issuewild":
                    has_wild = True
                elif tag == "iodef":
                    has_iodef = True
            if not has_wild:
                msg = "No issuewild tag — wildcard certificates can be issued by any CA"
                warn(msg)
                findings.append({"check": "caa_issuewild", "severity": "WARNING", "detail": msg})
            if not has_iodef:
                warn("No iodef tag — no incident reporting configured")
                findings.append({"check": "caa_iodef", "severity": "INFO", "detail": "No iodef tag"})
        except Exception:
            msg = "No CAA records — any CA can issue certificates for this domain"
            warn(msg)
            findings.append({"check": "caa_missing", "severity": "HIGH", "detail": msg})
        return findings

    def _check_naptr_records(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}NAPTR Records{C.RESET}")
        VOIP_SERVICES = {"SIP+D2U", "SIP+D2T", "SIPS+D2T"}
        try:
            answers = self.resolver.resolve(self.domain, "NAPTR")
            voip    = []
            for rdata in answers:
                service = rdata.service.decode() if isinstance(rdata.service, bytes) else rdata.service
                regexp  = rdata.regexp.decode()  if isinstance(rdata.regexp,  bytes) else rdata.regexp
                repl    = str(rdata.replacement).rstrip(".")
                ok(
                    f"NAPTR order={rdata.order}  pref={rdata.preference}  "
                    f"flags={rdata.flags!r}  service={service}  "
                    f"regexp={regexp!r}  replacement={repl}"
                )
                if service.upper() in VOIP_SERVICES:
                    voip.append(service)
            if voip:
                warn(f"VoIP services detected: {', '.join(voip)} — combine with _sip._tcp SRV for full architecture map")
                findings.append({"check": "naptr_voip", "severity": "INFO", "services": voip})
        except Exception:
            ok("No NAPTR records found")
        return findings

    def _check_hinfo_records(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}HINFO Records{C.RESET}")
        try:
            answers = self.resolver.resolve(self.domain, "HINFO")
            for rdata in answers:
                cpu = rdata.cpu.decode() if isinstance(rdata.cpu, bytes) else rdata.cpu
                os  = rdata.os.decode()  if isinstance(rdata.os,  bytes) else rdata.os
                warn(f"HINFO cpu={cpu!r}  os={os!r} — HIGH: hardware/OS info publicly exposed")
                findings.append({
                    "check": "hinfo_exposed", "severity": "HIGH",
                    "cpu": cpu, "os": os,
                })
        except Exception:
            ok("No HINFO records found")
        return findings

    def _check_rp_records(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}RP (Responsible Person) Records{C.RESET}")
        try:
            answers = self.resolver.resolve(self.domain, "RP")
            for rdata in answers:
                mailbox = str(rdata.mbox).rstrip(".")
                parts   = mailbox.split(".")
                email   = parts[0] + "@" + ".".join(parts[1:]) if len(parts) > 1 else mailbox
                txt_ref = str(rdata.txt).rstrip(".")
                info(f"RP email={email}  txt_ref={txt_ref}")
                findings.append({
                    "check": "rp_record", "severity": "INFO",
                    "email": email, "txt_ref": txt_ref,
                    "detail": "Admin email and naming convention exposed via RP record"
                })
        except Exception:
            ok("No RP records found")
        return findings

    def _check_ptr_leakage(self) -> list:
        findings = []
        print(f"\n  {C.BOLD}PTR Leakage — Internal Hostname Patterns{C.RESET}")
        ENV_PATTERNS  = re.compile(r"\b(prod|dev|stag|staging|test|uat|qa)\b", re.I)
        DC_PATTERNS   = re.compile(r"\b(dc[0-9]+|ams|fra|lon|nyc|sfo|sin|tok)\b", re.I)
        INT_PATTERNS  = re.compile(r"\.(internal|corp|local|lan)\b", re.I)
        SEQ_PATTERNS  = re.compile(r"-0*[0-9]{1,3}\b")
        try:
            a_answers = self.resolver.resolve(self.domain, "A")
            ips       = [r.to_text() for r in a_answers]
        except Exception:
            ok("No A records — skipping PTR leakage check")
            return findings
        for ip in ips:
            try:
                rev  = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                ptr_answers = self.resolver.resolve(rev, "PTR")
                for rdata in ptr_answers:
                    ptr = str(rdata.target).rstrip(".")
                    severity = None
                    reasons  = []
                    if INT_PATTERNS.search(ptr):
                        severity = "HIGH"
                        reasons.append("internal namespace (.internal/.corp/.local/.lan)")
                    if ENV_PATTERNS.search(ptr):
                        severity = severity or "MEDIUM"
                        reasons.append("environment label (prod/dev/stag/test/uat/qa)")
                    if DC_PATTERNS.search(ptr):
                        severity = severity or "MEDIUM"
                        reasons.append("datacenter label")
                    if SEQ_PATTERNS.search(ptr):
                        severity = severity or "MEDIUM"
                        reasons.append("sequential naming scheme")
                    if severity == "HIGH":
                        fail(f"PTR {ip} → {ptr}  [{', '.join(reasons)}]")
                        findings.append({"check": "ptr_leakage", "ip": ip, "ptr": ptr, "severity": "HIGH", "reasons": reasons})
                    elif severity == "MEDIUM":
                        warn(f"PTR {ip} → {ptr}  [{', '.join(reasons)}]")
                        findings.append({"check": "ptr_leakage", "ip": ip, "ptr": ptr, "severity": "MEDIUM", "reasons": reasons})
                    else:
                        ok(f"PTR {ip} → {ptr}")
            except Exception:
                ok(f"No PTR for {ip}")
        return findings

    def _check_extended_anomalies(self) -> list:
        anomalies = []
        anomalies.extend(self._check_negative_ttl())
        anomalies.extend(self._check_dnskey_algorithm())
        anomalies.extend(self._check_ds_dnskey_mismatch())
        anomalies.extend(self._check_fast_flux())
        anomalies.extend(self._check_ttl_consistency())
        anomalies.extend(self._check_caa_records())
        anomalies.extend(self._check_naptr_records())
        anomalies.extend(self._check_hinfo_records())
        anomalies.extend(self._check_rp_records())
        anomalies.extend(self._check_ptr_leakage())

        print(f"\n  {'─'*58}")
        if not anomalies:
            ok("No fast-flux or TTL anomalies detected")
        else:
            checks_hit = sorted({a["check"] for a in anomalies})
            warn(f"{len(anomalies)} anomaly signal(s) across checks: {', '.join(checks_hit)}")

        return anomalies