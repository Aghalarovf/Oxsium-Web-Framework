import socket
import struct
import datetime
import time
import threading

import dns.message
import dns.zone
import dns.query
import dns.resolver
import dns.rdatatype
import dns.exception

from modules.base import BaseDNSModule
from core.ui import C, ok, fail, warn, info, banner


class ZoneTransferModule(BaseDNSModule):

    def _axfr_tcp(self, ns: str) -> tuple[dns.zone.Zone | None, str | None]:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10, use_udp=False))
            return zone, None
        except dns.exception.FormError as exc:
            return None, f"malformed AXFR response: {exc}"
        except dns.query.TransferError as exc:
            return None, f"transfer refused: {exc}"
        except socket.gaierror as exc:
            return None, f"could not resolve {ns}: {exc}"
        except OSError as exc:
            return None, f"network error: {exc}"

    def _ixfr_fallback(self, ns: str, current_serial: int) -> tuple[dns.zone.Zone | None, str | None]:
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(
                dns.query.xfr(
                    ns_ip,
                    self.domain,
                    rdtype=dns.rdatatype.IXFR,
                    serial=current_serial,
                    timeout=10,
                )
            )
            return zone, None
        except dns.exception.FormError as exc:
            return None, f"malformed IXFR response: {exc}"
        except dns.query.TransferError as exc:
            return None, f"IXFR refused: {exc}"
        except socket.gaierror as exc:
            return None, f"could not resolve {ns}: {exc}"
        except OSError as exc:
            return None, f"network error: {exc}"

    def _any_query_dump(self, ns: str) -> list[str]:
        results = []
        try:
            ns_ip = socket.gethostbyname(ns)
            request = dns.message.make_query(self.domain, dns.rdatatype.ANY)
            response = dns.query.udp(request, ns_ip, timeout=10)

            if not response.answer:
                return results

            is_rfc8482 = any(
                rrset.rdtype == dns.rdatatype.HINFO
                and any(
                    str(getattr(r, "cpu", "")).upper() == "RFC8482"
                    or str(r).startswith("RFC8482")
                    for r in rrset
                )
                for rrset in response.answer
            )

            if is_rfc8482:
                results.append("RFC8482 compliant — server intentionally limits ANY responses")
                return results

            for rrset in response.answer:
                results.append(str(rrset))

        except socket.gaierror:
            pass
        except OSError:
            pass
        return results

    def _parse_soa_serial(self, ns: str) -> dict:
        result = {}
        try:
            ns_ip = socket.gethostbyname(ns)
            request = dns.message.make_query(self.domain, dns.rdatatype.SOA)
            response = dns.query.udp(request, ns_ip, timeout=10)
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    soa = list(rrset)[0]
                    serial = soa.serial
                    result["serial"] = serial
                    result["negative_ttl"] = soa.minimum

                    rname = str(soa.rname).rstrip(".")
                    escaped_local, _, domain_part = rname.partition("\\.")
                    if not domain_part:
                        parts = rname.split(".", 1)
                        local = parts[0]
                        domain_part = parts[1] if len(parts) > 1 else ""
                    else:
                        local = escaped_local.replace(".", "")
                    if domain_part:
                        result["admin_email"] = f"{local}@{domain_part}"

                    serial_str = str(serial)
                    if len(serial_str) == 10:
                        try:
                            year = int(serial_str[0:4])
                            month = int(serial_str[4:6])
                            day = int(serial_str[6:8])
                            nn = int(serial_str[8:10])
                            result["serial_date"] = datetime.date(year, month, day).isoformat()
                            result["serial_revision"] = nn
                        except ValueError:
                            pass
        except socket.gaierror:
            pass
        except OSError:
            pass
        return result

    def _passive_notify_detect(self, timeout: int = 10) -> list[str]:
        sources: list[str] = []
        result_ready = threading.Event()

        def _capture() -> None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                sock.settimeout(1.0)
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        data, addr = sock.recvfrom(512)
                        dns_data = data[28:]
                        if len(dns_data) >= 4:
                            flags = struct.unpack("!H", dns_data[2:4])[0]
                            opcode = (flags >> 11) & 0xF
                            if opcode == 4:
                                src = addr[0]
                                if src not in sources:
                                    sources.append(src)
                    except socket.timeout:
                        continue
                sock.close()
            except PermissionError:
                warn("Root privileges required for passive NOTIFY detection — skipping")
            except OSError:
                pass
            finally:
                result_ready.set()

        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        result_ready.wait(timeout=timeout + 2)
        return sources

    def attempt_axfr(self) -> dict:
        banner("Zone Transfer (AXFR)")
        report: dict = {
            "vulnerable": False,
            "zone_records": [],
            "any_records": [],
            "soa_info": {},
            "notify_sources": [],
        }

        try:
            ns_answers = self.resolver.resolve(self.domain, "NS")
            nameservers = [str(r.target).rstrip(".") for r in ns_answers]
        except dns.resolver.NXDOMAIN:
            fail(f"Domain {self.domain} does not exist")
            return report
        except dns.resolver.NoNameservers:
            fail(f"No nameservers available for {self.domain}")
            return report
        except dns.resolver.Timeout:
            fail(f"Timeout resolving NS records for {self.domain}")
            return report
        except dns.exception.DNSException as exc:
            fail(f"Could not resolve NS records: {exc}")
            return report

        for ns in nameservers:
            info(f"Trying AXFR on {ns}")

            soa_info = self._parse_soa_serial(ns)
            if soa_info:
                report["soa_info"][ns] = soa_info
                info(f"SOA recon from {ns}:")
                if "serial" in soa_info:
                    info(f"  Serial       : {soa_info['serial']}")
                if "serial_date" in soa_info:
                    info(f"  Serial date  : {soa_info['serial_date']} (revision {soa_info.get('serial_revision', '?')})")
                if "negative_ttl" in soa_info:
                    info(f"  Negative TTL : {soa_info['negative_ttl']}s")
                if "admin_email" in soa_info:
                    info(f"  Admin email  : {soa_info['admin_email']}")

            zone, axfr_err = self._axfr_tcp(ns)

            if zone is None:
                info(f"AXFR failed on {ns} ({axfr_err}), trying IXFR fallback")
                current_serial = soa_info.get("serial", 0)
                zone, ixfr_err = self._ixfr_fallback(ns, current_serial)

            if zone is not None:
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        record_str = f"{name}.{self.domain}  {rdataset}"
                        records.append(record_str)
                        ok(f"  {record_str}")

                warn(f"ZONE TRANSFER SUCCESSFUL on {ns} — {len(records)} records exposed!")
                report["vulnerable"] = True
                report["zone_records"].extend(records)
            else:
                ok(f"AXFR/IXFR refused on {ns}, trying ANY query")
                any_results = self._any_query_dump(ns)
                if any_results:
                    info(f"ANY query results from {ns}:")
                    for record in any_results:
                        info(f"  {record}")
                    report["any_records"].extend(any_results)
                else:
                    ok(f"ANY query returned no useful data from {ns}")

        info("Running passive NOTIFY detection (10s capture window)")
        notify_sources = self._passive_notify_detect(timeout=10)
        if notify_sources:
            warn("NOTIFY packets detected from hidden primary/secondary servers:")
            for src in notify_sources:
                warn(f"  {src}")
            report["notify_sources"] = notify_sources
        else:
            ok("No NOTIFY packets observed during capture window")

        return report