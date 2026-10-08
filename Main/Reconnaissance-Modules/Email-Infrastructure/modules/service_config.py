import asyncio
from typing import Optional

from .base import BaseEmailModule


_MAIL_PORTS = [
    {"port": 25,   "protocol": "SMTP",  "tls": False, "label": "SMTP"},
    {"port": 465,  "protocol": "SMTPS", "tls": True,  "label": "SMTPS"},
    {"port": 587,  "protocol": "SMTP",  "tls": False, "label": "SMTP Submission"},
    {"port": 2525, "protocol": "SMTP",  "tls": False, "label": "SMTP Alt"},
    {"port": 143,  "protocol": "IMAP",  "tls": False, "label": "IMAP"},
    {"port": 993,  "protocol": "IMAPS", "tls": True,  "label": "IMAPS"},
    {"port": 110,  "protocol": "POP3",  "tls": False, "label": "POP3"},
    {"port": 995,  "protocol": "POP3S", "tls": True,  "label": "POP3S"},
    {"port": 4190, "protocol": "SIEVE", "tls": False, "label": "ManageSieve"},
]

_AUTODISCOVER_PATHS = [
    "/autodiscover/autodiscover.xml",
    "/autodiscover/autodiscover.json",
]

_AUTOCONFIG_URL = "/.well-known/autoconfig/mail/config-v1.1.xml"

_CATCH_ALL_PROBE = "oxsium-probe-no-such-user-xqz9@{domain}"

_STARTTLS_INDICATORS = {
    "SMTP": "starttls",
    "IMAP": "starttls",
    "POP3": "stls",
}

_SMTP_ENUM_COMMANDS = [
    {"cmd": "VRFY root",                    "key": "VRFY root"},
    {"cmd": "VRFY admin",                   "key": "VRFY admin"},
    {"cmd": "EXPN root",                    "key": "EXPN root"},
    {"cmd": "EXPN all",                     "key": "EXPN all"},
    {"cmd": "RCPT TO:<root@localhost>",     "key": "RCPT TO root@localhost"},
    {"cmd": "RCPT TO:<admin@localhost>",    "key": "RCPT TO admin@localhost"},
]

_OPEN_RELAY_EXTERNAL_FROM  = "pentest-probe@external-oxsium.invalid"
_OPEN_RELAY_EXTERNAL_RCPT  = "probe-dest@external-oxsium.invalid"

_AUTH_MECHANISMS = ["PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "NTLM", "GSSAPI", "XOAUTH2"]


class ServiceConfigModule(BaseEmailModule):

    async def run(self, domain: str) -> dict:
        mx_records = await self._resolver.mx(domain)
        mx_hosts = [r["host"].rstrip(".") for r in (mx_records or [])]

        (
            port_results,
            smtp_enum,
            autodiscover,
            autoconfig,
            catch_all,
            ehlo_results,
            auth_results,
            relay_results,
            starttls_downgrade,
        ) = await asyncio.gather(
            self._probe_all_ports(domain, mx_hosts),
            self._smtp_enumerate(mx_hosts),
            self._check_autodiscover(domain),
            self._check_autoconfig(domain),
            self._check_catch_all(domain, mx_hosts),
            self._check_ehlo_helo(mx_hosts),
            self._check_auth_mechanisms(mx_hosts),
            self._check_open_relay(mx_hosts),
            self._check_starttls_downgrade(mx_hosts),
            return_exceptions=True,
        )

        if isinstance(port_results, Exception):
            port_results = {"hosts": [], "issues": [str(port_results)]}
        if isinstance(smtp_enum, Exception):
            smtp_enum = {"hosts": [], "issues": [str(smtp_enum)]}
        if isinstance(autodiscover, Exception):
            autodiscover = {"available": False, "urls": [], "issues": [str(autodiscover)]}
        if isinstance(autoconfig, Exception):
            autoconfig = {"available": False, "url": None, "issues": [str(autoconfig)]}
        if isinstance(catch_all, Exception):
            catch_all = {"enabled": None, "issues": [str(catch_all)]}
        if isinstance(ehlo_results, Exception):
            ehlo_results = {"hosts": [], "issues": [str(ehlo_results)]}
        if isinstance(auth_results, Exception):
            auth_results = {"hosts": [], "issues": [str(auth_results)]}
        if isinstance(relay_results, Exception):
            relay_results = {"hosts": [], "issues": [str(relay_results)]}
        if isinstance(starttls_downgrade, Exception):
            starttls_downgrade = {"hosts": [], "issues": [str(starttls_downgrade)]}

        return {
            "port_scan":          port_results,
            "smtp_enum":          smtp_enum,
            "autodiscover":       autodiscover,
            "autoconfig":         autoconfig,
            "catch_all":          catch_all,
            "ehlo_helo":          ehlo_results,
            "auth_mechanisms":    auth_results,
            "open_relay":         relay_results,
            "starttls_downgrade": starttls_downgrade,
        }

    async def _probe_all_ports(self, domain: str, mx_hosts: list[str]) -> dict:
        issues = []
        hosts_results = []

        targets = mx_hosts if mx_hosts else [domain]

        for host in targets:
            host_entry = {"host": host, "ports": []}

            tasks = [self._probe_port(host, spec) for spec in _MAIL_PORTS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for spec, result in zip(_MAIL_PORTS, results):
                if isinstance(result, Exception):
                    result = {"open": False, "banner": None, "starttls": None, "error": str(result)}

                port_entry = {
                    "port":     spec["port"],
                    "label":    spec["label"],
                    "protocol": spec["protocol"],
                    "tls":      spec["tls"],
                    **result,
                }
                host_entry["ports"].append(port_entry)

                self._logger.finding(
                    "PORT",
                    f"{host}:{spec['port']}",
                    f"{spec['label']}  {'open' if result.get('open') else 'closed'}",
                    confidence=1.0 if result.get("open") else 0.0,
                )

                if result.get("open") and not spec["tls"] and result.get("starttls") is False:
                    issues.append(
                        f"{spec['label']} on {host}:{spec['port']} is open but STARTTLS is not advertised"
                    )

            hosts_results.append(host_entry)

        open_smtp = any(
            p["open"]
            for h in hosts_results
            for p in h["ports"]
            if p["port"] in (25, 587, 465)
        )
        if not open_smtp:
            issues.append("No SMTP port (25, 465, 587) reachable on any MX host")

        return {"hosts": hosts_results, "issues": issues}

    async def _probe_port(self, host: str, spec: dict, timeout: float = 5.0) -> dict:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, spec["port"]),
                timeout=timeout,
            )
        except Exception as exc:
            return {"open": False, "banner": None, "starttls": None, "error": str(exc)}

        try:
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = banner_bytes.decode(errors="replace").strip()
        except Exception:
            banner = None

        starttls = None
        protocol = spec["protocol"].upper().rstrip("S")

        if not spec["tls"] and protocol in _STARTTLS_INDICATORS:
            try:
                if protocol == "SMTP":
                    writer.write(b"EHLO oxsium-probe.local\r\n")
                elif protocol == "IMAP":
                    writer.write(b". CAPABILITY\r\n")
                elif protocol == "POP3":
                    writer.write(b"CAPA\r\n")
                await writer.drain()
                response = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                indicator = _STARTTLS_INDICATORS[protocol]
                starttls = indicator in response.decode(errors="replace").lower()
            except Exception:
                starttls = False

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        return {"open": True, "banner": banner, "starttls": starttls, "error": None}

    async def _smtp_enumerate(self, mx_hosts: list[str]) -> dict:
        issues = []
        hosts_results = []

        for host in mx_hosts:
            result = await self._smtp_enum_host(host)
            hosts_results.append({"host": host, **result})

            for entry in result.get("commands", []):
                self._logger.finding(
                    "SMTP-ENUM",
                    f"{entry['cmd']}",
                    entry["response"].splitlines()[0][:80] if entry["response"] else "no response",
                    confidence=1.0,
                )

            if result.get("vrfy_enabled"):
                issues.append(
                    f"VRFY is enabled on {host} - allows user enumeration without authentication"
                )
            if result.get("expn_enabled"):
                issues.append(
                    f"EXPN is enabled on {host} - exposes mailing list membership"
                )

        return {"hosts": hosts_results, "issues": issues}

    async def _smtp_enum_host(self, host: str, timeout: float = 6.0) -> dict:
        commands_results = []
        vrfy_enabled = False
        expn_enabled = False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 25),
                timeout=timeout,
            )
        except Exception as exc:
            return {
                "connected": False,
                "error": str(exc),
                "commands": [],
                "vrfy_enabled": False,
                "expn_enabled": False,
            }

        async def send(data: bytes) -> str:
            try:
                writer.write(data)
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                return raw.decode(errors="replace").strip()
            except Exception:
                return ""

        try:
            raw_banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner_str = raw_banner.decode(errors="replace").strip()
            if banner_str[:3] in ("421", "521", "554"):
                writer.close()
                await writer.wait_closed()
                return {
                    "connected": False,
                    "error": banner_str.splitlines()[0][:80],
                    "commands": [],
                    "vrfy_enabled": False,
                    "expn_enabled": False,
                }
            await send(b"EHLO oxsium-probe.local\r\n")

            for spec in _SMTP_ENUM_COMMANDS:
                cmd_bytes = (spec["cmd"] + "\r\n").encode()

                if spec["cmd"].startswith("RCPT TO"):
                    await send(b"MAIL FROM:<>\r\n")

                response = await send(cmd_bytes)
                code = response[:3] if response else "???"

                commands_results.append({
                    "cmd":      spec["cmd"],
                    "key":      spec["key"],
                    "response": response,
                    "code":     code,
                })

                if spec["cmd"].startswith("VRFY") and code in ("250", "251"):
                    vrfy_enabled = True
                if spec["cmd"].startswith("EXPN") and code in ("250", "251"):
                    expn_enabled = True

                if spec["cmd"].startswith("RCPT TO"):
                    await send(b"RSET\r\n")

            await send(b"QUIT\r\n")
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return {
            "connected":    True,
            "error":        None,
            "commands":     commands_results,
            "vrfy_enabled": vrfy_enabled,
            "expn_enabled": expn_enabled,
        }

    async def _check_ehlo_helo(self, mx_hosts: list[str], timeout: float = 6.0) -> dict:
        issues = []
        hosts_results = []

        for host in mx_hosts:
            entry = {"host": host, "ehlo": None, "helo": None, "extensions": []}

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 25), timeout=timeout
                )
            except Exception as exc:
                entry["error"] = str(exc)
                hosts_results.append(entry)
                continue

            async def send(data: bytes) -> str:
                try:
                    writer.write(data)
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    return raw.decode(errors="replace").strip()
                except Exception:
                    return ""

            try:
                await asyncio.wait_for(reader.read(1024), timeout=timeout)

                ehlo_resp = await send(b"EHLO oxsium-probe.local\r\n")
                entry["ehlo"] = ehlo_resp
                extensions = [
                    line[4:].strip()
                    for line in ehlo_resp.splitlines()
                    if line.startswith("250-") or line.startswith("250 ")
                ][1:]
                entry["extensions"] = extensions

                self._logger.finding(
                    "EHLO",
                    host,
                    f"{len(extensions)} extensions advertised",
                    confidence=1.0,
                )

                await send(b"RSET\r\n")

                helo_resp = await send(b"HELO oxsium-probe.local\r\n")
                entry["helo"] = helo_resp
                helo_code = helo_resp[:3] if helo_resp else "???"
                self._logger.finding("HELO", host, f"code {helo_code}", confidence=1.0)

                if helo_code == "250":
                    issues.append(
                        f"HELO accepted on {host} - legacy unauthenticated handshake still permitted"
                    )

                sensitive = {"PIPELINING", "CHUNKING", "BDAT", "ETRN"}
                exposed = sensitive & {e.split()[0].upper() for e in extensions}
                if exposed:
                    issues.append(
                        f"{host} advertises potentially dangerous extensions via EHLO: {', '.join(sorted(exposed))}"
                    )

                await send(b"QUIT\r\n")
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            hosts_results.append(entry)

        return {"hosts": hosts_results, "issues": issues}

    async def _check_auth_mechanisms(self, mx_hosts: list[str], timeout: float = 6.0) -> dict:
        issues = []
        hosts_results = []

        for host in mx_hosts:
            entry = {
                "host":               host,
                "advertised":         [],
                "plain_text_allowed": False,
                "anonymous_allowed":  False,
            }

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 25), timeout=timeout
                )
            except Exception as exc:
                entry["error"] = str(exc)
                hosts_results.append(entry)
                continue

            async def send(data: bytes) -> str:
                try:
                    writer.write(data)
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    return raw.decode(errors="replace").strip()
                except Exception:
                    return ""

            try:
                await asyncio.wait_for(reader.read(1024), timeout=timeout)
                ehlo_resp = await send(b"EHLO oxsium-probe.local\r\n")

                advertised: list[str] = []
                for line in ehlo_resp.splitlines():
                    upper = line.upper()
                    if "AUTH" in upper:
                        parts = upper.split()
                        if "AUTH" in parts:
                            idx = parts.index("AUTH")
                            advertised = parts[idx + 1:]
                        elif parts and parts[0].lstrip("250-").lstrip("250 ") == "AUTH":
                            advertised = parts[1:]

                entry["advertised"] = advertised

                plain_text = {"PLAIN", "LOGIN"}
                exposed_plain = plain_text & set(advertised)
                if exposed_plain:
                    entry["plain_text_allowed"] = True
                    issues.append(
                        f"{host} advertises plain-text AUTH mechanisms without mandatory TLS: "
                        + ", ".join(sorted(exposed_plain))
                    )

                for mech in advertised:
                    self._logger.finding("AUTH", host, f"mechanism {mech}", confidence=1.0)

                anon_resp = await send(b"AUTH ANONYMOUS\r\n")
                anon_code = anon_resp[:3] if anon_resp else "???"
                if anon_code in ("334", "235"):
                    entry["anonymous_allowed"] = True
                    issues.append(f"{host} accepted AUTH ANONYMOUS - unauthenticated relay possible")
                    self._logger.finding("AUTH", host, "ANONYMOUS accepted", confidence=1.0)

                await send(b"QUIT\r\n")
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            hosts_results.append(entry)

        return {"hosts": hosts_results, "issues": issues}

    async def _check_open_relay(self, mx_hosts: list[str], timeout: float = 8.0) -> dict:
        issues = []
        hosts_results = []

        for host in mx_hosts:
            entry = {"host": host, "open_relay": False, "relay_response": None}

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 25), timeout=timeout
                )
            except Exception as exc:
                entry["error"] = str(exc)
                hosts_results.append(entry)
                continue

            async def send(data: bytes) -> str:
                try:
                    writer.write(data)
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                    return raw.decode(errors="replace").strip()
                except Exception:
                    return ""

            try:
                await asyncio.wait_for(reader.read(1024), timeout=timeout)
                await send(b"EHLO oxsium-probe.local\r\n")

                mail_resp = await send(
                    f"MAIL FROM:<{_OPEN_RELAY_EXTERNAL_FROM}>\r\n".encode()
                )
                mail_code = mail_resp[:3] if mail_resp else "???"

                if mail_code == "250":
                    rcpt_resp = await send(
                        f"RCPT TO:<{_OPEN_RELAY_EXTERNAL_RCPT}>\r\n".encode()
                    )
                    rcpt_code = rcpt_resp[:3] if rcpt_resp else "???"
                    entry["relay_response"] = rcpt_resp

                    if rcpt_code == "250":
                        entry["open_relay"] = True
                        issues.append(
                            f"{host} appears to be an open relay - accepted external MAIL FROM and external RCPT TO "
                            "without authentication"
                        )
                        self._logger.finding("OPEN-RELAY", host, "VULNERABLE", confidence=0.95)
                    else:
                        self._logger.finding("OPEN-RELAY", host, f"relay rejected ({rcpt_code})", confidence=0.9)

                    await send(b"RSET\r\n")
                else:
                    entry["relay_response"] = mail_resp
                    self._logger.finding("OPEN-RELAY", host, f"MAIL FROM rejected ({mail_code})", confidence=0.8)

                await send(b"QUIT\r\n")
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            hosts_results.append(entry)

        return {"hosts": hosts_results, "issues": issues}

    async def _check_starttls_downgrade(self, mx_hosts: list[str], timeout: float = 6.0) -> dict:
        issues = []
        hosts_results = []

        for host in mx_hosts:
            entry = {
                "host":              host,
                "starttls_offered":  False,
                "downgrade_possible": False,
                "plain_data_accepted": False,
            }

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 25), timeout=timeout
                )
            except Exception as exc:
                entry["error"] = str(exc)
                hosts_results.append(entry)
                continue

            async def send(data: bytes) -> str:
                try:
                    writer.write(data)
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    return raw.decode(errors="replace").strip()
                except Exception:
                    return ""

            try:
                await asyncio.wait_for(reader.read(1024), timeout=timeout)
                ehlo_resp = await send(b"EHLO oxsium-probe.local\r\n")

                starttls_offered = "starttls" in ehlo_resp.lower()
                entry["starttls_offered"] = starttls_offered

                if starttls_offered:
                    skip_resp = await send(b"MAIL FROM:<test@oxsium-probe.local>\r\n")
                    skip_code = skip_resp[:3] if skip_resp else "???"

                    if skip_code == "250":
                        entry["downgrade_possible"] = True
                        entry["plain_data_accepted"] = True
                        issues.append(
                            f"{host} offers STARTTLS but allows MAIL FROM before TLS negotiation - "
                            "STARTTLS downgrade / stripping attack is possible"
                        )
                        self._logger.finding(
                            "STARTTLS-DOWNGRADE", host, "VULNERABLE - plaintext accepted before TLS", confidence=0.95
                        )
                        await send(b"RSET\r\n")
                    else:
                        self._logger.finding(
                            "STARTTLS-DOWNGRADE", host, f"enforced - MAIL FROM rejected before TLS ({skip_code})", confidence=0.9
                        )
                else:
                    entry["downgrade_possible"] = True
                    issues.append(
                        f"{host} does not offer STARTTLS on port 25 - all traffic is unencrypted"
                    )
                    self._logger.finding("STARTTLS-DOWNGRADE", host, "STARTTLS not offered", confidence=1.0)

                await send(b"QUIT\r\n")
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            hosts_results.append(entry)

        return {"hosts": hosts_results, "issues": issues}

    async def _check_autodiscover(self, domain: str) -> dict:
        issues = []
        found_urls = []

        autodiscover_host = f"autodiscover.{domain}"
        a_records = await self._resolver.a(autodiscover_host)

        base_urls = []
        if a_records:
            base_urls.append(f"https://{autodiscover_host}")
        base_urls.append(f"https://{domain}")

        for base in base_urls:
            for path in _AUTODISCOVER_PATHS:
                url = base + path
                status = await self._requester.get_status(url)
                if status and status in (200, 401):
                    found_urls.append({"url": url, "status": status})
                    self._logger.finding(
                        "AUTODISCOVER",
                        "Endpoint",
                        f"found  {url}  [{status}]",
                        confidence=1.0,
                    )

        if not found_urls:
            issues.append("No Autodiscover endpoint found - Outlook/Exchange clients cannot auto-configure")
            self._logger.finding("AUTODISCOVER", "Endpoint", "not found", confidence=0.0)

        return {"available": bool(found_urls), "urls": found_urls, "issues": issues}

    async def _check_autoconfig(self, domain: str) -> dict:
        issues = []
        url = f"https://{domain}{_AUTOCONFIG_URL}"
        fallback = f"https://autoconfig.{domain}{_AUTOCONFIG_URL}"

        status = await self._requester.get_status(url)
        if status == 200:
            self._logger.finding("AUTOCONFIG", "Endpoint", f"found  {url}", confidence=1.0)
            return {"available": True, "url": url, "issues": issues}

        status = await self._requester.get_status(fallback)
        if status == 200:
            self._logger.finding("AUTOCONFIG", "Endpoint", f"found  {fallback}", confidence=1.0)
            return {"available": True, "url": fallback, "issues": issues}

        issues.append("No Thunderbird/ISPDB Autoconfig endpoint found - Mozilla clients cannot auto-configure")
        self._logger.finding("AUTOCONFIG", "Endpoint", "not found", confidence=0.0)
        return {"available": False, "url": None, "issues": issues}

    async def _check_catch_all(self, domain: str, mx_hosts: list[str]) -> dict:
        issues = []

        if not mx_hosts:
            return {"enabled": None, "issues": ["No MX hosts available for catch-all probe"]}

        probe_address = _CATCH_ALL_PROBE.format(domain=domain)
        host = mx_hosts[0]

        result = await self._requester.smtp_vrfy_catch_all(host, probe_address)

        if result is True:
            issues.append(
                f"Catch-all is enabled on {host} - accepts mail for any address, "
                "increases spam exposure and makes email harvesting easier"
            )
            self._logger.finding("CATCH-ALL", host, "enabled", confidence=0.9)
        elif result is False:
            self._logger.finding("CATCH-ALL", host, "disabled", confidence=0.9)
        else:
            issues.append(f"Catch-all probe inconclusive on {host} - SMTP RCPT TO check was not definitive")
            self._logger.finding("CATCH-ALL", host, "unknown", confidence=0.3)

        return {
            "enabled":       result,
            "probe_address": probe_address,
            "tested_host":   host,
            "issues":        issues,
        }