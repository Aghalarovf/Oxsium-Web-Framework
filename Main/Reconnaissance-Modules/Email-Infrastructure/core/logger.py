import sys

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORAMA = True
except ImportError:
    _COLORAMA = False

_RISK_COLORS = {
    "NONE":     "GREEN",
    "LOW":      "GREEN",
    "MEDIUM":   "YELLOW",
    "HIGH":     "RED",
    "CRITICAL": "RED",
}

_STRENGTH_COLORS = {
    "strong":   "GREEN",
    "adequate": "GREEN",
    "weak":     "YELLOW",
    "critical": "RED",
    "revoked":  "RED",
    "unknown":  "YELLOW",
}

_POLICY_COLORS = {
    "reject":      "GREEN",
    "quarantine":  "YELLOW",
    "none":        "RED",
    "enforce":     "GREEN",
    "testing":     "YELLOW",
    "missing":     "RED",
    "unreachable": "RED",
}


class Logger:

    BANNER = r"""
  _____                 _ _   _        __
 | ____|_ __ ___   __ _(_) | | |      / /__  ___  _   _ _ __
 |  _| | '_ ` _ \ / _` | | | | |     / / _ \/ _ \| | | | '__|
 | |___| | | | | | (_| | | | | |___ / /  __/ (_) | |_| | |
 |_____|_| |_| |_|\__,_|_|_| |_____/_/ \___|\___/ \__,_|_|
"""

    def __init__(self, color: bool = True) -> None:
        self._color = color and _COLORAMA

    def _c(self, text: str, fore_name: str) -> str:
        if not self._color:
            return text
        code = getattr(Fore, fore_name, "")
        return f"{code}{text}{Style.RESET_ALL}"

    def _dim(self, text: str) -> str:
        if not self._color:
            return text
        return f"{Style.DIM}{text}{Style.RESET_ALL}"

    def _bold(self, text: str) -> str:
        if not self._color:
            return text
        return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"

    def _label(self, text: str) -> str:
        return self._c(text, "CYAN")

    def _ok(self, text: str) -> str:
        return self._c(text, "GREEN")

    def _warn(self, text: str) -> str:
        return self._c(text, "YELLOW")

    def _err(self, text: str) -> str:
        return self._c(text, "RED")

    def _risk_color(self, level: str) -> str:
        return _RISK_COLORS.get(level.upper(), "WHITE")

    def banner(self) -> None:
        print(self._c(self.BANNER, "CYAN"))

    def info(self, msg: str) -> None:
        pass

    def success(self, msg: str) -> None:
        print(f"  {self._ok('✓')}  {msg}")

    def warning(self, msg: str) -> None:
        pass

    def error(self, msg: str) -> None:
        print(f"  {self._err('✗')}  {msg}", file=sys.stderr)

    def debug(self, msg: str) -> None:
        pass

    def section(self, title: str) -> None:
        pass

    def finding(self, category: str, key: str, value: str, confidence: float = 1.0) -> None:
        pass

    def table(self, headers: list[str], rows: list[list[str]]) -> None:
        pass

    def spinner_start(self, msg: str) -> None:
        pass

    def spinner_stop(self) -> None:
        pass

    def report(self, results: dict) -> None:
        sep = "─" * 52
        for domain, modules in results.items():
            print(f"\n{self._dim(sep)}")
            print(f"  {self._bold('RESULTS')}  {self._dim('·')}  {domain.upper()}")
            print(f"{self._dim(sep)}")
            for module_name, data in modules.items():
                if module_name == "dns_hardening":
                    continue
                if isinstance(data, dict) and "error" in data:
                    print(f"\n  {self._err('✗')}  {module_name}  {data['error']}")
                    continue
                renderer = _MODULE_RENDERERS.get(module_name)
                if renderer:
                    renderer(self, module_name, data)
                else:
                    self._render_generic(module_name, data)

    def _section_header(self, title: str) -> None:
        print(f"\n  {self._bold(title)}")

    def _issue(self, text: str) -> None:
        print(f"    {self._warn('▸')}  {text}")

    def _row(self, label: str, value: str, color: str = "") -> None:
        val = self._c(value, color) if color else value
        print(f"    {self._dim(label + ':')}  {val}")

    def _render_dns_sec(self, module_name: str, data: dict) -> None:
        self._section_header("DNS Security")

        mx = data.get("mx_records", [])
        if mx:
            hosts = "  ".join(f"{r['host']} [{r['priority']}]" for r in mx)
            self._row("MX", hosts, "")
        else:
            self._row("MX", "no records found", "RED")

        spf = data.get("spf", {})
        if spf.get("record"):
            record = spf["record"]
            truncated = record[:70] + "…" if len(record) > 70 else record
            all_q = spf.get("all_qualifier") or "?"
            color = "GREEN" if all_q == "fail" else "YELLOW" if all_q == "softfail" else "RED"
            self._row("SPF", f"{truncated}")
            self._row("SPF qualifier", all_q, color)
            self._row("SPF lookups", str(spf.get("include_count", 0)))
        else:
            self._row("SPF", "not found", "RED")

        dkim = data.get("dkim", {})
        selectors = dkim.get("found_selectors", [])
        if selectors:
            self._row("DKIM selectors", f"{', '.join(selectors)} ({len(selectors)} found)", "GREEN")
        else:
            self._row("DKIM selectors", "none found", "RED")

        dmarc = data.get("dmarc", {})
        policy = dmarc.get("policy") or "not found"
        color = "GREEN" if policy == "reject" else "YELLOW" if policy == "quarantine" else "RED"
        self._row("DMARC policy", policy, color)
        if dmarc.get("subdomain_policy") and dmarc["subdomain_policy"] != policy:
            self._row("DMARC subdomain", dmarc["subdomain_policy"])
        if dmarc.get("pct") is not None and dmarc["pct"] < 100:
            self._row("DMARC pct", f"{dmarc['pct']}%", "YELLOW")

        risk = data.get("spoofing_risk", {})
        if risk:
            score = risk.get("score", 0)
            level = risk.get("level", "")
            color = self._risk_color(level)
            print()
            self._row("Spoofing risk", f"{score}/100  {level}", color)

        mta = data.get("mta_sts", {})
        mode = mta.get("mode") or "missing"
        color = _POLICY_COLORS.get(mode, "RED")
        self._row("MTA-STS", mode, color)

        dkim_ks = data.get("dkim_key_strength", {})
        for selector, info in (dkim_ks.get("selectors") or {}).items():
            bits = info.get("key_bits")
            key_type = (info.get("key_type") or "rsa").upper()
            strength = info.get("strength", "unknown")
            color = _STRENGTH_COLORS.get(strength, "WHITE")
            bits_str = f"{bits}b" if bits else "?"
            revoked = "  revoked" if info.get("revoked") else ""
            self._row(f"DKIM key [{selector}]", f"{key_type} {bits_str}  {strength}{revoked}", color)

        spf_depth = data.get("spf_lookup_depth", {})
        count = spf_depth.get("effective_lookup_count", 0)
        exceeded = spf_depth.get("exceeded", False)
        self._row("SPF lookups (effective)", f"{count}/10", "RED" if exceeded else "GREEN")

        takeover = data.get("subdomain_takeover", {})
        for host_info in (takeover.get("mx_hosts") or []):
            risk = host_info.get("takeover_risk", "none")
            host = host_info.get("host", "")
            color = "RED" if risk == "high" else "YELLOW" if risk == "medium" else "GREEN"
            self._row(f"Takeover [{host}]", risk, color)

        bimi = data.get("bimi", {})
        if bimi.get("record"):
            has_vmc = bool(bimi.get("vmc_url"))
            logo = bool(bimi.get("logo_url"))
            status = "configured" + (" + VMC" if has_vmc else " (no VMC)") + ("" if logo else " (no logo)")
            self._row("BIMI", status, "GREEN" if has_vmc and logo else "YELLOW")
        else:
            self._row("BIMI", "not configured", "YELLOW")

        caa = data.get("caa", {})
        issuers = caa.get("issuers", [])
        if issuers:
            self._row("CAA issuers", ", ".join(issuers), "GREEN")
            self._row("CAA iodef", ", ".join(caa.get("iodef", [])) if caa.get("iodef") else "not configured",
                      "GREEN" if caa.get("iodef") else "YELLOW")
        else:
            self._row("CAA issuers", "not configured", "RED")
            self._row("CAA iodef", "not configured", "RED")

        null_mx = data.get("null_mx", {})
        if null_mx.get("applicable"):
            present = null_mx.get("null_mx_present", False)
            self._row("Null MX (RFC 7505)", "present" if present else "missing",
                      "GREEN" if present else "RED")
        else:
            self._row("Null MX (RFC 7505)", "n/a (MX records exist)", "")

        dane = data.get("dane", {})
        mx_dane = dane.get("mx_dane") or []
        if mx_dane:
            for host_info in mx_dane:
                host = host_info.get("host", "")
                enabled = host_info.get("dane_enabled", False)
                record_count = len(host_info.get("records", []))
                label = f"{record_count} TLSA record(s)" if enabled else "no TLSA"
                self._row(f"DANE [{host}]", label, "GREEN" if enabled else "YELLOW")
        else:
            self._row("DANE", "no MX hosts to check", "YELLOW")

        all_issues = (
            spf.get("issues", []) +
            dkim.get("issues", []) +
            dmarc.get("issues", []) +
            mta.get("issues", []) +
            dkim_ks.get("issues", []) +
            spf_depth.get("issues", []) +
            takeover.get("issues", []) +
            bimi.get("issues", []) +
            caa.get("issues", []) +
            null_mx.get("issues", []) +
            dane.get("issues", [])
        )
        if all_issues:
            print(f"\n    {self._dim('issues')}")
            for issue in all_issues:
                self._issue(issue)

    def _render_dns_hardening(self, module_name: str, data: dict) -> None:
        self._section_header("DNS Hardening")

        mta = data.get("mta_sts", {})
        mode = mta.get("mode") or "missing"
        color = _POLICY_COLORS.get(mode, "RED")
        self._row("MTA-STS", mode, color)

        dkim_ks = data.get("dkim_key_strength", {})
        for selector, info in (dkim_ks.get("selectors") or {}).items():
            bits = info.get("key_bits")
            key_type = (info.get("key_type") or "rsa").upper()
            strength = info.get("strength", "unknown")
            color = _STRENGTH_COLORS.get(strength, "WHITE")
            bits_str = f"{bits}b" if bits else "?"
            revoked = "  revoked" if info.get("revoked") else ""
            self._row(f"DKIM [{selector}]", f"{key_type} {bits_str}  {strength}{revoked}", color)

        spf_depth = data.get("spf_lookup_depth", {})
        count = spf_depth.get("effective_lookup_count", 0)
        exceeded = spf_depth.get("exceeded", False)
        color = "RED" if exceeded else "GREEN"
        self._row("SPF lookups (effective)", f"{count}/10", color)

        takeover = data.get("subdomain_takeover", {})
        mx_hosts_takeover = takeover.get("mx_hosts") or []
        if mx_hosts_takeover:
            for host_info in mx_hosts_takeover:
                risk = host_info.get("takeover_risk", "none")
                host = host_info.get("host", "")
                color = "RED" if risk == "high" else "YELLOW" if risk == "medium" else "GREEN"
                self._row(f"Takeover [{host}]", risk, color)
        else:
            self._row("Takeover", "no MX hosts", "YELLOW")

        bimi = data.get("bimi", {})
        if bimi.get("record"):
            has_vmc = bool(bimi.get("vmc_url"))
            logo = bool(bimi.get("logo_url"))
            status = "configured"
            status += " + VMC" if has_vmc else " (no VMC)"
            status += "" if logo else " (no logo)"
            self._row("BIMI", status, "GREEN" if has_vmc and logo else "YELLOW")
        else:
            self._row("BIMI", "not configured", "YELLOW")

        caa = data.get("caa", {})
        issuers = caa.get("issuers", [])
        if issuers:
            self._row("CAA issuers", ", ".join(issuers), "GREEN")
            self._row("CAA iodef", ", ".join(caa.get("iodef", [])) if caa.get("iodef") else "not configured",
                      "GREEN" if caa.get("iodef") else "YELLOW")
        else:
            self._row("CAA issuers", "not configured", "RED")
            self._row("CAA iodef", "not configured", "RED")

        null_mx = data.get("null_mx", {})
        if null_mx.get("applicable"):
            present = null_mx.get("null_mx_present", False)
            self._row("Null MX (RFC 7505)", "present" if present else "missing",
                      "GREEN" if present else "RED")
        else:
            self._row("Null MX (RFC 7505)", "n/a (MX records exist)", "")

        dane = data.get("dane", {})
        mx_dane = dane.get("mx_dane") or []
        if mx_dane:
            for host_info in mx_dane:
                host = host_info.get("host", "")
                enabled = host_info.get("dane_enabled", False)
                record_count = len(host_info.get("records", []))
                label = f"{record_count} TLSA record(s)" if enabled else "no TLSA"
                self._row(f"DANE [{host}]", label, "GREEN" if enabled else "YELLOW")
        else:
            self._row("DANE", "no MX hosts to check", "YELLOW")

        all_issues = []
        for key in ("mta_sts", "dkim_key_strength", "spf_lookup_depth",
                    "subdomain_takeover", "bimi", "caa", "null_mx", "dane"):
            section = data.get(key, {})
            all_issues.extend(section.get("issues", []))

        if all_issues:
            print(f"\n    {self._dim('issues')}")
            for issue in all_issues:
                self._issue(issue)

    def _render_service_config(self, module_name: str, data: dict) -> None:
        self._section_header("Service Configuration")

        port_scan = data.get("port_scan", {})
        for host_entry in (port_scan.get("hosts") or []):
            host = host_entry.get("host", "")
            print(f"\n    {self._dim(host)}")
            for p in host_entry.get("ports", []):
                label = p.get("label", "")
                port = p.get("port", "")
                open_ = p.get("open", False)
                starttls = p.get("starttls")
                banner = p.get("banner", "")

                state_color = "GREEN" if open_ else "RED"
                state = self._c("open" if open_ else "closed", state_color)

                suffix = ""
                if open_ and starttls is True:
                    suffix = f"  {self._c('STARTTLS', 'GREEN')}"
                elif open_ and starttls is False:
                    suffix = f"  {self._c('no STARTTLS', 'YELLOW')}"

                banner_str = ""
                if open_ and banner:
                    trimmed = banner[:60] + "…" if len(banner) > 60 else banner
                    banner_str = f"  {self._dim(trimmed)}"

                print(f"    {self._label(label)}  {self._dim(str(port))}  {state}{suffix}{banner_str}")

        autodiscover = data.get("autodiscover", {})
        if autodiscover.get("available"):
            for entry in autodiscover.get("urls", []):
                url = entry.get("url", "")
                status = entry.get("status", "")
                self._row("Autodiscover", f"{url}  [{status}]", "GREEN")
        else:
            self._row("Autodiscover", "not found", "YELLOW")

        autoconfig = data.get("autoconfig", {})
        if autoconfig.get("available"):
            self._row("Autoconfig", autoconfig.get("url", ""), "GREEN")
        else:
            self._row("Autoconfig", "not found", "YELLOW")

        smtp_enum = data.get("smtp_enum", {})
        smtp_hosts = smtp_enum.get("hosts", [])
        if smtp_hosts:
            print(f"\n    {self._dim('SMTP User Enumeration')}")
            for host_entry in smtp_hosts:
                host = host_entry.get("host", "")
                connected = host_entry.get("connected", False)
                if not connected:
                    err = host_entry.get("error", "connection failed")
                    print(f"      {self._dim(host)}  {self._c('unreachable', 'RED')}  {self._dim(err)}")
                    continue

                print(f"      {self._dim(host)}")
                for cmd_entry in host_entry.get("commands", []):
                    cmd = cmd_entry.get("cmd", "")
                    code = cmd_entry.get("code", "???")
                    response_first = ""
                    if cmd_entry.get("response"):
                        response_first = cmd_entry["response"].splitlines()[0][:60]
                        if len(cmd_entry["response"].splitlines()[0]) > 60:
                            response_first += "…"

                    if code in ("250", "251", "252"):
                        code_colored = self._c(code, "RED")
                    elif code in ("550", "551", "553"):
                        code_colored = self._c(code, "GREEN")
                    else:
                        code_colored = self._c(code, "YELLOW")

                    print(f"        {self._label(cmd):<30}  {code_colored}  {self._dim(response_first)}")

                vrfy = host_entry.get("vrfy_enabled", False)
                expn = host_entry.get("expn_enabled", False)
                print(f"        {self._dim('VRFY enabled:')}  {self._c('yes', 'RED') if vrfy else self._c('no', 'GREEN')}"
                      f"    {self._dim('EXPN enabled:')}  {self._c('yes', 'RED') if expn else self._c('no', 'GREEN')}")

        catch_all = data.get("catch_all", {})
        enabled = catch_all.get("enabled")
        host = catch_all.get("tested_host", "")
        if enabled is True:
            self._row(f"Catch-all [{host}]", "enabled", "RED")
        elif enabled is False:
            self._row(f"Catch-all [{host}]", "disabled", "GREEN")
        else:
            self._row(f"Catch-all [{host}]", "unknown", "YELLOW")

        # ── EHLO / HELO ──────────────────────────────────────────────
        ehlo_helo = data.get("ehlo_helo", {})
        ehlo_hosts = ehlo_helo.get("hosts", [])
        if ehlo_hosts:
            print(f"\n    {self._dim('EHLO / HELO')}")
            for entry in ehlo_hosts:
                h = entry.get("host", "")
                err = entry.get("error")
                if err:
                    print(f"      {self._dim(h)}  {self._c('unreachable', 'RED')}  {self._dim(err)}")
                    continue
                print(f"      {self._dim(h)}")
                extensions = entry.get("extensions", [])
                if extensions:
                    ext_str = "  ".join(extensions)
                    print(f"        {self._dim('extensions:')}  {ext_str}")
                else:
                    print(f"        {self._dim('extensions:')}  {self._c('none', 'YELLOW')}")

                helo_resp = entry.get("helo") or ""
                helo_code = helo_resp[:3] if helo_resp else "???"
                helo_color = "RED" if helo_code == "250" else "GREEN"
                helo_label = "accepted" if helo_code == "250" else f"rejected ({helo_code})"
                print(f"        {self._dim('HELO:')}  {self._c(helo_label, helo_color)}")

        # ── AUTH mechanisms ───────────────────────────────────────────
        auth_data = data.get("auth_mechanisms", {})
        auth_hosts = auth_data.get("hosts", [])
        if auth_hosts:
            print(f"\n    {self._dim('AUTH Mechanisms')}")
            plain_text_mechs = {"PLAIN", "LOGIN"}
            for entry in auth_hosts:
                h = entry.get("host", "")
                err = entry.get("error")
                if err:
                    print(f"      {self._dim(h)}  {self._c('unreachable', 'RED')}  {self._dim(err)}")
                    continue
                print(f"      {self._dim(h)}")
                advertised = entry.get("advertised", [])
                if advertised:
                    for mech in advertised:
                        color = "RED" if mech in plain_text_mechs else "GREEN"
                        print(f"        {self._label(mech):<20}  {self._c('plain-text', 'RED') if mech in plain_text_mechs else self._c('ok', 'GREEN')}")
                else:
                    print(f"        {self._dim('no AUTH mechanisms advertised')}")

                if entry.get("anonymous_allowed"):
                    print(f"        {self._c('AUTH ANONYMOUS accepted', 'RED')}")

        # ── Open Relay ────────────────────────────────────────────────
        relay_data = data.get("open_relay", {})
        relay_hosts = relay_data.get("hosts", [])
        if relay_hosts:
            print(f"\n    {self._dim('Open Relay')}")
            for entry in relay_hosts:
                h = entry.get("host", "")
                err = entry.get("error")
                if err:
                    print(f"      {self._dim(h)}  {self._c('unreachable', 'RED')}  {self._dim(err)}")
                    continue
                is_relay = entry.get("open_relay", False)
                relay_label = "VULNERABLE" if is_relay else "not relaying"
                relay_color = "RED" if is_relay else "GREEN"
                relay_resp = entry.get("relay_response") or ""
                relay_resp_trimmed = relay_resp.splitlines()[0][:60] if relay_resp else ""
                print(f"      {self._dim(h)}  {self._c(relay_label, relay_color)}"
                      + (f"  {self._dim(relay_resp_trimmed)}" if relay_resp_trimmed else ""))

        # ── STARTTLS Downgrade ────────────────────────────────────────
        starttls_dg = data.get("starttls_downgrade", {})
        starttls_hosts = starttls_dg.get("hosts", [])
        if starttls_hosts:
            print(f"\n    {self._dim('STARTTLS Downgrade')}")
            for entry in starttls_hosts:
                h = entry.get("host", "")
                err = entry.get("error")
                if err:
                    print(f"      {self._dim(h)}  {self._c('unreachable', 'RED')}  {self._dim(err)}")
                    continue
                offered = entry.get("starttls_offered", False)
                downgrade = entry.get("downgrade_possible", False)
                plain_accepted = entry.get("plain_data_accepted", False)

                if not offered:
                    status = "not offered — all traffic plaintext"
                    color = "RED"
                elif plain_accepted:
                    status = "VULNERABLE — plaintext accepted before TLS"
                    color = "RED"
                else:
                    status = "enforced"
                    color = "GREEN"

                offered_str = self._c("offered", "GREEN") if offered else self._c("not offered", "RED")
                print(f"      {self._dim(h)}  STARTTLS {offered_str}  {self._c(status, color)}")

        all_issues = (
            port_scan.get("issues", []) +
            smtp_enum.get("issues", []) +
            autodiscover.get("issues", []) +
            autoconfig.get("issues", []) +
            catch_all.get("issues", []) +
            ehlo_helo.get("issues", []) +
            auth_data.get("issues", []) +
            relay_data.get("issues", []) +
            starttls_dg.get("issues", [])
        )
        if all_issues:
            print(f"\n    {self._dim('issues')}")
            for issue in all_issues:
                self._issue(issue)

    def _render_harvest_recon(self, module_name: str, data: dict) -> None:
        self._section_header("Harvest Recon")

        # ── Harvested emails ─────────────────────────────────────────
        harvested = data.get("harvested_emails", [])
        print(f"\n    {self._dim('Harvested Emails')}  ({len(harvested)})")
        if harvested:
            for email in harvested:
                print(f"      {self._ok('·')}  {email}")
        else:
            print(f"      {self._dim('none found')}")

        # ── Email format patterns ─────────────────────────────────────
        fmt = data.get("email_format_patterns", {})
        patterns = fmt.get("detected_patterns", [])
        if patterns:
            print(f"\n    {self._dim('Email Format Patterns')}")
            for p in patterns:
                conf = p.get('confidence', 0)
                color = "GREEN" if conf >= 0.6 else "YELLOW" if conf >= 0.4 else "WHITE"
                print(
                    f"      {self._label(p.get('pattern', ''))}  "
                    f"template: {self._bold(p.get('template', ''))}  "
                    f"freq: {p.get('frequency', '')}  "
                    f"confidence: {self._c(str(conf), color)}"
                )

        # ── Conventional / guessed emails ─────────────────────────────
        conventional = data.get("conventional_emails", [])
        if conventional:
            print(f"\n    {self._dim('Conventional / Guessed Emails')}  ({len(conventional)})")
            for entry in conventional:
                addr = entry.get("address", "")
                conf = entry.get("confidence", 0)
                status = entry.get("status", "")
                color = "YELLOW" if status == "guessed" else "GREEN"
                print(f"      {self._c('·', color)}  {addr}  {self._dim(f'[{status}  conf:{conf}]')}")

        # ── Social patterns ───────────────────────────────────────────
        social = data.get("social_patterns", {})
        if social:
            print(f"\n    {self._dim('Social Patterns')}")
            linkedin = social.get("linkedin_found", False)
            github   = social.get("github_found", False)
            print(f"      LinkedIn: {self._c('found', 'GREEN') if linkedin else self._c('not found', 'YELLOW')}"
                  f"    GitHub: {self._c('found', 'GREEN') if github else self._c('not found', 'YELLOW')}")
            for pat in social.get("patterns", []):
                if pat:
                    print(f"      {self._dim('·')}  {pat}")

        # ── Breach findings grouped by source ────────────────────────
        findings = data.get("breach_findings", [])
        if findings:
            from collections import defaultdict
            by_source: dict = defaultdict(list)
            for f in findings:
                by_source[f.get("source", "unknown")].append(f)

            SOURCE_ORDER = [
                "proxynova_domain", "proxynova",
                "scylla_domain", "scylla_email",
                "leakcheck_domain", "leakcheck_email",
                "hibp_breach", "hibp_paste",
                "credential_pattern",
                "dehashed",
                "dork_hint",
            ]
            ordered_sources = [s for s in SOURCE_ORDER if s in by_source]
            for s in by_source:
                if s not in ordered_sources:
                    ordered_sources.append(s)

            SOURCE_LABELS = {
                "proxynova_domain":  "ProxyNova  (domain)",
                "proxynova":         "ProxyNova  (email)",
                "scylla_domain":     "Scylla  (domain)",
                "scylla_email":      "Scylla  (email)",
                "leakcheck_domain":  "LeakCheck  (domain)",
                "leakcheck_email":   "LeakCheck  (email)",
                "hibp_breach":       "HIBP  (breach)",
                "hibp_paste":        "HIBP  (paste)",
                "credential_pattern":"Credential Scan",
                "dehashed":          "DeHashed",
                "dork_hint":         "Dork Hints",
            }

            print(f"\n    {self._dim('Breach Findings')}")
            for src in ordered_sources:
                items = by_source[src]
                label = SOURCE_LABELS.get(src, src)
                sev_sample = items[0].get("severity", "info").upper()
                sev_color  = "RED" if sev_sample == "CRITICAL" else \
                             "YELLOW" if sev_sample == "HIGH" else \
                             "CYAN"  if sev_sample == "INFO" else "WHITE"
                print(f"\n      {self._bold(label)}  "
                      f"{self._c(f'[{sev_sample}]', sev_color)}  "
                      f"{self._dim(f'({len(items)} result(s))')}")
                print(f"      {'─' * 56}")

                for item in items:
                    if src == "dork_hint":
                        print(f"        {self._dim('dork:')}  {item.get('dork', '')}")
                    else:
                        email = item.get("email", "")
                        combo = item.get("combo_line", "")
                        breach = item.get("breach_name", "")
                        pw_hash = item.get("password_hash", "")
                        cred_hint = item.get("credential_hint", "")

                        line = f"        {self._ok('·')}  {email}"
                        if combo:
                            line += f"  {self._dim('combo:')}  {self._c(combo, 'YELLOW')}"
                        if breach:
                            line += f"  {self._dim('breach:')}  {breach}"
                        if pw_hash:
                            line += f"  {self._dim('hash:')}  {self._c(pw_hash[:40] + ('…' if len(pw_hash) > 40 else ''), 'RED')}"
                        if cred_hint:
                            line += f"  {self._dim('hint:')}  {self._c(cred_hint[:60], 'RED')}"
                        print(line)
        else:
            print(f"\n    {self._dim('Breach Findings')}  {self._dim('none')}")

    def _render_generic(self, module_name: str, data: dict) -> None:
        self._section_header(module_name.replace("_", " ").title())
        self._render_generic_value(data, indent=4)

    def _render_generic_value(self, value, indent: int) -> None:
        prefix = " " * indent
        if isinstance(value, dict):
            for k, v in value.items():
                label = k.replace("_", " ")
                if isinstance(v, (dict, list)):
                    print(f"{prefix}{self._dim(label + ':')}")
                    self._render_generic_value(v, indent + 2)
                else:
                    print(f"{prefix}{self._dim(label + ':')}  {v}")
        elif isinstance(value, list):
            if not value:
                print(f"{prefix}{self._dim('—')}")
            for item in value:
                if isinstance(item, dict):
                    self._render_generic_value(item, indent)
                    print()
                else:
                    print(f"{prefix}{self._dim('·')}  {item}")
        else:
            print(f"{prefix}{value}")


_MODULE_RENDERERS = {
    "dns_sec":        Logger._render_dns_sec,
    "dns_hardening":  Logger._render_dns_hardening,
    "service_config": Logger._render_service_config,
    "harvest_recon":  Logger._render_harvest_recon,
}