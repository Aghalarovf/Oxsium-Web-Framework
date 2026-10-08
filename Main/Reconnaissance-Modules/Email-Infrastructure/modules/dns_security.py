import asyncio
import base64
import re
import struct
from typing import Optional

from cryptography.hazmat.primitives import serialization

from .base import BaseEmailModule


_WEAK_RSA_BITS = 1024
_MINIMUM_RSA_BITS = 2048

_KNOWN_DANGLING_PROVIDERS = [
    "sendgrid.net", "mailgun.org", "mailjet.com", "sparkpostmail.com",
    "amazonses.com", "smtp.com", "postmarkapp.com", "mandrillapp.com",
    "mimecast.com", "proofpoint.com", "messagelabs.com",
]

_SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "exists", "redirect", "ptr"}

COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "dkim",
    "mail", "smtp", "s1", "s2",
]


class DNSHardeningModule(BaseEmailModule):

    async def run(self, domain: str) -> dict:
        mx_records = await self._resolver.mx(domain)
        mx_hosts = [r["host"] for r in (mx_records or [])]

        results = await asyncio.gather(
            self.check_mta_sts(domain),
            self.check_dkim_key_strength(domain),
            self.check_spf_lookup_depth(domain),
            self.check_subdomain_takeover(mx_hosts),
            self.check_bimi(domain),
            self.check_caa(domain),
            self.check_null_mx(domain, mx_hosts),
            self.check_dane(mx_hosts),
            return_exceptions=True,
        )

        keys = [
            "mta_sts", "dkim_key_strength", "spf_lookup_depth",
            "subdomain_takeover", "bimi", "caa", "null_mx", "dane",
        ]

        output = {}
        for key, result in zip(keys, results):
            if isinstance(result, Exception):
                output[key] = {"error": str(result)}
            else:
                output[key] = result

        return output

    async def check_mta_sts(self, domain: str) -> dict:
        txt = await self._resolver.txt(f"_mta-sts.{domain}")
        issues = []

        if not txt:
            issues.append("No MTA-STS TXT record found - TLS downgrade attacks possible")
            self._logger.finding("MTA-STS", "Policy", "missing", confidence=0.0)
            return {
                "txt_record": None,
                "policy_file": None,
                "mode": None,
                "mx_covered": [],
                "max_age": None,
                "issues": issues,
            }

        sts_record = next((r for r in txt if "v=STSv1" in r), None)
        if not sts_record:
            issues.append("MTA-STS TXT record present but malformed - missing v=STSv1")
            self._logger.finding("MTA-STS", "Policy", "malformed", confidence=0.3)
            return {
                "txt_record": txt,
                "policy_file": None,
                "mode": None,
                "mx_covered": [],
                "max_age": None,
                "issues": issues,
            }

        policy = await self._fetch_mta_sts_policy(domain)
        mode = None
        mx_covered = []
        max_age = None

        if policy:
            tags = {}
            for line in policy.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    tags[k.strip()] = v.strip()

            mode = tags.get("mode")
            max_age = int(tags.get("max_age", 0))
            mx_covered = [v for k, v in tags.items() if k == "mx"]

            if mode == "none":
                issues.append("MTA-STS mode is 'none' - policy exists but offers no protection")
            elif mode == "testing":
                issues.append("MTA-STS mode is 'testing' - upgrade to 'enforce' for active protection")
            if max_age and max_age < 86400:
                issues.append(f"MTA-STS max_age is very low ({max_age}s) - reduces caching effectiveness")
        else:
            issues.append("MTA-STS policy file not reachable at https://mta-sts." + domain + "/.well-known/mta-sts.txt")

        self._logger.finding("MTA-STS", "Mode", mode or "unreachable", confidence=1.0 if mode == "enforce" else 0.5)
        return {
            "txt_record": sts_record,
            "policy_file": policy,
            "mode": mode,
            "mx_covered": mx_covered,
            "max_age": max_age,
            "issues": issues,
        }

    async def _fetch_mta_sts_policy(self, domain: str) -> Optional[str]:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            return await self._requester.get_text(url)
        except Exception:
            return None

    async def check_dkim_key_strength(self, domain: str) -> dict:
        from modules.dns_security import COMMON_DKIM_SELECTORS
        found = await self._resolver.probe_dkim_selectors(domain, COMMON_DKIM_SELECTORS)

        results = {}
        issues = []

        for selector, record in found.items():
            tags = {}
            for part in re.split(r";\s*", record.strip().strip('"')):
                if "=" in part:
                    k, _, v = part.partition("=")
                    tags[k.strip()] = v.strip()

            key_type = tags.get("k", "rsa").lower()
            p = tags.get("p", "")

            if not p:
                issues.append(f"Selector '{selector}' has empty p= tag - key is revoked")
                self._logger.finding("DKIM-KEY", f"[{selector}]", "revoked", confidence=1.0)
                results[selector] = {
                    "key_type": key_type,
                    "revoked": True,
                    "key_bits": None,
                    "strength": "revoked",
                }
                continue

            key_bits = None
            strength = "unknown"

            if key_type == "rsa":
                key_bits = self._estimate_rsa_bits(p)
                if key_bits:
                    if key_bits < _WEAK_RSA_BITS:
                        strength = "critical"
                        issues.append(f"Selector '{selector}' uses {key_bits}-bit RSA - critically weak, rotate immediately")
                    elif key_bits < _MINIMUM_RSA_BITS:
                        strength = "weak"
                        issues.append(f"Selector '{selector}' uses {key_bits}-bit RSA - below 2048-bit minimum")
                    else:
                        strength = "adequate"
            elif key_type == "ed25519":
                strength = "strong"
                key_bits = 256

            self._logger.finding(
                "DKIM-KEY",
                f"[{selector}]",
                f"{key_type.upper()} {key_bits or '?'}b [{strength}]",
                confidence=1.0 if strength in ("adequate", "strong") else 0.3,
            )
            results[selector] = {
                "key_type": key_type,
                "revoked": False,
                "key_bits": key_bits,
                "strength": strength,
            }

        return {
            "selectors": results,
            "issues": issues,
        }

    def _estimate_rsa_bits(self, b64_p: str) -> Optional[int]:
        try:
            padded = b64_p + "=" * (-len(b64_p) % 4)
            der = base64.b64decode(padded)
            public_key = serialization.load_der_public_key(der)
            return getattr(public_key, "key_size", None)
        except Exception:
            return None

    async def check_spf_lookup_depth(self, domain: str) -> dict:
        visited: set[str] = set()
        issues: list[str] = []

        total_lookups, tree = await self._count_spf_lookups(domain, visited, issues, depth=0)

        self._logger.finding(
            "SPF-DEPTH",
            "Lookups",
            f"{total_lookups}/10",
            confidence=1.0 if total_lookups <= 10 else 0.2,
        )

        return {
            "effective_lookup_count": total_lookups,
            "limit": 10,
            "exceeded": total_lookups > 10,
            "tree": tree,
            "issues": issues,
        }

    async def _count_spf_lookups(
        self,
        domain: str,
        visited: set[str],
        issues: list[str],
        depth: int,
    ) -> tuple[int, dict]:
        if domain in visited or depth > 12:
            return 0, {}
        visited.add(domain)

        raw = await self._resolver.spf(domain)
        if not raw:
            return 0, {}

        count = 0
        tree: dict = {}

        for token in raw.split()[1:]:
            value = token.lstrip("+-~?")
            if ":" in value:
                mech, param = value.split(":", 1)
            else:
                mech, param = value, domain

            if mech not in _SPF_LOOKUP_MECHANISMS:
                continue

            count += 1

            if mech in ("include", "redirect"):
                sub_count, sub_tree = await self._count_spf_lookups(param, visited, issues, depth + 1)
                count += sub_count
                tree[f"{mech}:{param}"] = sub_tree
            else:
                tree[f"{mech}:{param}"] = {}

        if count > 10 and depth == 0:
            issues.append(
                f"SPF effective lookup count is {count} (limit is 10) - "
                "receiving servers may reject or skip SPF evaluation"
            )

        return count, tree

    async def check_subdomain_takeover(self, mx_hosts: list[str]) -> dict:
        issues = []
        results = []

        for host in mx_hosts:
            host = host.rstrip(".")
            a_records = await self._resolver.a(host)
            reachable = await self._requester.is_reachable_smtp(host) if a_records else False

            provider = next(
                (p for p in _KNOWN_DANGLING_PROVIDERS if host.endswith(p)),
                None,
            )

            risk = "none"
            if not a_records:
                risk = "high"
                issues.append(f"MX host '{host}' has no A record - dangling DNS, potential takeover")
            elif not reachable and provider:
                risk = "medium"
                issues.append(f"MX host '{host}' resolves but SMTP unreachable - possible abandoned provider record")
            elif provider:
                risk = "low"

            entry = {
                "host": host,
                "a_records": a_records,
                "smtp_reachable": reachable,
                "known_provider": provider,
                "takeover_risk": risk,
            }

            self._logger.finding(
                "TAKEOVER",
                host,
                risk.upper(),
                confidence=0.0 if risk == "high" else 0.7 if risk == "medium" else 1.0,
            )
            results.append(entry)

        return {
            "mx_hosts": results,
            "issues": issues,
        }

    async def check_bimi(self, domain: str) -> dict:
        txt = await self._resolver.txt(f"default._bimi.{domain}")
        issues = []

        if not txt:
            self._logger.finding("BIMI", "Record", "not found", confidence=0.5)
            return {
                "record": None,
                "logo_url": None,
                "vmc_url": None,
                "issues": ["No BIMI record found"],
            }

        bimi_record = next((r for r in txt if "v=BIMI1" in r), None)
        if not bimi_record:
            issues.append("BIMI TXT record present but does not contain v=BIMI1")
            return {"record": txt, "logo_url": None, "vmc_url": None, "issues": issues}

        tags = {}
        for part in re.split(r";\s*", bimi_record.strip()):
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip()] = v.strip()

        logo_url = tags.get("l")
        vmc_url = tags.get("a")

        if not logo_url:
            issues.append("BIMI record has no logo URI (l=) - clients will not display brand indicator")
        if not vmc_url:
            issues.append("BIMI record has no VMC (a=) - unverified mark, major clients may ignore it")

        self._logger.finding("BIMI", "Record", "found", confidence=1.0 if logo_url and vmc_url else 0.6)
        return {
            "record": bimi_record,
            "logo_url": logo_url,
            "vmc_url": vmc_url,
            "issues": issues,
        }

    async def check_caa(self, domain: str) -> dict:
        records = await self._resolver.caa(domain)
        issues = []

        if not records:
            issues.append("No CAA records found - any CA can issue TLS certificates for this domain")
            self._logger.finding("CAA", "Records", "none", confidence=0.0)
            return {
                "records": [],
                "issuers": [],
                "issue_wildcard": [],
                "iodef": [],
                "issues": issues,
            }

        issuers = [r["value"] for r in records if r.get("tag") == "issue"]
        wildcard_issuers = [r["value"] for r in records if r.get("tag") == "issuewild"]
        iodef = [r["value"] for r in records if r.get("tag") == "iodef"]

        if not iodef:
            issues.append("No CAA iodef tag - mis-issuance violations will not be reported")

        self._logger.finding("CAA", "Issuers", ", ".join(issuers) or "none", confidence=1.0)
        return {
            "records": records,
            "issuers": issuers,
            "issue_wildcard": wildcard_issuers,
            "iodef": iodef,
            "issues": issues,
        }

    async def check_null_mx(self, domain: str, mx_hosts: list[str]) -> dict:
        issues = []

        if mx_hosts:
            return {
                "null_mx_present": False,
                "applicable": False,
                "issues": [],
            }

        txt = await self._resolver.mx(domain)
        null_mx_present = any(
            r.get("host") == "." and r.get("priority") == 0
            for r in (txt or [])
        )

        if not null_mx_present:
            issues.append(
                "Domain has no MX records and no Null MX (RFC 7505) - "
                "may accept delivery attempts and expose to backscatter"
            )

        self._logger.finding(
            "NULL-MX",
            "RFC 7505",
            "present" if null_mx_present else "missing",
            confidence=1.0 if null_mx_present else 0.0,
        )
        return {
            "null_mx_present": null_mx_present,
            "applicable": True,
            "issues": issues,
        }

    async def check_dane(self, mx_hosts: list[str]) -> dict:
        issues = []
        results = []

        for host in mx_hosts:
            host = host.rstrip(".")
            tlsa_name = f"_25._tcp.{host}"
            records = await self._resolver.tlsa(tlsa_name)

            if not records:
                issues.append(f"No DANE/TLSA record for '{host}' - TLS certificate cannot be pinned via DNS")
                self._logger.finding("DANE", host, "no TLSA", confidence=0.0)
                results.append({
                    "host": host,
                    "tlsa_name": tlsa_name,
                    "records": [],
                    "dane_enabled": False,
                })
                continue

            parsed = []
            for rec in records:
                usage = rec.get("usage")
                selector = rec.get("selector")
                matching = rec.get("matching_type")
                parsed.append({
                    "usage": usage,
                    "selector": selector,
                    "matching_type": matching,
                    "certificate_association": rec.get("certificate_association"),
                })

            self._logger.finding("DANE", host, f"{len(records)} TLSA record(s)", confidence=1.0)
            results.append({
                "host": host,
                "tlsa_name": tlsa_name,
                "records": parsed,
                "dane_enabled": True,
            })

        return {
            "mx_dane": results,
            "issues": issues,
        }

# ---------------------------------------------------------------------------
# DNSSecModule — SPF / DKIM / DMARC / MX analysis
# Output keys match logger._render_dns_sec()
# ---------------------------------------------------------------------------

import re as _re

_SPF_ALL_QUALIFIERS = {
    "-all": "fail",
    "~all": "softfail",
    "+all": "pass",
    "?all": "neutral",
}

_COMMON_DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "dkim",
    "mail", "smtp", "s1", "s2", "proofpoint", "mimecast",
    "mandrill", "sendgrid", "mailjet", "postfix",
]


class DNSSecModule(BaseEmailModule):

    async def run(self, domain: str) -> dict:
        mx_records, spf_raw, dmarc_raw = await asyncio.gather(
            self._resolver.mx(domain),
            self._resolver.spf(domain),
            self._resolver.dmarc(domain),
        )

        dkim_found = await self._resolver.probe_dkim_selectors(domain, _COMMON_DKIM_SELECTORS)

        # Resolve IPs for each MX host
        if mx_records:
            ip_tasks = [self._resolver.a(r["host"]) for r in mx_records]
            ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
            for record, ips in zip(mx_records, ip_results):
                record["ips"] = ips if isinstance(ips, list) else []

        spf_result   = self._parse_spf(spf_raw)
        dkim_result  = self._parse_dkim(dkim_found)
        dmarc_result = self._parse_dmarc(dmarc_raw)
        risk         = self._spoofing_risk(spf_result, dkim_result, dmarc_result)

        return {
            "mx_records":    mx_records or [],
            "spf":           spf_result,
            "dkim":          dkim_result,
            "dmarc":         dmarc_result,
            "spoofing_risk": risk,
        }

    # ------------------------------------------------------------------ #

    def _parse_spf(self, raw):
        issues = []
        if not raw:
            issues.append("No SPF record found - domain is unprotected against sender spoofing")
            return {"record": None, "all_qualifier": None, "include_count": 0, "issues": issues}

        all_qualifier = None
        for token, qualifier in _SPF_ALL_QUALIFIERS.items():
            if token in raw.split():
                all_qualifier = qualifier
                break

        if all_qualifier is None:
            issues.append("SPF record has no 'all' mechanism - undefined policy for non-matching senders")
        elif all_qualifier == "pass":
            issues.append("SPF uses '+all' - allows any sender, effectively no protection")
        elif all_qualifier == "neutral":
            issues.append("SPF uses '?all' - neutral policy provides no protection")
        elif all_qualifier == "softfail":
            issues.append("SPF uses '~all' (softfail) - consider upgrading to '-all' for strict enforcement")

        include_count = len(_re.findall(r"\binclude:", raw))
        if include_count >= 10:
            issues.append(f"SPF has {include_count} include mechanisms - may exceed the 10-lookup DNS limit")

        return {"record": raw, "all_qualifier": all_qualifier, "include_count": include_count, "issues": issues}

    def _parse_dkim(self, found: dict) -> dict:
        issues = []
        selectors = list(found.keys())
        if not selectors:
            issues.append("No DKIM selectors found - outgoing mail cannot be cryptographically verified")
        elif len(selectors) == 1:
            issues.append("Only one DKIM selector found - consider a second for zero-downtime key rotation")
        return {"found_selectors": selectors, "issues": issues}

    def _parse_dmarc(self, raw) -> dict:
        issues = []
        if not raw:
            issues.append("No DMARC record found - phishing and spoofing using this domain is unrestricted")
            return {"record": None, "policy": None, "subdomain_policy": None,
                    "pct": None, "rua": [], "ruf": [], "issues": issues}

        tags = {}
        for part in _re.split(r";\s*", raw.strip()):
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()

        policy           = tags.get("p", "none").lower()
        subdomain_policy = tags.get("sp", policy).lower()
        pct              = int(tags.get("pct", 100))
        rua              = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
        ruf              = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]

        if policy == "none":
            issues.append("DMARC policy is 'none' - monitoring only, no enforcement against spoofed mail")
        elif policy == "quarantine":
            issues.append("DMARC policy is 'quarantine' - consider upgrading to 'reject' for full protection")
        if pct < 100:
            issues.append(f"DMARC pct={pct} - policy only applied to {pct}% of failing messages")
        if not rua:
            issues.append("No DMARC rua address - no visibility into authentication failures")
        if subdomain_policy == "none" and policy != "none":
            issues.append("DMARC subdomain policy (sp=) is 'none' - subdomains are unprotected")

        return {"record": raw, "policy": policy, "subdomain_policy": subdomain_policy,
                "pct": pct, "rua": rua, "ruf": ruf, "issues": issues}

    def _spoofing_risk(self, spf: dict, dkim: dict, dmarc: dict) -> dict:
        score = 0

        if not spf.get("record"):
            score += 30
        else:
            q = spf.get("all_qualifier")
            if q in (None, "pass", "neutral"):
                score += 25
            elif q == "softfail":
                score += 10

        if not dkim.get("found_selectors"):
            score += 20

        policy = dmarc.get("policy")
        if not policy:
            score += 50
        elif policy == "none":
            score += 40
        elif policy == "quarantine":
            pct = dmarc.get("pct") or 100
            score += int(20 * (1 - pct / 100)) + 10
        elif policy == "reject":
            pct = dmarc.get("pct") or 100
            score += int(20 * (1 - pct / 100))

        score = min(score, 100)
        level = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "NONE"
        return {"score": score, "level": level}