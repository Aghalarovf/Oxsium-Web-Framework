import random
import socket
import string

import dns.resolver

from modules.base import BaseDNSModule
from core.ui import ok, fail, warn, info, banner


CLOUD_CNAME_PATTERNS = [
    ("s3.amazonaws.com",          "AWS S3"),
    ("azurewebsites.net",         "Azure Web Apps"),
    ("azureedge.net",             "Azure CDN"),
    ("cloudfront.net",            "AWS CloudFront"),
    ("pages.github.io",           "GitHub Pages"),
    ("github.io",                 "GitHub Pages"),
    ("herokuapp.com",             "Heroku"),
    ("netlify.app",               "Netlify"),
    ("vercel.app",                "Vercel"),
    ("firebaseapp.com",           "Firebase"),
    ("web.app",                   "Firebase Hosting"),
    ("pantheonsite.io",           "Pantheon"),
    ("ghost.io",                  "Ghost"),
    ("freshdesk.com",             "Freshdesk"),
    ("helpscoutdocs.com",         "Help Scout"),
    ("zendesk.com",               "Zendesk"),
    ("myshopify.com",             "Shopify"),
    ("tumblr.com",                "Tumblr"),
    ("wpengine.com",              "WP Engine"),
    ("fastly.net",                "Fastly CDN"),
    ("squarespace.com",           "Squarespace"),
    ("surge.sh",                  "Surge.sh"),
    ("bitbucket.io",              "Bitbucket"),
]

PLATFORM_FINGERPRINTS = {
    "GitHub Pages":   "There isn't a GitHub Pages site here",
    "Heroku":         "No such app",
    "Fastly CDN":     "Fastly error: unknown domain",
    "Azure Web Apps": "404 Web Site not found",
    "Azure CDN":      "404 Web Site not found",
    "Shopify":        "Sorry, this shop is currently unavailable",
    "Ghost":          "404 - Page Not Found",
    "Zendesk":        "Help Center Closed",
    "Surge.sh":       "project not found",
}

SRV_PREFIXES = [
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_http._tcp",
]

EXTRA_SUBDOMAINS = [
    "blog", "cdn", "admin", "ftp", "smtp", "vpn",
    "status", "docs", "help", "shop", "portal",
]

WILDCARD_RANDOM_LENGTH = 22
WILDCARD_PROBE_COUNT   = 3
WILDCARD_HIT_THRESHOLD = 2


class DanglingDNSModule(BaseDNSModule):

    def _fetch_subdomain(self, subdomain: str) -> tuple[str, int | None]:
        for scheme in ("https", "http"):
            try:
                r = self.session.get(
                    f"{scheme}://{subdomain}",
                    timeout=8,
                    allow_redirects=True,
                )
                return r.text, r.status_code
            except Exception:
                continue
        return "", None

    def _check_cname_liveness(self, subdomain: str, target: str, service: str) -> dict | None:
        try:
            socket.gethostbyname(target)
            resolves = True
        except socket.gaierror:
            resolves = False

        body, status = self._fetch_subdomain(subdomain)

        fingerprint = PLATFORM_FINGERPRINTS.get(service)
        if fingerprint and fingerprint in body:
            warn(f"TAKEOVER CONFIRMED: {subdomain} → {target} ({service}) — claim page detected")
            return {
                "subdomain": subdomain,
                "cname": target,
                "service": service,
                "reason": "fingerprint_match",
                "claim_url": f"https://{subdomain}",
            }

        if not resolves:
            if status in (404, 400):
                warn(f"POSSIBLE TAKEOVER: {subdomain} → {target} ({service}) — HTTP {status}")
                return {
                    "subdomain": subdomain,
                    "cname": target,
                    "service": service,
                    "reason": f"http_{status}",
                    "claim_url": f"https://{subdomain}",
                }
            warn(f"LIKELY DANGLING: {subdomain} → {target} ({service}) — no response")
            return {
                "subdomain": subdomain,
                "cname": target,
                "service": service,
                "reason": "no_response",
                "claim_url": f"https://{subdomain}",
            }

        ok(f"{subdomain}  →  {target}  ({service} — active)")
        return None

    def _whois_registered(self, domain: str) -> bool | None:
        tld = domain.split(".")[-1].upper()
        whois_servers = {
            "COM":  "whois.verisign-grs.com",
            "NET":  "whois.verisign-grs.com",
            "ORG":  "whois.pir.org",
            "IO":   "whois.nic.io",
            "CO":   "whois.nic.co",
            "ME":   "whois.nic.me",
            "INFO": "whois.afilias.net",
            "BIZ":  "whois.biz",
            "APP":  "whois.nic.google",
            "DEV":  "whois.nic.google",
        }
        server = whois_servers.get(tld, f"whois.nic.{tld.lower()}")
        unregistered_signals = [
            "no match",
            "not found",
            "no entries found",
            "object does not exist",
            "no data found",
            "domain not found",
        ]
        try:
            with socket.create_connection((server, 43), timeout=5) as sock:
                sock.sendall(f"{domain}\r\n".encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            text = response.decode(errors="ignore").lower()
            return not any(sig in text for sig in unregistered_signals)
        except socket.timeout:
            warn(f"WHOIS timeout for {domain} — skipping NS takeover check")
            return None
        except OSError as exc:
            warn(f"WHOIS connection error for {domain} ({exc}) — skipping NS takeover check")
            return None

    def _check_ns_delegation_takeover(self) -> list:
        findings = []
        try:
            ns_answers = self.resolver.resolve(self.domain, "NS")
            nameservers = [str(r.target).rstrip(".") for r in ns_answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return findings

        seen_roots = set()
        for ns in nameservers:
            labels = ns.split(".")
            if len(labels) < 2:
                continue
            root = ".".join(labels[-2:])
            if root in seen_roots:
                continue
            seen_roots.add(root)

            registered = self._whois_registered(root)
            if registered is None:
                continue
            if not registered:
                warn(f"CRITICAL — NS delegation takeover: {ns} root domain {root} is unregistered")
                findings.append({
                    "ns": ns,
                    "root_domain": root,
                    "reason": "unregistered_ns_root",
                })
            else:
                ok(f"NS {ns} root {root} — registered")

        return findings

    def _check_mx_takeover(self) -> list:
        findings = []
        try:
            mx_answers = self.resolver.resolve(self.domain, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return findings

        for mx in mx_answers:
            host = str(mx.exchange).rstrip(".")
            try:
                socket.gethostbyname(host)
                ok(f"MX {host} — resolves OK")
            except socket.gaierror:
                warn(
                    f"CRITICAL — MX takeover risk: {host} does not resolve. "
                    f"Password resets, 2FA codes, and internal notifications may be intercepted."
                )
                findings.append({
                    "mx_host": host,
                    "priority": mx.preference,
                    "reason": "unresolvable_mx",
                })

        return findings

    def _probe_resolves_cname(self, subdomain: str) -> bool:
        try:
            self.resolver.resolve(subdomain, "CNAME")
            return True
        except Exception:
            return False

    def _check_wildcard_cname(self) -> dict | None:
        CLOUD_DOMAINS = {pattern for pattern, _ in CLOUD_CNAME_PATTERNS}
        if any(self.domain == pattern or self.domain.endswith("." + pattern) for pattern in CLOUD_DOMAINS):
            ok(f"Target {self.domain} is a cloud platform domain — wildcard check skipped")
            return None

        probes = [
            "".join(random.choices(string.ascii_lowercase, k=WILDCARD_RANDOM_LENGTH))
            + "."
            + self.domain
            for _ in range(WILDCARD_PROBE_COUNT)
        ]
        hits = sum(1 for p in probes if self._probe_resolves_cname(p))
        if hits < WILDCARD_HIT_THRESHOLD:
            ok(f"No wildcard CNAME on *.{self.domain}")
            return None

        try:
            cname_answers = self.resolver.resolve(probes[0], "CNAME")
            for cname in cname_answers:
                target = str(cname.target).rstrip(".")
                service = next(
                    (svc for pattern, svc in CLOUD_CNAME_PATTERNS if pattern in target),
                    "Unknown",
                )
                warn(f"WILDCARD CNAME active: *.{self.domain} → {target} ({service})")
                result = self._check_cname_liveness(f"*.{self.domain}", target, service)
                if result:
                    result["wildcard"] = True
                    return result
                return {
                    "subdomain": f"*.{self.domain}",
                    "cname": target,
                    "service": service,
                    "wildcard": True,
                    "reason": "wildcard_active",
                }
        except dns.resolver.Timeout:
            warn(f"Timeout resolving wildcard probe for {self.domain}")
        except Exception:
            pass
        return None

    def _port_reachable(self, host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _check_srv_dangling(self) -> list:
        findings = []
        for prefix in SRV_PREFIXES:
            srv_name = f"{prefix}.{self.domain}"
            try:
                srv_answers = self.resolver.resolve(srv_name, "SRV")
                for srv in srv_answers:
                    target = str(srv.target).rstrip(".")
                    port = srv.port
                    priority = srv.priority
                    try:
                        socket.gethostbyname(target)
                    except socket.gaierror:
                        warn(
                            f"DANGLING SRV: {srv_name} → {target}:{port} "
                            f"(priority {priority}) — does not resolve"
                        )
                        findings.append({
                            "srv": srv_name,
                            "target": target,
                            "port": port,
                            "priority": priority,
                            "reason": "unresolvable_srv_target",
                        })
                        continue

                    if self._port_reachable(target, port):
                        ok(f"SRV {srv_name} → {target}:{port} (priority {priority}) — reachable")
                    else:
                        warn(
                            f"DANGLING SRV: {srv_name} → {target}:{port} "
                            f"(priority {priority}) — resolves but port unreachable"
                        )
                        findings.append({
                            "srv": srv_name,
                            "target": target,
                            "port": port,
                            "priority": priority,
                            "reason": "port_unreachable",
                        })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.resolver.Timeout:
                warn(f"Timeout resolving SRV {srv_name}")
            except Exception:
                pass
        return findings

    def _has_any_dns_record(self, subdomain: str) -> bool:
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                self.resolver.resolve(subdomain, rtype)
                return True
            except Exception:
                pass
        return False

    def check_dangling_cname(self) -> list:
        banner("Dangling DNS Detection")
        dangling = []

        base_subdomains = [
            self.domain,
            f"www.{self.domain}",
            f"mail.{self.domain}",
            f"dev.{self.domain}",
            f"staging.{self.domain}",
            f"api.{self.domain}",
        ]
        extra_subdomains = [f"{label}.{self.domain}" for label in EXTRA_SUBDOMAINS]
        subdomains = base_subdomains + extra_subdomains

        CLOUD_DOMAINS = {pattern for pattern, _ in CLOUD_CNAME_PATTERNS}

        for sub in subdomains:
            if any(sub == pattern or sub.endswith("." + pattern) for pattern in CLOUD_DOMAINS):
                continue
            try:
                cname_answers = self.resolver.resolve(sub, "CNAME")
                for cname in cname_answers:
                    target = str(cname.target).rstrip(".")
                    service = next(
                        (svc for pattern, svc in CLOUD_CNAME_PATTERNS if pattern in target),
                        None,
                    )
                    if service:
                        result = self._check_cname_liveness(sub, target, service)
                        if result:
                            dangling.append(result)
                    else:
                        ok(f"{sub}  →  {target}  (CNAME, non-cloud)")

            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                if self._has_any_dns_record(sub):
                    warn(f"{sub}  →  NXDOMAIN despite prior record — possible dangling")
                    dangling.append({"subdomain": sub, "cname": "NXDOMAIN", "service": "Unknown", "reason": "nxdomain_with_record"})
            except dns.resolver.Timeout:
                warn(f"Timeout resolving {sub}")
            except Exception:
                pass

        wildcard_result = self._check_wildcard_cname()
        if wildcard_result:
            dangling.append(wildcard_result)

        dangling.extend(self._check_ns_delegation_takeover())
        dangling.extend(self._check_mx_takeover())
        dangling.extend(self._check_srv_dangling())

        if not dangling:
            ok("No dangling DNS entries detected")

        return dangling