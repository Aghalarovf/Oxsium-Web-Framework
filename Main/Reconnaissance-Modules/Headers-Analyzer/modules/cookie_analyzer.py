import ipaddress
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit

from .base import BaseHeaderModule
from .cookie_intel.balancers import decode_bigip, find_addresses
from .cookie_intel.decoders import inspect_value
from .cookie_intel.structure import flatten
from .cookie_intel.entropy import analyze_samples, rate_strength
from .cookie_intel.signatures import (
    CLIENT_READABLE_CATEGORIES,
    SENSITIVE_CATEGORIES,
    identify_cookie,
    is_sensitive_name,
)
from core.engine import SEVERITY_ORDER, ModuleResult
from core.intercept_reader import HTTPResponse

try:
    import tldextract

    _SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:
    _SUFFIX_EXTRACTOR = None

PUBLIC_SUFFIXES = {
    "com", "net", "org", "io", "co", "gov", "edu", "app", "dev", "info", "biz", "me",
    "tv", "cc", "us", "uk", "de", "cn", "ru", "xyz", "mil", "int", "name", "pro",
    "online", "site", "tech", "store", "cloud", "ai",
}
SECOND_LEVEL_LABELS = {"co", "com", "net", "org", "gov", "edu", "ac", "mil", "or", "ne", "go"}

LOGIN_PATH_PATTERN = re.compile(r"login|log-in|signin|sign-in|authenticate|/auth|/sso|oauth|/token|callback", re.IGNORECASE)
LOGOUT_PATH_PATTERN = re.compile(r"logout|log-out|signout|sign-out|signoff|sign-off", re.IGNORECASE)

STRUCTURED_TYPES = frozenset({"opaque-token", "opaque", "hex-token", "provider-token"})

SENTINEL_VALUES = frozenset({
    "deleteme", "deleted", "expired", "null", "none", "undefined", "nil",
    "invalid", "true", "false", "yes", "no", "0", "1", "-", "",
})
IDENTITY_KEYS = frozenset({
    "sub", "user", "username", "user_name", "user_id", "userid", "uid",
    "email", "login", "preferred_username", "name", "upn", "account", "account_id", "id",
})
EMAIL_FINDER = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
MAX_IDENTITIES = 100
SAMPLED_TYPES = frozenset({"numeric", "hex-token", "opaque-token", "opaque", "uuid"})
SAMPLE_THRESHOLDS = (3, 5, 10, 20)
MAX_SAMPLES_PER_COOKIE = 50

CHROME_MAX_LIFETIME_SECONDS = 400 * 86400
CONSENT_TRACKING_LIFETIME_SECONDS = 395 * 86400
MAX_COOKIE_BYTES = 4096
MAX_COOKIE_HEADER_BYTES = 8000


def _split_set_cookie_header(raw: str) -> List[str]:
    return [part.strip() for part in re.split(r",(?=\s*[^;=,\s]+=)", raw) if part.strip()]


def _parse_set_cookie_entry(raw: str) -> Optional[Dict[str, Any]]:
    segments = [seg.strip() for seg in raw.split(";")]
    if not segments or "=" not in segments[0]:
        return None
    name, _, value = segments[0].partition("=")
    name = name.strip()
    value = value.strip().strip('"')
    if not name:
        return None
    attrs: Dict[str, str] = {}
    flags = set()
    for segment in segments[1:]:
        if not segment:
            continue
        if "=" in segment:
            key, _, val = segment.partition("=")
            attrs[key.strip().lower()] = val.strip()
        else:
            flags.add(segment.strip().lower())
    return {"name": name, "value": value, "attrs": attrs, "flags": flags, "raw_length": len(raw)}


def _parse_cookie_header(raw: Optional[str]) -> List[Tuple[str, str]]:
    result = []
    for part in (raw or "").split(";"):
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        value = value.strip().strip('"')
        if name:
            result.append((name, value))
    return result


def _is_public_suffix(domain: str) -> bool:
    if _SUFFIX_EXTRACTOR is not None:
        try:
            extracted = _SUFFIX_EXTRACTOR(domain)
            return extracted.domain == "" and extracted.suffix != ""
        except Exception:
            pass
    labels = domain.split(".")
    if len(labels) == 1:
        return domain in PUBLIC_SUFFIXES or (len(domain) == 2 and domain.isalpha())
    if len(labels) == 2:
        return labels[0] in SECOND_LEVEL_LABELS and len(labels[1]) == 2 and labels[1].isalpha()
    return False


def _is_ip_literal(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def _parse_expires(raw: Optional[str]) -> Optional[float]:
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _cache_directives(value: Optional[str]) -> Set[str]:
    directives = set()
    for part in (value or "").split(","):
        token = part.strip().lower().split("=", 1)[0]
        if token:
            directives.add(token)
    return directives


class _Context:
    __slots__ = ("response", "result", "host", "scheme", "is_https", "reference_epoch", "extras")

    def __init__(self, response: HTTPResponse, result: ModuleResult, host: str, scheme: str, is_https: bool, reference_epoch: float):
        self.response = response
        self.result = result
        self.host = host
        self.scheme = scheme
        self.is_https = is_https
        self.reference_epoch = reference_epoch
        self.extras: List[str] = []


class CookieModule(BaseHeaderModule):
    name = "Cookie & JWT Analyzer"
    description = (
        "Audits Set-Cookie attributes and prefixes, classifies and decodes cookie values (JWT, signed sessions, serialized objects, "
        "encodings), estimates entropy and hash predictability, detects leaked provider tokens, fingerprints frameworks, load balancers, "
        "WAFs and trackers, and correlates cookies across exchanges."
    )

    def __init__(self):
        self._samples: Dict[Tuple[str, str], List[str]] = {}
        self._reported: Set[Tuple[Any, ...]] = set()
        self._consent_hosts: Set[str] = set()
        self._pre_auth_values: Dict[str, Dict[str, str]] = {}
        self._identities: List[str] = []

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        parts = urlsplit(response.url or "")
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        is_https = scheme in ("https", "wss")

        raw_set_cookie = self._get_header(response.headers, "Set-Cookie")
        set_cookies = []
        if raw_set_cookie:
            for part in _split_set_cookie_header(raw_set_cookie):
                parsed = _parse_set_cookie_entry(part)
                if parsed:
                    set_cookies.append(parsed)

        raw_request_cookie = response.request_headers.get("cookie")
        request_cookies = _parse_cookie_header(raw_request_cookie)

        if not set_cookies and not request_cookies:
            result.add_finding("INFO", "Cookie", "No cookies observed in this exchange")
            return result

        ctx = _Context(response, result, host, scheme, is_https, self._reference_epoch(response))
        ctx.extras = self._collect_extras(host, parts.path, set_cookies, request_cookies)

        set_meta = [self._analyze_set_cookie(cookie, ctx) for cookie in set_cookies]
        issued_pairs = {(cookie["name"], cookie["value"]) for cookie in set_cookies}
        request_meta = [
            self._analyze_request_cookie(name, value, ctx, (name, value) in issued_pairs)
            for name, value in request_cookies
        ]

        self._check_duplicates(set_cookies, ctx)
        self._check_sizes(set_cookies, raw_request_cookie, ctx)
        self._check_response_context(set_meta, ctx)
        self._check_auth_flow(set_cookies, request_cookies, ctx)
        self._track_samples(set_cookies, set_meta, ctx)
        self._check_privacy(set_meta, request_meta, ctx)
        summary = self._build_summary(set_meta, request_meta, ctx)

        result.metadata["cookies"] = {
            "set_cookie": set_meta,
            "request_cookie": request_meta,
            "summary": summary,
        }
        return result

    def _collect_extras(self, host: str, path: str, set_cookies: List[Dict[str, Any]], request_cookies: List[Tuple[str, str]]) -> List[str]:
        candidates: List[str] = []
        if host:
            candidates.extend([host, host.split(".")[0]])
        candidates.extend(segment for segment in path.split("/") if segment)
        candidates.extend(cookie["value"] for cookie in set_cookies)
        candidates.extend(value for _, value in request_cookies)
        candidates.extend(self._identities)
        unique: List[str] = []
        seen = set()
        for item in candidates:
            if 0 < len(item) <= 128 and item not in seen:
                seen.add(item)
                unique.append(item)
        return unique[:150]

    def _harvest_identities(self, profile: Dict[str, Any]) -> None:
        decoded = profile.get("decoded")
        if not decoded:
            return
        found: List[str] = []
        obj = profile.get("_decoded_obj")
        if isinstance(obj, (dict, list)):
            leaves, _ = flatten(obj)
            for path, value in leaves:
                key = path.split(".")[-1].split("[")[0].lower()
                if key in IDENTITY_KEYS and isinstance(value, (str, int)) and not isinstance(value, bool):
                    text_value = str(value)
                    if 0 < len(text_value) <= 64:
                        found.append(text_value)
        found.extend(EMAIL_FINDER.findall(str(decoded)[:6000]))
        for item in found:
            if item not in self._identities and len(self._identities) < MAX_IDENTITIES:
                self._identities.append(item)

    def _classify(self, name: str, profile: Dict[str, Any], fingerprint: Optional[Dict[str, str]]) -> Tuple[Optional[str], bool]:
        category = fingerprint["category"] if fingerprint else None
        sensitive = is_sensitive_name(name) or category in SENSITIVE_CATEGORIES
        if category in CLIENT_READABLE_CATEGORIES:
            sensitive = False
        if profile["signed"] or profile["encrypted"] or profile["provider_tokens"]:
            sensitive = True
        return category, sensitive

    def _pre_sensitive(self, name: str, fingerprint: Optional[Dict[str, str]]) -> bool:
        category = fingerprint["category"] if fingerprint else None
        if category in CLIENT_READABLE_CATEGORIES:
            return False
        return is_sensitive_name(name) or category in SENSITIVE_CATEGORIES

    def _analyze_set_cookie(self, cookie: Dict[str, Any], ctx: _Context) -> Dict[str, Any]:
        result = ctx.result
        name = cookie["name"]
        value = cookie["value"]
        attrs = cookie["attrs"]
        flags = cookie["flags"]
        label = f"Set-Cookie ({name})"

        fingerprint = identify_cookie(name)
        profile = inspect_value(value, ctx.reference_epoch, ctx.extras, deep=self._pre_sensitive(name, fingerprint))
        category, is_sensitive = self._classify(name, profile, fingerprint)
        client_readable = category in CLIENT_READABLE_CATEGORIES

        has_secure = "secure" in flags
        has_httponly = "httponly" in flags
        has_partitioned = "partitioned" in flags
        samesite = attrs.get("samesite", "").strip().lower() or None
        domain = attrs.get("domain")
        path = attrs.get("path")
        lower_name = name.lower()

        self._check_prefixes(label, lower_name, attrs, has_secure, has_httponly, ctx)

        if ctx.is_https and not has_secure:
            if is_sensitive:
                severity = "HIGH"
            elif client_readable:
                severity = "LOW"
            else:
                severity = "MEDIUM"
            result.add_finding(severity, label, "Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted")
        elif not ctx.is_https:
            if is_sensitive:
                result.add_finding("HIGH", label, f"Sensitive cookie is issued over plaintext {ctx.scheme or 'http'}://; any network observer can read and replay it")
            if has_secure:
                result.add_finding("INFO", label, "Secure flag is present on a cookie delivered over plaintext HTTP; browsers reject or ignore Secure cookies set by insecure origins")
        elif has_secure:
            result.add_finding("OK", label, "Secure flag is set")

        if has_httponly:
            result.add_finding("OK", label, "HttpOnly flag is set")
        elif category == "csrf":
            result.add_finding("INFO", label, "CSRF token cookie is readable by JavaScript; this is expected for double-submit patterns but exposes it to any XSS")
        elif not client_readable:
            severity = "HIGH" if is_sensitive else "LOW"
            result.add_finding(severity, label, "HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie")

        if has_partitioned and not has_secure:
            result.add_finding("MEDIUM", label, "Partitioned attribute without Secure; browsers reject partitioned cookies that are not Secure")

        if samesite is None:
            if not client_readable:
                result.add_finding("LOW", label, "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies")
        elif samesite == "none":
            if not has_secure:
                result.add_finding("HIGH", label, "SameSite=None without Secure; modern browsers reject this cookie outright, or older ones send it on every cross-site request")
            elif is_sensitive:
                result.add_finding("MEDIUM", label, "SameSite=None allows this cookie on cross-site requests; confirm this is intentional (e.g. a third-party embed) and not an oversight")
            elif client_readable:
                result.add_finding("INFO", label, "SameSite=None makes this tracking/preference cookie available in cross-site contexts")
            else:
                result.add_finding("INFO", label, "SameSite=None allows this cookie on cross-site requests; confirm this is intentional" + ("" if has_partitioned else " (consider Partitioned/CHIPS for embedded use)"))
        elif samesite == "lax":
            result.add_finding("OK", label, "SameSite=Lax is set")
        elif samesite == "strict":
            result.add_finding("OK", label, "SameSite=Strict is set (strongest CSRF protection)")
        else:
            result.add_finding("LOW", label, f"Unrecognized SameSite value: '{samesite}'")

        self._check_domain_and_path(label, domain, path, is_sensitive, ctx)
        lifetime = self._check_lifetime(label, attrs, is_sensitive, category, ctx)

        if fingerprint:
            result.add_finding("INFO", f"Fingerprint ({name})", f"{fingerprint['label']} [{category}]")
        self._check_special_cookies(name, value, fingerprint, label, ctx)
        cleared = (lifetime is not None and lifetime <= 0) or value.strip().lower() in SENTINEL_VALUES
        self._emit_value_findings(label, profile, is_sensitive, ctx, cleared)
        self._harvest_identities(profile)

        return {
            "name": name,
            "value": value,
            "host": ctx.host,
            "value_preview": value[:80] + ("..." if len(value) > 80 else ""),
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite,
            "partitioned": has_partitioned,
            "domain": domain,
            "path": path,
            "max_age": attrs.get("max-age"),
            "expires": attrs.get("expires"),
            "lifetime_seconds": lifetime,
            "category": category,
            "fingerprint": fingerprint["label"] if fingerprint else None,
            "sensitive": is_sensitive,
            "value_type": profile["type"],
            "decoded": profile["decoded"],
            "layers": profile["layers"],
            "entropy": profile["assessment"],
            "hash_candidates": profile["hash_candidates"],
            "provider_tokens": profile["provider_tokens"],
        }

    def _analyze_request_cookie(self, name: str, value: str, ctx: _Context, already_reported: bool) -> Dict[str, Any]:
        result = ctx.result
        label = f"Cookie ({name})"
        fingerprint = identify_cookie(name)
        profile = inspect_value(value, ctx.reference_epoch, ctx.extras, deep=self._pre_sensitive(name, fingerprint))
        category, is_sensitive = self._classify(name, profile, fingerprint)

        if not already_reported:
            if not ctx.is_https and is_sensitive:
                result.add_finding("HIGH", label, f"Sent to a {ctx.scheme}:// endpoint in cleartext; if this cookie lacks the Secure flag it can be intercepted on the network")
            if fingerprint:
                result.add_finding("INFO", f"Fingerprint ({name})", f"{fingerprint['label']} [{category}]")
            self._check_special_cookies(name, value, fingerprint, label, ctx)
            self._emit_value_findings(label, profile, is_sensitive, ctx, value.strip().lower() in SENTINEL_VALUES)
            self._harvest_identities(profile)

        return {
            "name": name,
            "value": value,
            "host": ctx.host,
            "value_preview": value[:80] + ("..." if len(value) > 80 else ""),
            "category": category,
            "fingerprint": fingerprint["label"] if fingerprint else None,
            "sensitive": is_sensitive,
            "value_type": profile["type"],
            "decoded": profile["decoded"],
            "layers": profile["layers"],
            "entropy": profile["assessment"],
            "hash_candidates": profile["hash_candidates"],
            "provider_tokens": profile["provider_tokens"],
        }

    def _check_prefixes(self, label: str, lower_name: str, attrs: Dict[str, str], has_secure: bool, has_httponly: bool, ctx: _Context) -> None:
        result = ctx.result
        path_ok = attrs.get("path", "").strip() == "/"
        no_domain = "domain" not in attrs

        if lower_name.startswith("__host-http-"):
            missing = []
            if not has_secure:
                missing.append("Secure")
            if not has_httponly:
                missing.append("HttpOnly")
            if not path_ok:
                missing.append("Path=/")
            if not no_domain:
                missing.append("no Domain attribute")
            if missing:
                result.add_finding("HIGH", label, f"__Host-Http- prefix is used but its requirements are violated (missing: {', '.join(missing)}); browsers will reject this cookie")
            else:
                result.add_finding("OK", label, "__Host-Http- prefix requirements are satisfied (Secure, HttpOnly, Path=/, no Domain)")
        elif lower_name.startswith("__http-"):
            if has_secure and has_httponly:
                result.add_finding("OK", label, "__Http- prefix requirements (Secure, HttpOnly) are satisfied")
            else:
                result.add_finding("HIGH", label, "__Http- prefix is used without Secure and HttpOnly; browsers will reject this cookie")
        elif lower_name.startswith("__host-"):
            if has_secure and path_ok and no_domain:
                result.add_finding("OK", label, "__Host- prefix requirements are satisfied (Secure, Path=/, no Domain)")
            else:
                missing = []
                if not has_secure:
                    missing.append("Secure")
                if not path_ok:
                    missing.append("Path=/")
                if not no_domain:
                    missing.append("no Domain attribute")
                result.add_finding("HIGH", label, f"__Host- prefix is used but its requirements are violated (missing: {', '.join(missing)}); browsers will reject or strip this cookie, or the developer misunderstands the guarantee")
        elif lower_name.startswith("__secure-"):
            if has_secure:
                result.add_finding("OK", label, "__Secure- prefix requirement (Secure flag) is satisfied")
            else:
                result.add_finding("HIGH", label, "__Secure- prefix is used without the Secure flag; browsers will reject this cookie")

    def _check_domain_and_path(self, label: str, domain: Optional[str], path: Optional[str], is_sensitive: bool, ctx: _Context) -> None:
        result = ctx.result
        if domain:
            normalized = domain.lstrip(".").lower()
            if _is_ip_literal(normalized):
                result.add_finding("LOW", label, f"Domain='{domain}' is an IP address; Domain scoping is not defined for IP hosts and is ignored or rejected by browsers")
            elif _is_public_suffix(normalized):
                result.add_finding("HIGH", label, f"Domain='{domain}' scopes the cookie to a bare public suffix; this is invalid and browsers should reject it, but it signals a serious misconfiguration if accepted")
            elif ctx.host and not (ctx.host == normalized or ctx.host.endswith("." + normalized)):
                result.add_finding("MEDIUM", label, f"Domain='{domain}' does not domain-match the response host '{ctx.host}'; browsers reject this cookie, which indicates a misconfigured proxy or application")
            else:
                severity = "LOW" if is_sensitive and normalized != ctx.host else "INFO"
                result.add_finding(severity, label, f"Domain='{domain}' shares this cookie across all matching subdomains; ensure every subdomain is equally trusted")
        if path is not None and not path.startswith("/"):
            result.add_finding("LOW", label, f"Path='{path}' does not start with '/'; browsers ignore it and fall back to the default path")

    def _check_lifetime(self, label: str, attrs: Dict[str, str], is_sensitive: bool, category: Optional[str], ctx: _Context) -> Optional[float]:
        result = ctx.result
        max_age = attrs.get("max-age")
        seconds: Optional[int] = None
        if max_age is not None:
            try:
                seconds = int(max_age.strip())
            except ValueError:
                result.add_finding("LOW", label, f"Max-Age is not an integer: '{max_age}'; browsers ignore it")

        expires_raw = attrs.get("expires")
        expires_epoch = _parse_expires(expires_raw)
        if expires_raw and expires_epoch is None:
            result.add_finding("LOW", label, f"Expires value could not be parsed as an HTTP date: '{expires_raw[:40]}'")

        lifetime: Optional[float] = None
        if seconds is not None:
            lifetime = float(seconds)
            if expires_epoch is not None and abs((expires_epoch - ctx.reference_epoch) - seconds) > 86400:
                result.add_finding("INFO", label, "Max-Age and Expires disagree by more than a day; browsers use Max-Age and ignore Expires")
        elif expires_epoch is not None:
            lifetime = expires_epoch - ctx.reference_epoch

        if lifetime is not None:
            if lifetime <= 0:
                result.add_finding("INFO", label, "Expiry is in the past (Max-Age <= 0 or old Expires); this clears the cookie immediately")
            elif lifetime > CHROME_MAX_LIFETIME_SECONDS:
                result.add_finding("LOW", label, f"Very long-lived cookie ({int(lifetime // 86400)} days); Chromium caps cookie lifetime at 400 days")
            elif is_sensitive and lifetime > 30 * 86400:
                result.add_finding("LOW", label, f"Session-like cookie persists for {int(lifetime // 86400)} days; consider a shorter-lived token with refresh")
        elif is_sensitive:
            result.add_finding("OK", label, "No Max-Age/Expires; this is a session cookie cleared when the browser closes")
        return lifetime

    def _check_special_cookies(self, name: str, value: str, fingerprint: Optional[Dict[str, str]], label: str, ctx: _Context) -> None:
        result = ctx.result
        lower_name = name.lower()
        decoded_value = unquote(value)

        if lower_name.startswith("bigipserver"):
            decoded = decode_bigip(decoded_value)
            pool = name[len("BIGipServer"):]
            if decoded:
                severity = "MEDIUM" if decoded["scope"] in ("private", "loopback", "link-local") else "LOW"
                route = f", route domain {decoded['route_domain']}" if decoded["route_domain"] is not None else ""
                result.add_finding(severity, label, f"F5 BIG-IP persistence cookie discloses the backend member {decoded['address']}:{decoded['port']} ({decoded['scope']}{route}, pool '{pool}')")
            else:
                result.add_finding("INFO", label, f"F5 BIG-IP persistence cookie exposes the pool name '{pool}'; the member value could not be decoded (possibly encrypted)")
            return

        if re.match(r"^ts[0-9a-f]{8}(?:[0-9a-f]{3})?$", lower_name):
            suffix = f", suffix '{name[10:]}'" if name[10:] else ""
            result.add_finding("INFO", label, f"F5 BIG-IP ASM / Advanced WAF TS cookie (id '{name[2:10]}'{suffix}); the value is an opaque {len(value)}-character state token and carries no decodable backend address")
            lead = value[:16].lower()
            if re.match(r"^[0-9a-f]{16}$", lead):
                result.add_finding("INFO", label, f"Value begins with the 16-hex segment '{lead}'")

        if fingerprint and fingerprint["category"] == "load_balancer":
            for item in find_addresses(decoded_value):
                severity = "MEDIUM" if item["scope"] in ("private", "loopback", "link-local", "internal-hostname") else "LOW"
                result.add_finding(severity, label, f"Load balancer cookie value reveals a backend address: {item['address']} ({item['scope']})")
            if lower_name.startswith("nsc_"):
                result.add_finding("INFO", label, "Citrix NetScaler persistence cookie; its name is derived from the virtual server and its value may encode the backend")

        if lower_name == "rememberme":
            if decoded_value == "deleteMe":
                result.add_finding("INFO", label, "rememberMe=deleteMe is the Apache Shiro response to an unauthenticated request; Shiro is deployed on this endpoint")
            elif len(decoded_value) >= 100:
                result.add_finding("MEDIUM", label, "Apache Shiro rememberMe cookie carries an encrypted serialized principal; confirm Shiro is fully patched and that the AES key is not the default or shared")

    def _emit_value_findings(self, label: str, profile: Dict[str, Any], is_sensitive: bool, ctx: _Context, cleared: bool = False) -> None:
        result = ctx.result
        for severity, detail, scope in profile["signals"]:
            result.add_finding(severity, f"{scope} {label}", detail)

        kind = profile["type"]
        value_header = f"Value {label}"

        if kind == "empty":
            result.add_finding("INFO", value_header, "Empty value")
            return

        if cleared and is_sensitive and kind in ("numeric", "hex-token", "opaque-token", "opaque"):
            # A cleared/placeholder value ("deleteMe", "0", an expired Max-Age=0
            # cookie, ...) isn't a real identifier; scoring its randomness or
            # guessability would just be noise.
            result.add_finding("INFO", value_header, "Value looks like a cleared/placeholder sentinel rather than a live identifier; skipping randomness and predictability analysis")
            return

        if kind == "numeric":
            if is_sensitive and profile["time_hint"]:
                result.add_finding("MEDIUM", value_header, f"Session-like cookie value is a Unix timestamp in {profile['time_hint']}; it is derived from time and therefore guessable")
            elif is_sensitive and len(profile["assessment"]["patterns"]) == 0 and profile["assessment"]["length"] >= 4:
                result.add_finding("MEDIUM", value_header, "Session-like cookie value is purely numeric; likely sequential, guessable or enumerable")
            elif is_sensitive and profile["assessment"]["length"] >= 4:
                result.add_finding("MEDIUM", value_header, f"Session-like cookie value is purely numeric with predictable structure ({', '.join(profile['assessment']['patterns'])})")
            return

        if kind == "hex-token":
            if profile["preimage"]:
                found = profile["preimage"]
                result.add_finding("HIGH", value_header, f"Value equals {found['algorithm']}('{found['preimage']}'); it is an unsalted hash of a predictable input and can be reproduced by anyone")
            elif profile["hash_candidates"] and is_sensitive:
                result.add_finding("LOW", value_header, f"Hex value of {profile['assessment']['length']} characters matches the digest size of {', '.join(profile['hash_candidates'])}; if it derives from predictable input (user id, username, timestamp) it can be reproduced, so confirm it is random")

        if kind in ("hex-token", "opaque-token", "opaque"):
            self._emit_entropy(value_header, profile["assessment"], ctx, is_sensitive)

    def _emit_entropy(self, header: str, assessment: Dict[str, Any], ctx: _Context, sensitive: bool = True) -> None:
        result = ctx.result
        rating = rate_strength(assessment)
        bits = assessment["estimated_bits"]
        detail_core = f"{assessment['length']} chars, {assessment['charset']} alphabet, Shannon {assessment['shannon_bits_per_char']} bits/char, uniformity {assessment['uniformity']}"
        if rating == "predictable":
            patterns = ", ".join(assessment["patterns"]) or "uneven character distribution"
            severity = "MEDIUM" if sensitive else "INFO"
            result.add_finding(severity, header, f"Low-randomness value ({patterns}; {detail_core}); session-like cookies should be unpredictable")
        elif rating == "weak":
            severity = ("HIGH" if bits < 32 else "MEDIUM") if sensitive else "INFO"
            result.add_finding(severity, header, f"Estimated entropy is about {bits:.0f} bits ({detail_core}); OWASP recommends at least 64 bits for session identifiers")
        else:
            result.add_finding("OK", header, f"Value looks like an opaque random token, estimated {bits:.0f} bits of entropy ({rating}; {detail_core})")

    def _check_duplicates(self, set_cookies: List[Dict[str, Any]], ctx: _Context) -> None:
        result = ctx.result
        scopes: Dict[str, Set[Tuple[str, str]]] = {}
        exact: Dict[Tuple[str, str, str], int] = {}
        for cookie in set_cookies:
            domain = cookie["attrs"].get("domain", "").lstrip(".").lower() or ctx.host
            path = cookie["attrs"].get("path") or "/"
            scopes.setdefault(cookie["name"], set()).add((domain, path))
            key = (cookie["name"], domain, path)
            exact[key] = exact.get(key, 0) + 1
        for (name, domain, path), count in exact.items():
            if count > 1:
                result.add_finding("INFO", f"Set-Cookie ({name})", f"Cookie is set {count} times in one response for the same Domain/Path; only the last value survives")
        for name, scope_set in scopes.items():
            if len(scope_set) > 1:
                described = "; ".join(f"{domain}{path}" for domain, path in sorted(scope_set)[:4])
                result.add_finding("LOW", f"Set-Cookie ({name})", f"Cookie is set with multiple Domain/Path scopes ({described}); same-name cookies can shadow each other and enable cookie tossing")

    def _check_sizes(self, set_cookies: List[Dict[str, Any]], raw_request_cookie: Optional[str], ctx: _Context) -> None:
        result = ctx.result
        for cookie in set_cookies:
            size = len(cookie["name"]) + 1 + len(cookie["value"])
            if size > MAX_COOKIE_BYTES:
                result.add_finding("MEDIUM", f"Set-Cookie ({cookie['name']})", f"Cookie is {size} bytes; browsers drop cookies above roughly {MAX_COOKIE_BYTES} bytes, and large values often indicate client-side state storage")
        if raw_request_cookie and len(raw_request_cookie) > MAX_COOKIE_HEADER_BYTES:
            result.add_finding("LOW", "Cookie header", f"Request Cookie header is {len(raw_request_cookie)} bytes; many servers reject headers above 8 KB (HTTP 400/431), and oversized jars hint at cookie bloat")
        if len(set_cookies) > 30:
            result.add_finding("LOW", "Set-Cookie", f"{len(set_cookies)} cookies are set in a single response; browsers cap cookies per domain and the excess evicts older cookies")

    def _check_response_context(self, set_meta: List[Dict[str, Any]], ctx: _Context) -> None:
        result = ctx.result
        headers = ctx.response.headers
        status = ctx.response.status_code
        sensitive_names = [meta["name"] for meta in set_meta if meta["sensitive"] and meta["category"] != "csrf"]

        if sensitive_names:
            cache_control = _cache_directives(self._get_header(headers, "Cache-Control"))
            age = self._get_header(headers, "Age")
            cache_hit = False
            if age and age.strip().isdigit() and int(age.strip()) > 0:
                cache_hit = True
            for header_name in ("X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Served-By"):
                header_value = (self._get_header(headers, header_name) or "").lower()
                if "hit" in header_value:
                    cache_hit = True
            names = ", ".join(sensitive_names[:4])
            if cache_hit:
                result.add_finding("HIGH", "Set-Cookie caching", f"Response setting session cookie(s) ({names}) was served from a shared cache; another user may receive this session")
            elif "public" in cache_control or "s-maxage" in cache_control:
                result.add_finding("HIGH", "Set-Cookie caching", f"Response setting session cookie(s) ({names}) is explicitly shareable via Cache-Control; a cache may replay the Set-Cookie to other users")
            elif not (cache_control & {"no-store", "private", "no-cache"}):
                result.add_finding("MEDIUM", "Set-Cookie caching", f"Response setting session cookie(s) ({names}) lacks Cache-Control no-store/private; intermediary caches may store it")

        if ctx.is_https and sensitive_names:
            hsts = self._get_header(headers, "Strict-Transport-Security")
            if not hsts:
                result.add_finding("LOW", "Set-Cookie transport", "Sensitive cookies are issued without Strict-Transport-Security; a first visit or downgrade to HTTP can expose them")
            else:
                directives = self._parse_directives(hsts)
                wide = [meta["name"] for meta in set_meta if meta["sensitive"] and meta["domain"]]
                if wide and "includesubdomains" not in directives:
                    result.add_finding("LOW", "Set-Cookie transport", f"Domain-scoped cookie(s) ({', '.join(wide[:3])}) are shared with subdomains but HSTS lacks includeSubDomains; a plaintext subdomain can overwrite or observe them")

        credentials = (self._get_header(headers, "Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        if credentials:
            cross_site = [meta["name"] for meta in set_meta if meta["sensitive"] and meta["samesite"] == "none"]
            if cross_site:
                result.add_finding("MEDIUM", "Set-Cookie CORS", f"Credentialed CORS is enabled and cookie(s) ({', '.join(cross_site[:3])}) use SameSite=None; cross-origin pages can ride the session if origin validation is weak")

        location = self._get_header(headers, "Location") or ""
        if ctx.is_https and 300 <= status < 400 and location.lower().startswith("http://") and set_meta:
            result.add_finding("MEDIUM", "Set-Cookie redirect", "Cookies are set on a response redirecting to plaintext HTTP; the follow-up request may expose them if they lack Secure")
        if status in (401, 403) and sensitive_names:
            result.add_finding("INFO", "Set-Cookie status", f"Session cookie(s) ({', '.join(sensitive_names[:3])}) are issued on an HTTP {status} response; verify no authenticated state is created for denied requests")

    def _check_auth_flow(self, set_cookies: List[Dict[str, Any]], request_cookies: List[Tuple[str, str]], ctx: _Context) -> None:
        result = ctx.result
        response = ctx.response
        if not ctx.host:
            return
        path = urlsplit(response.url or "").path
        status = response.status_code
        method = (response.method or "").upper()
        issued = {cookie["name"]: cookie for cookie in set_cookies}

        auth_cookies = []
        for name, value in request_cookies:
            fingerprint = identify_cookie(name)
            category = fingerprint["category"] if fingerprint else None
            if category in CLIENT_READABLE_CATEGORIES or category in ("csrf", "load_balancer", "cdn_waf", "bot_protection"):
                continue
            if is_sensitive_name(name) or category in ("session", "auth"):
                auth_cookies.append((name, value))

        stored = self._pre_auth_values.get(ctx.host, {})
        for name, value in auth_cookies:
            if stored.get(name) == value and ("fixation", ctx.host, name) not in self._reported:
                self._reported.add(("fixation", ctx.host, name))
                result.add_finding("MEDIUM", f"Cookie ({name})", "Session cookie value used after a login-like request is identical to the pre-authentication value; if that login succeeded, the identifier was not rotated (session fixation)")

        if method == "POST" and LOGIN_PATH_PATTERN.search(path) and 200 <= status < 400:
            for name, value in auth_cookies:
                reissued = issued.get(name)
                if reissued is not None and reissued["value"] == value:
                    result.add_finding("MEDIUM", f"Set-Cookie ({name})", "Login-like request re-issues the session cookie with the same value it arrived with; the identifier is not rotated on authentication (session fixation)")
                elif reissued is None:
                    self._pre_auth_values.setdefault(ctx.host, {})[name] = value

        if LOGOUT_PATH_PATTERN.search(path) and 200 <= status < 400:
            for name, value in auth_cookies:
                reissued = issued.get(name)
                cleared = False
                if reissued is not None:
                    attrs = reissued["attrs"]
                    max_age = attrs.get("max-age")
                    expires_epoch = _parse_expires(attrs.get("expires"))
                    if reissued["value"] == "":
                        cleared = True
                    if max_age is not None and max_age.strip().lstrip("-").isdigit() and int(max_age.strip()) <= 0:
                        cleared = True
                    if expires_epoch is not None and expires_epoch <= ctx.reference_epoch:
                        cleared = True
                if not cleared:
                    result.add_finding("MEDIUM", f"Cookie ({name})", "Logout-like request does not clear this session cookie; verify the session is invalidated server-side, otherwise the captured value stays usable")

    def _track_samples(self, set_cookies: List[Dict[str, Any]], set_meta: List[Dict[str, Any]], ctx: _Context) -> None:
        if not ctx.host:
            return
        # set_cookies and set_meta are built together in run(), so they line up
        # positionally - this avoids misattributing values when the same cookie
        # name is set more than once in a single response (e.g. shadowed paths).
        for cookie, meta in zip(set_cookies, set_meta):
            if not meta["sensitive"] or meta["value_type"] not in SAMPLED_TYPES:
                continue
            value = cookie["value"]
            if not value:
                continue
            samples = self._samples.setdefault((ctx.host, meta["name"]), [])
            if value in samples or len(samples) >= MAX_SAMPLES_PER_COOKIE:
                continue
            samples.append(value)
            if len(samples) in SAMPLE_THRESHOLDS:
                for severity, detail in analyze_samples(samples):
                    ctx.result.add_finding(severity, f"Set-Cookie ({meta['name']}) samples", detail)

    def _check_privacy(self, set_meta: List[Dict[str, Any]], request_meta: List[Dict[str, Any]], ctx: _Context) -> None:
        result = ctx.result
        if not ctx.host:
            return
        consent_seen = any(meta["category"] == "consent" for meta in set_meta + request_meta)
        if consent_seen:
            self._consent_hosts.add(ctx.host)

        tracking = [meta for meta in set_meta if meta["category"] == "tracking"]
        if tracking:
            vendors = sorted({meta["fingerprint"] for meta in tracking if meta["fingerprint"]})
            names = ", ".join(meta["name"] for meta in tracking[:6])
            result.add_finding("INFO", "Privacy", f"Tracking cookies set ({names}); vendors: {', '.join(vendors)}")
            if ctx.host not in self._consent_hosts:
                result.add_finding("LOW", "Privacy", f"Tracking cookies are set while no consent cookie has been observed for {ctx.host}; verify consent gating under GDPR/ePrivacy")
            for meta in tracking:
                lifetime = meta["lifetime_seconds"]
                if lifetime is not None and lifetime > CONSENT_TRACKING_LIFETIME_SECONDS:
                    result.add_finding("LOW", f"Privacy ({meta['name']})", f"Tracking cookie lives {int(lifetime // 86400)} days, beyond the 13-month ceiling commonly recommended by data protection authorities")

    def _build_summary(self, set_meta: List[Dict[str, Any]], request_meta: List[Dict[str, Any]], ctx: _Context) -> Dict[str, Any]:
        categories: Dict[str, int] = {}
        seen_names: Set[str] = set()
        for meta in set_meta + request_meta:
            if meta["name"] in seen_names:
                continue
            seen_names.add(meta["name"])
            key = meta["category"] or "uncategorized"
            categories[key] = categories.get(key, 0) + 1

        counts = ", ".join(f"{key}={count}" for key, count in sorted(categories.items()))
        ctx.result.add_finding("INFO", "Cookie Inventory", f"{len(set_meta)} Set-Cookie and {len(request_meta)} request cookie(s); categories: {counts}")

        worst = "OK"
        for finding in ctx.result.findings:
            severity = finding.get("severity", "INFO")
            if SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(worst, 99):
                worst = severity

        return {
            "set_cookie_count": len(set_meta),
            "request_cookie_count": len(request_meta),
            "categories": categories,
            "sensitive_cookies": sorted({meta["name"] for meta in set_meta + request_meta if meta["sensitive"]}),
            "tracking_vendors": sorted({meta["fingerprint"] for meta in set_meta + request_meta if meta["category"] == "tracking" and meta["fingerprint"]}),
            "worst_severity": worst,
        }

    def _reference_epoch(self, response: HTTPResponse) -> float:
        timestamp = response.timestamp
        if timestamp:
            try:
                return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
        return time.time()