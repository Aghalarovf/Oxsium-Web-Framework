"""
modules/captcha_bot.py - CAPTCHA and Bot-Protection Detection Module.

Detection strategy
──────────────────
1. HTML body scan – parse the homepage HTML for well-known CAPTCHA service
   script tags, sitekey attributes, form field names, and container IDs
   (Google reCAPTCHA, hCaptcha, Cloudflare Turnstile, FriendlyCaptcha, …).

2. Header fingerprinting – some bot-protection platforms inject custom
   response headers (e.g. "cf-mitigated: challenge").

3. JavaScript challenge detection – identify Cloudflare's JS challenge
   (__cf_chl_f_tk, jschl_vc, cf_chl_prog) and similar client-side
   challenge patterns that cannot be solved by a plain HTTP client.

4. Login-form CAPTCHA probe – fetch /login and /register and repeat the
   body scan, since CAPTCHA widgets are most commonly placed on auth forms.

5. Bot-score header analysis – report Akamai Bot Manager, DataDome,
   PerimeterX, and similar headers that expose bot detection verdicts.

6. Honeypot & hidden-field detection – look for form fields designed to
   trap bots (type="hidden" fields not shown to humans, aria-hidden inputs).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from core.exporter import Finding, Severity
from core.logger import get_logger
from core.requester import Requester, Response

log = get_logger("captcha_bot")


# ── CAPTCHA provider signatures ───────────────────────────────────────────────
#
# Each entry maps a human-readable provider name to detection rules.
# Rules are applied to the response body; all patterns are case-insensitive.

CAPTCHA_BODY_SIGNATURES: Dict[str, List[str]] = {
    "Google reCAPTCHA v2 (checkbox)": [
        r"google\.com/recaptcha",
        r"g-recaptcha",
        r"data-sitekey",
        r"grecaptcha\.render",
    ],
    "Google reCAPTCHA v3 (invisible)": [
        r"recaptcha/api\.js\?render=",
        r"grecaptcha\.execute",
        r"grecaptcha\.ready",
    ],
    "hCaptcha": [
        r"hcaptcha\.com/1/api\.js",
        r"h-captcha",
        r"data-hcaptcha-sitekey",
        r"hcaptcha\.render",
    ],
    "Cloudflare Turnstile": [
        r"challenges\.cloudflare\.com/turnstile",
        r"cf-turnstile",
        r"data-sitekey.*turnstile",
        r"turnstile\.render",
    ],
    "FriendlyCaptcha": [
        r"friendlycaptcha\.com",
        r"frc-captcha",
        r"FriendlyCaptcha\.auto\.render",
    ],
    "Arkose Labs (FunCaptcha)": [
        r"funcaptcha\.com",
        r"arkoselabs\.com",
        r"fc-token",
        r"data-callback.*arko",
    ],
    "AWS WAF CAPTCHA": [
        r"captcha\.us-east-1\.amazonaws\.com",
        r"awswaf.*captcha",
        r"AwsWafIntegration\.checkUrl",
    ],
    "GeeTest": [
        r"geetest\.com/typeb/",
        r"initGeetest",
        r"geetest_validate",
    ],
    "Capy Puzzle CAPTCHA": [
        r"capy\.me/assets/captcha",
        r"capy-captcha",
    ],
    "KeyCAPTCHA": [
        r"keycaptcha\.com",
        r"s_s_c_user_id",
    ],
}

# ── JavaScript challenge signatures (Cloudflare & similar) ───────────────────

JS_CHALLENGE_PATTERNS: List[Tuple[str, str]] = [
    # Pattern, description
    (r"__cf_chl_f_tk",            "Cloudflare JS challenge token field"),
    (r"cf_chl_prog",              "Cloudflare challenge progress variable"),
    (r"jschl_vc",                 "Cloudflare IUAM jschl answer field"),
    (r"__cf_chl_opt",             "Cloudflare challenge options object"),
    (r"datadome",                 "DataDome bot-protection JS"),
    (r"_perimeterx",              "PerimeterX bot sensor"),
    (r"px\.init",                 "PerimeterX pixel initialisation"),
    (r"kasada",                   "Kasada bot protection"),
    (r"_shieldsquare",            "ShieldSquare / Radware bot manager"),
    (r"FingerprintJS",            "FingerprintJS device fingerprinting"),
    (r"iovation\.loader",         "iovation device intelligence"),
    (r"ThreatMetrix",             "ThreatMetrix fraud detection"),
]

# ── Bot-management response headers ──────────────────────────────────────────

BOT_HEADERS: Dict[str, str] = {
    "cf-mitigated":                "Cloudflare mitigation verdict",
    "x-datadome-isbot":            "DataDome bot verdict",
    "x-datadome-cid":              "DataDome client ID",
    "x-px-score":                  "PerimeterX risk score",
    "x-px-bypass":                 "PerimeterX bypass flag",
    "x-akamai-bot-score":          "Akamai Bot Manager score",
    "x-akamai-edgescape":          "Akamai edge properties",
    "x-bot-score":                 "Generic bot score header",
    "x-threat-score":              "Generic threat score header",
    "x-perimeterx-device-id":      "PerimeterX device ID",
}

# ── Endpoints likely to have CAPTCHA on their forms ──────────────────────────

AUTH_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/register",
    "/signup",
    "/sign-up",
    "/account/login",
    "/user/login",
    "/wp-login.php",
    "/forgot-password",
    "/reset-password",
    "/contact",
    "/contact-us",
]

# ── Honeypot field heuristics ─────────────────────────────────────────────────

HONEYPOT_PATTERNS = [
    r'<input[^>]+type=["\']hidden["\'][^>]+name=["\'](?:url|website|hp|honeypot|bot_field|winnie|trap)["\']',
    r'style=["\'][^"\']*display:\s*none[^"\']*["\'][^>]*<input',
    r'aria-hidden=["\']true["\'][^>]*>.*?<input',
    r'class=["\'][^"\']*(?:honeypot|bot-trap|hp-field)[^"\']*["\']',
]


class CaptchaBotModule:
    """
    Identify CAPTCHA widgets and bot-protection mechanisms on the target.

    Parameters
    ----------
    target    : Normalised base URL of the target.
    requester : Shared Requester instance.
    """

    MODULE_NAME = "captcha"

    def __init__(self, target: str, requester: Requester) -> None:
        self.target    = target
        self.requester = requester
        self._findings: List[Finding] = []

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        """Run all CAPTCHA and bot-protection detection strategies."""
        log.info(f"CAPTCHA/bot detection started → {self.target}")

        # Homepage analysis
        homepage = self.requester.get(self.target)
        if homepage:
            self._scan_body_for_captcha(homepage, path="/")
            self._scan_js_challenges(homepage, path="/")
            self._scan_bot_headers(homepage, path="/")
        else:
            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title="Homepage request failed",
                severity=Severity.INFO,
                detail="Could not fetch the homepage; CAPTCHA detection may be incomplete.",
            ))

        # Auth / high-value form endpoints
        self._probe_auth_endpoints()

        if not self._findings:
            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title="No CAPTCHA or bot-protection detected",
                severity=Severity.INFO,
                detail=(
                    "No known CAPTCHA provider signatures, JS challenge scripts, "
                    "or bot-management headers were found. The target may rely "
                    "on server-side bot detection not visible in HTML/headers, "
                    "or may have no protection at all."
                ),
            ))

        log.info(f"CAPTCHA detection finished – {len(self._findings)} finding(s).")
        return self._findings

    # ── Layer 1: body CAPTCHA signatures ─────────────────────────────────────

    def _scan_body_for_captcha(self, resp: Response, path: str) -> None:
        """
        Search the response body for CAPTCHA provider script tags, widget
        containers, and sitekey attributes.
        """
        log.debug(f"Scanning body for CAPTCHA signatures ({path}) …")

        for provider, patterns in CAPTCHA_BODY_SIGNATURES.items():
            matched = [
                p for p in patterns
                if re.search(p, resp.body, re.IGNORECASE | re.DOTALL)
            ]
            if matched:
                # Try to extract the sitekey for intelligence gathering
                sitekey = self._extract_sitekey(resp.body)
                evidence = [f"Matched pattern: {p}" for p in matched]
                if sitekey:
                    evidence.append(f"Sitekey: {sitekey}")

                self._findings.append(Finding(
                    module=self.MODULE_NAME,
                    title=f"CAPTCHA detected: {provider} – {path}",
                    severity=Severity.MEDIUM,
                    detail=(
                        f"{provider} was identified on '{path}'. "
                        f"Automated form submissions and brute-force attacks "
                        f"on this endpoint require CAPTCHA solving."
                    ),
                    evidence=evidence,
                ))
                log.info(f"CAPTCHA found: {provider} on {path}")

        # Honeypot field check
        self._check_honeypot_fields(resp, path)

    def _extract_sitekey(self, body: str) -> Optional[str]:
        """
        Attempt to extract a reCAPTCHA or hCaptcha sitekey from the HTML.

        Returns the sitekey string or None if not found.
        """
        patterns = [
            r'data-sitekey=["\']([0-9A-Za-z_\-]{20,})["\']',
            r'sitekey:\s*["\']([0-9A-Za-z_\-]{20,})["\']',
            r'recaptcha/api\.js\?.*render=([0-9A-Za-z_\-]{20,})',
        ]
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    # ── Layer 2: JavaScript challenge detection ───────────────────────────────

    def _scan_js_challenges(self, resp: Response, path: str) -> None:
        """
        Look for client-side bot-challenge scripts that a headless HTTP
        client cannot solve (Cloudflare IUAM, DataDome, PerimeterX, …).
        """
        log.debug(f"Scanning for JS challenge patterns ({path}) …")

        for pattern, description in JS_CHALLENGE_PATTERNS:
            if re.search(pattern, resp.body, re.IGNORECASE):
                self._findings.append(Finding(
                    module=self.MODULE_NAME,
                    title=f"JavaScript bot challenge detected – {path}",
                    severity=Severity.HIGH,
                    detail=(
                        f"A JavaScript-based bot-challenge was identified on "
                        f"'{path}': {description}. "
                        f"Standard HTTP clients will fail to interact with this "
                        f"endpoint; a headless browser or challenge-solver is required."
                    ),
                    evidence=[
                        f"Pattern matched : {pattern}",
                        f"Description     : {description}",
                    ],
                ))
                log.info(f"JS challenge detected on {path}: {description}")
                # One JS challenge per page is sufficient – avoid duplicates
                return

    # ── Layer 3: bot-management header inspection ─────────────────────────────

    def _scan_bot_headers(self, resp: Response, path: str) -> None:
        """
        Check response headers for bot-management platform fingerprints
        (score values, verdict flags, session IDs, …).
        """
        log.debug(f"Scanning bot-management headers ({path}) …")

        found_headers: List[str] = []
        for header_name, description in BOT_HEADERS.items():
            value = resp.header(header_name)
            if value:
                found_headers.append(f"{header_name}: {value}  ({description})")

        if found_headers:
            self._findings.append(Finding(
                module=self.MODULE_NAME,
                title=f"Bot-management platform headers detected – {path}",
                severity=Severity.MEDIUM,
                detail=(
                    f"Response headers on '{path}' reveal active bot-management "
                    f"or risk-scoring. These headers expose detection verdicts "
                    f"that could help an attacker tune their bypass strategy."
                ),
                evidence=found_headers,
            ))

    # ── Layer 4: auth-form endpoint probing ──────────────────────────────────

    def _probe_auth_endpoints(self) -> None:
        """
        Fetch authentication and contact-form pages and scan them for CAPTCHA
        widgets, since these are the most common placement targets.
        """
        log.debug("Probing auth/form endpoints for CAPTCHA …")

        probed = 0
        for path in AUTH_PATHS:
            url  = self.target + path
            resp = self.requester.get(url)

            if resp is None or resp.status_code in (404, 410, 500, 503):
                # Endpoint does not exist or is broken – skip silently
                continue

            probed += 1
            log.debug(f"Probing {path} ({resp.status_code}) …")
            self._scan_body_for_captcha(resp, path)
            self._scan_js_challenges(resp, path)
            self._scan_bot_headers(resp, path)

            # Don't hammer the server – only probe up to 5 auth paths
            if probed >= 5:
                break

    # ── Layer 5: honeypot / hidden-field detection ────────────────────────────

    def _check_honeypot_fields(self, resp: Response, path: str) -> None:
        """
        Look for hidden form fields designed to trap bots.

        Honeypot fields are invisible to humans (CSS-hidden or aria-hidden)
        but visible to bots that parse raw HTML.  If a form submission
        populates them, the server assumes it is a bot.
        """
        log.debug(f"Checking for honeypot fields ({path}) …")

        for pattern in HONEYPOT_PATTERNS:
            if re.search(pattern, resp.body, re.IGNORECASE | re.DOTALL):
                self._findings.append(Finding(
                    module=self.MODULE_NAME,
                    title=f"Honeypot / hidden bot-trap field detected – {path}",
                    severity=Severity.LOW,
                    detail=(
                        f"A hidden or CSS-invisible form field consistent with "
                        f"a honeypot bot-trap was found on '{path}'. "
                        f"Automated form-submission tools must detect and skip "
                        f"such fields to avoid triggering the protection."
                    ),
                    evidence=[f"Matched pattern: {pattern}"],
                ))
                log.info(f"Honeypot field found on {path}")
                return   # One finding per page is sufficient