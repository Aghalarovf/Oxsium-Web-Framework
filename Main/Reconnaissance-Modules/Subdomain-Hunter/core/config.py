from __future__ import annotations
import re

__version__ = "0.5.0"

USER_AGENT = "Subdomain-Hunter/0.5 (passive recon)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)

ENV_FALLBACKS = {
    "censys_id":      "CENSYS_API_ID",
    "censys_secret":  "CENSYS_API_SECRET",
    "virustotal":     "VIRUSTOTAL_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "urlscan":        "URLSCAN_API_KEY",
    "shodan":         "SHODAN_API_KEY",
    "otx":            "OTX_API_KEY",
    "hackertarget":   "HACKERTARGET_API_KEY",
    "circl_user":     "CIRCL_USER",
    "circl_pass":     "CIRCL_PASS",
}
