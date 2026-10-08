from __future__ import annotations

import base64
import json
import re

import requests

from core import BaseSource, SourceError, clean_names, request_with_retry

CERTSEARCH_URL = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"
CERTBYHASH_URL = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash"
MAX_HASHES = 50
HASH_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")


def _strip_jsonp_prefix(text: str) -> str:
    if text.startswith(")]}'"):
        text = text[4:]
    return text.lstrip("\r\n")


def _collect_base64_values(node) -> list[str]:
    found: list[str] = []
    if isinstance(node, str):
        if HASH_RE.match(node):
            found.append(node)
    elif isinstance(node, list):
        for item in node:
            found.extend(_collect_base64_values(item))
    elif isinstance(node, dict):
        for value in node.values():
            found.extend(_collect_base64_values(value))
    return found


def _extract_names_from_der(der: bytes) -> set[str]:
    names: set[str] = set()
    for run in re.findall(rb"[A-Za-z0-9](?:[A-Za-z0-9._-]{2,251}[A-Za-z0-9])?", der):
        text = run.decode("ascii", "ignore").lower()
        if "." not in text or re.fullmatch(r"\d+(?:\.\d+)+", text):
            continue
        tld = text.rsplit(".", 1)[-1]
        if len(tld) < 2 or not tld.isalpha():
            continue
        names.add(text)
    return names


class GoogleCT(BaseSource):
    name = "googlect"
    description = "Google Transparency Report CT search (undocumented API; currently down)"
    enabled = False
    default_timeout = 20

    def fetch(self, domain: str) -> set[str]:
        params = {"include_expired": "true", "include_subdomains": "true", "domain": domain}
        try:
            resp = request_with_retry(
                self.session, "GET", CERTSEARCH_URL, params=params, timeout=self.timeout
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                self.log("Google CT endpoint returned 404 - API appears discontinued")
                return set()
            raise SourceError(f"googlect request failed: {exc}") from exc

        try:
            data = json.loads(_strip_jsonp_prefix(resp.text))
        except ValueError as exc:
            raise SourceError(f"googlect: invalid JSON: {exc}") from exc

        hashes = _collect_base64_values(data)
        if not hashes:
            self.log("no certificate hashes in Google CT response")
            return set()

        raw: list[str] = []
        for cert_hash in hashes[:MAX_HASHES]:
            try:
                r = request_with_retry(
                    self.session, "GET", CERTBYHASH_URL,
                    params={"hash": cert_hash}, timeout=self.timeout,
                )
            except requests.HTTPError:
                continue
            try:
                cert_data = json.loads(_strip_jsonp_prefix(r.text))
            except ValueError:
                continue
            for b64 in _collect_base64_values(cert_data):
                try:
                    der = base64.b64decode(b64, validate=True)
                except (ValueError, TypeError):
                    continue
                if len(der) > 64 and der[0] == 0x30 and der[1] == 0x82:
                    raw.extend(_extract_names_from_der(der))

        return clean_names(raw, domain)
