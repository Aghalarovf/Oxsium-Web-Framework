from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse, parse_qs

from modules.base import BaseArchiveModule

SENSITIVE_KEYS: set[str] = {
    "token", "access_token", "refresh_token", "id_token", "bearer",
    "auth", "authorization", "authenticate",
    "api_key", "apikey", "api-key", "app_key", "appkey",
    "secret", "client_secret", "app_secret",
    "password", "passwd", "pass", "pwd",
    "session", "session_id", "sessionid", "sess",
    "key", "private_key", "signing_key", "encryption_key",
    "jwt", "csrf", "xsrf", "nonce",
    "ssn", "credit_card", "card_number", "cvv", "ccnum",
    "user", "username", "email", "phone", "mobile",
    "redirect", "redirect_uri", "next", "return_url", "callback",
    "sql", "query", "search", "filter", "where",
    "file", "path", "dir", "folder", "upload", "download",
    "cmd", "exec", "command", "shell", "eval",
    "debug", "test", "dev", "admin", "root",
}

SENSITIVE_VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_key",       re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt",           re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("generic_token", re.compile(r"[a-f0-9]{32,}")),
    ("base64_secret", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("google_api",    re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("github_token",  re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("slack_token",   re.compile(r"xox[baprs]-[A-Za-z0-9\-]+")),
    ("private_key",   re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    ("session_id",    re.compile(r"[A-Za-z0-9]{26,64}")),
]

class ParamMinerModule(BaseArchiveModule):

    async def run(self, urls: list[str] | None = None) -> dict[str, Any]:
        if urls is None:
            urls = getattr(self, "input_urls", [])

        self.logger.info(f"Param mining started → {len(urls)} URLs")

        all_params      = self.extract_query_params(urls)
        sensitive_keys  = self.detect_sensitive_keys(all_params)
        exposed_values  = self.detect_exposed_values(urls)
        wordlist        = self.generate_fuzzing_wordlist(all_params)
        param_urls      = self.extract_param_urls(urls)

        stats = {
            "total_urls":       len(urls),
            "unique_params":    len(all_params),
            "sensitive_keys":   len(sensitive_keys),
            "exposed_values":   len(exposed_values),
            "wordlist_size":    len(wordlist),
            "param_urls":       len(param_urls),
        }

        self.logger.success(
            f"Mining complete – "
            f"Params:{stats['unique_params']} | "
            f"Sensitive:{stats['sensitive_keys']} | "
            f"Exposed:{stats['exposed_values']} | "
            f"ParamURLs:{stats['param_urls']}"
        )

        return {
            "params":         all_params,
            "sensitive_keys": sensitive_keys,
            "exposed_values": exposed_values,
            "param_urls":     param_urls,
            "stats":          stats,
        }

    def extract_query_params(self, urls: list[str]) -> dict[str, int]:
        counter: Counter = Counter()

        for url in urls:
            if not url:
                continue
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                for key in params:
                    counter[key.lower().strip()] += 1
            except Exception:
                continue

        return dict(counter.most_common())

    def detect_sensitive_keys(self, params: dict[str, int]) -> dict[str, int]:
        return {
            key: count
            for key, count in params.items()
            if key in SENSITIVE_KEYS
            or any(s in key for s in SENSITIVE_KEYS)
        }

    def detect_exposed_values(self, urls: list[str]) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        seen: set[str] = set()

        for url in urls:
            if not url:
                continue
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue

            for key, values in params.items():
                key_lower = key.lower().strip()
                if key_lower not in SENSITIVE_KEYS and not any(s in key_lower for s in SENSITIVE_KEYS):
                    continue
                for value in values:
                    if not value or len(value) < 8:
                        continue
                    for label, pattern in SENSITIVE_VALUE_PATTERNS:
                        if pattern.search(value):
                            fingerprint = f"{key}:{value[:32]}"
                            if fingerprint not in seen:
                                seen.add(fingerprint)
                                findings.append({
                                    "url":   url,
                                    "param": key,
                                    "value": value[:128],
                                    "type":  label,
                                })
                            break

        return findings

    def extract_param_urls(self, urls: list[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}

        for url in urls:
            if not url:
                continue
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue

            for key in params:
                key_clean = key.lower().strip()
                if key_clean not in result:
                    result[key_clean] = []
                if url not in result[key_clean]:
                    result[key_clean].append(url)

        return dict(sorted(result.items()))

    def generate_fuzzing_wordlist(self, params: dict[str, int]) -> list[str]:
        base_params = sorted(params.keys())

        wordlist: set[str] = set(base_params)

        for param in base_params:
            wordlist.add(param + "[]")
            wordlist.add(param + "[0]")
            wordlist.add(param + "_id")
            wordlist.add(param + "_key")
            wordlist.add(param + "_token")
            wordlist.add(param + "2")
            wordlist.add("old_" + param)
            wordlist.add("new_" + param)
            wordlist.add("debug_" + param)
            wordlist.add("test_" + param)

        for key in SENSITIVE_KEYS:
            wordlist.add(key)

        return sorted(wordlist)