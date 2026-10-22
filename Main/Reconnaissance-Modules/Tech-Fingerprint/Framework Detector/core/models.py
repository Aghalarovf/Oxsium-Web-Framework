from __future__ import annotations

import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional


def _first_present(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def _merge_all_present(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """Like _first_present, but does not stop at the first match: it walks the
    whole key list, collects every present (non-None) string value, and joins
    them together. Returns `default` if none of the keys were present."""
    collected: List[str] = []
    for key in keys:
        if key in data and data[key] is not None:
            value = data[key]
            if isinstance(value, str):
                if value and value not in collected:
                    collected.append(value)
            elif value not in (None, ""):
                collected.append(str(value))
    if not collected:
        return default
    return "\n".join(collected)


def _normalize_headers(raw: Any) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, list):
                value = ", ".join(str(item) for item in value)
            normalized[str(key).strip().lower()] = str(value)
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict) and "name" in entry and "value" in entry:
                normalized[str(entry["name"]).strip().lower()] = str(entry["value"])
            elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                normalized[str(entry[0]).strip().lower()] = str(entry[1])
    return normalized


def _extract_cookies(explicit: Any, response_headers: Dict[str, str]) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if isinstance(explicit, dict):
        for key, value in explicit.items():
            cookies[str(key)] = str(value)
    elif isinstance(explicit, list):
        for entry in explicit:
            if isinstance(entry, dict) and "name" in entry:
                cookies[str(entry["name"])] = str(entry.get("value", ""))

    set_cookie_header = response_headers.get("set-cookie")
    if set_cookie_header:
        for chunk in re.split(r",(?=[^;,]+?=)", set_cookie_header):
            parser = SimpleCookie()
            try:
                parser.load(chunk.strip())
            except Exception:
                continue
            for morsel_key, morsel in parser.items():
                cookies[morsel_key] = morsel.value

    return cookies


def _parse_cookie_header(header: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if not header:
        return cookies
    for chunk in header.split(";"):
        name, separator, value = chunk.strip().partition("=")
        if name and separator:
            cookies[name.strip()] = value.strip()
    return cookies


@dataclass
class Transaction:
    url: str
    method: str
    status: Optional[int]
    request_headers: Dict[str, str]
    response_headers: Dict[str, str]
    cookies: Dict[str, str]
    body: str
    source: str
    index: int
    meta_tags: Optional[List[Dict[str, str]]] = None
    script_urls: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], source: str, index: int) -> "Transaction":
        request_block = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        response_block = raw.get("response") if isinstance(raw.get("response"), dict) else {}

        response_headers = _normalize_headers(
            _first_present(response_block, ["headers"], None)
            or _first_present(raw, ["response_headers", "resp_headers", "headers"], {})
        )
        request_headers = _normalize_headers(
            _first_present(request_block, ["headers"], None)
            or _first_present(raw, ["request_headers", "req_headers"], {})
        )
        cookies = _extract_cookies(raw.get("cookies"), response_headers)
        for name, value in _parse_cookie_header(request_headers.get("cookie", "")).items():
            cookies.setdefault(name, value)

        status_raw = _first_present(response_block, ["status_code", "status"], None)
        if status_raw is None:
            status_raw = _first_present(raw, ["status", "status_code"], None)
        status = int(status_raw) if isinstance(status_raw, (int, str)) and str(status_raw).isdigit() else None

        body = _merge_all_present(
            response_block, ["body", "body_preview", "content", "html", "text"], None
        )
        if body is None:
            body = _merge_all_present(raw, ["body", "response_body", "html", "content"], "")
        if not isinstance(body, str):
            body = ""

        url = _first_present(request_block, ["url", "uri", "path"], None)
        if url is None:
            url = _first_present(raw, ["url", "uri", "path"], "")

        method = _first_present(request_block, ["method"], None)
        if method is None:
            method = _first_present(raw, ["method"], "GET")

        return cls(
            url=str(url),
            method=str(method).upper(),
            status=status,
            request_headers=request_headers,
            response_headers=response_headers,
            cookies=cookies,
            body=body,
            source=source,
            index=index,
        )


@dataclass
class DetectionMatch:
    framework: str
    category: str
    confidence: int
    module: str
    evidence: str
    transaction_url: str
    transaction_source: str


@dataclass
class DetectionResult:
    framework: str
    category: str
    confidence: int
    occurrences: int
    modules: List[str]
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "category": self.category,
            "confidence": self.confidence,
            "occurrences": self.occurrences,
            "modules": self.modules,
            "evidence": self.evidence,
        }