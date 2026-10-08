from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Iterable, Optional

import requests

from .config import DOMAIN_RE, ENV_FALLBACKS


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split(":")[0].rstrip(".")
    if not DOMAIN_RE.match(d):
        raise ValueError(f"Invalid domain: {domain!r}")
    return d


def clean_names(raw_names: Iterable[str], domain: str) -> set[str]:
    suffix = "." + domain
    out: set[str] = set()
    for raw in raw_names:
        if not raw:
            continue
        for piece in str(raw).splitlines():
            name = piece.strip().lower()
            name = re.sub(r"^[a-z][a-z0-9+.-]*://", "", name)
            name = name.split("/")[0].rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name == domain or not name.endswith(suffix):
                continue
            if re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", name):
                out.add(name)
    return out


def request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    attempts: int = 3,
    base_delay: float = 1.5,
    retry_statuses: tuple = (429, 500, 502, 503, 504),
    **kwargs,
) -> requests.Response:
    for attempt in range(1, attempts + 1):
        try:
            resp = session.request(method, url, **kwargs)
            if resp.status_code not in retry_statuses:
                return resp
            delay = base_delay * (2 ** (attempt - 1))
            ra = resp.headers.get("Retry-After")
            if ra and ra.isdigit():
                delay = max(delay, float(ra))
            if attempt < attempts:
                time.sleep(delay)
            else:
                resp.raise_for_status()
        except requests.RequestException:
            if attempt < attempts:
                time.sleep(base_delay * (2 ** (attempt - 1)))
            else:
                raise
    raise RuntimeError("unreachable")


def load_keys(api_keys_path: Optional[str]) -> dict:
    keys: dict[str, str] = {}
    for name, env in ENV_FALLBACKS.items():
        if os.environ.get(env):
            keys[name] = os.environ[env]

    candidates: list[str] = []
    if api_keys_path:
        candidates.append(api_keys_path)
    candidates.append(os.path.join(os.getcwd(), "api_keys.json"))
    candidates.append(
        os.path.join(os.path.expanduser("~"), ".config", "subdomain-hunter", "api_keys.json")
    )

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str) and v.strip():
                        keys[k] = v.strip()
            break
        except (OSError, ValueError) as exc:
            print(f"[!] could not read key file {path}: {exc}", file=sys.stderr)
    return keys
