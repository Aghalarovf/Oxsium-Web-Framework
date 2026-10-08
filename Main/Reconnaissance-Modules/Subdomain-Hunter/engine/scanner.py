from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional

import requests

from core import BaseSource, SourceError, SourceResult, normalize_domain
from core.config import USER_AGENT


def _run_source(cls: type[BaseSource], domain: str, timeout: int, verbose: bool, keys: dict) -> set[str]:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    source = cls(session=session, timeout=timeout, verbose=verbose, keys=keys)
    return source.fetch(domain)


def scan(
    domain: str,
    source_classes: Iterable[type[BaseSource]],
    *,
    max_workers: int = 5,
    timeout: int = 30,
    verbose: bool = False,
    keys: Optional[dict] = None,
) -> tuple[str, dict[str, SourceResult], list[str]]:
    domain = normalize_domain(domain)
    source_classes = list(source_classes)
    keys = keys or {}

    results: dict[str, SourceResult] = {}
    pending: list[type[BaseSource]] = []

    for cls in source_classes:
        missing = [k for k in getattr(cls, "required_keys", ()) if not keys.get(k)]
        if missing:
            print(f"[!] [{cls.name}] Skipped: missing API key(s): {', '.join(missing)}", file=sys.stderr)
            results[cls.name] = SourceResult(
                source=cls.name,
                error=f"skipped: missing API key(s): {', '.join(missing)} (add to api_keys.json)",
            )
        else:
            print(f"[*] [{cls.name}] Starting scan on {domain} ...", file=sys.stderr)
            pending.append(cls)

    if pending:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_run_source, cls, domain, timeout, verbose, keys): cls.name
                for cls in pending
            }
            for future in as_completed(futures):
                name = futures[future]
                result = SourceResult(source=name)
                try:
                    result.subdomains = future.result()
                    print(f"[+] [{name}] Authentication successful — {len(result.subdomains)} subdomain(s) found", file=sys.stderr)
                except SourceError as exc:
                    result.error = str(exc)
                    print(f"[!] [{name}] Error: {exc}", file=sys.stderr)
                except Exception as exc:
                    result.error = f"unexpected error: {exc}"
                    print(f"[!] [{name}] Unexpected error: {exc}", file=sys.stderr)
                results[name] = result

    unique = sorted({sub for res in results.values() for sub in res.subdomains})
    return domain, results, unique