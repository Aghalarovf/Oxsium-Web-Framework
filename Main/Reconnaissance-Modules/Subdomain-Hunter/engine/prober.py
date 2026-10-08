from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core import CheckResult, HostInfo
from core.config import USER_AGENT


def _probe_one(subdomain: str, scheme: str, *, timeout: int, follow_redirects: bool) -> CheckResult:
    url = f"{scheme}://{subdomain}"
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=follow_redirects, verify=False, stream=True)
        status = resp.status_code
        final = resp.url if follow_redirects else None
        resp.close()
        return CheckResult(scheme=scheme, subdomain=subdomain, status=status, final_url=final)
    except requests.exceptions.SSLError:
        return CheckResult(scheme=scheme, subdomain=subdomain, error="SSL")
    except requests.exceptions.Timeout:
        return CheckResult(scheme=scheme, subdomain=subdomain, error="TIMEOUT")
    except requests.exceptions.TooManyRedirects:
        return CheckResult(scheme=scheme, subdomain=subdomain, error="REDIRECT-LOOP")
    except requests.exceptions.ConnectionError:
        return CheckResult(scheme=scheme, subdomain=subdomain, error="CONN")
    except requests.RequestException as exc:
        return CheckResult(scheme=scheme, subdomain=subdomain, error=type(exc).__name__)


def check_status_codes(
    hosts: dict[str, HostInfo],
    *,
    timeout: int = 10,
    workers: int = 10,
    follow_redirects: bool = False,
    schemes: Iterable[str] = ("https", "http"),
) -> None:
    scheme_list = list(schemes)
    tasks = [
        (name, scheme)
        for name, info in hosts.items()
        if info.ips
        for scheme in scheme_list
    ]

    def run(task: tuple[str, str]) -> CheckResult:
        sub, scheme = task
        try:
            return _probe_one(sub, scheme, timeout=timeout, follow_redirects=follow_redirects)
        except Exception as exc:
            return CheckResult(scheme=scheme, subdomain=sub, error=type(exc).__name__)

    if not tasks:
        return
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for check in pool.map(run, tasks):
            hosts[check.subdomain].checks.append(check)