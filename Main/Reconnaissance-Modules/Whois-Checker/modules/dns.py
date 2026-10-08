from __future__ import annotations

import re
import socket
from typing import Any, Dict, List

from core.models import DnsResult


def lookup(domain: str, timeout: int) -> DnsResult:
    result = DnsResult()

    # Try dnspython first (best results)
    try:
        import dns.resolver  # type: ignore

        res = dns.resolver.Resolver()
        res.lifetime = timeout
        result.resolver = "dnspython"

        for rtype, key in (
            ("A", "a"),
            ("AAAA", "aaaa"),
            ("NS", "ns"),
            ("MX", "mx"),
            ("CNAME", "cname"),
            ("TXT", "txt"),
        ):
            try:
                ans = res.resolve(domain, rtype)
                vals = [str(rr).rstrip(".").strip('"') for rr in ans]
                setattr(result, key, vals)
            except Exception:
                pass
        return result
    except ImportError:
        pass

    # Fallback: socket for A/AAAA
    socket.setdefaulttimeout(timeout)
    for fam, key in ((socket.AF_INET, "a"), (socket.AF_INET6, "aaaa")):
        try:
            infos = socket.getaddrinfo(domain, None, fam, socket.SOCK_STREAM)
            ips: List[str] = []
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            setattr(result, key, ips)
        except Exception:
            pass

    # Fallback: dig / nslookup for NS, MX, CNAME, TXT
    import subprocess

    for cmd, rtype, key in (
        (["dig", "+short", "NS", domain], "NS", "ns"),
        (["dig", "+short", "MX", domain], "MX", "mx"),
        (["dig", "+short", "CNAME", domain], "CNAME", "cname"),
        (["dig", "+short", "TXT", domain], "TXT", "txt"),
        (["nslookup", "-type=NS", domain], "NS", "ns"),
    ):
        if getattr(result, key):
            continue
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            lines = [
                ln.strip().rstrip(".")
                for ln in proc.stdout.splitlines()
                if ln.strip() and not ln.lower().startswith("server")
            ]
            if cmd[0] == "nslookup":
                parsed: List[str] = []
                for ln in lines:
                    m = re.search(r"nameserver\s*=\s*(\S+)", ln, re.I)
                    if m:
                        parsed.append(m.group(1).rstrip("."))
                lines = parsed
            if lines:
                setattr(result, key, lines)
                result.resolver = cmd[0]
        except Exception:
            pass

    return result