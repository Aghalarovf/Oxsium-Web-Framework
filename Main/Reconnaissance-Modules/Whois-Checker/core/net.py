from __future__ import annotations

import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


class Net:
    def __init__(
        self,
        proxy: Optional[str],
        timeout: int,
        ua: str,
        verbose: bool,
    ) -> None:
        self.proxy = proxy
        self.timeout = timeout
        self.ua = ua
        self.verbose = verbose
        self.socks = None

        if proxy:
            u = urllib.parse.urlparse(proxy)
            if u.scheme.startswith("socks"):
                try:
                    import socks  # type: ignore
                    self.socks = socks
                except ImportError:
                    raise SystemExit("[-] SOCKS proxy requires PySocks: pip install PySocks")

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[debug] {msg}", file=sys.stderr)

    def _is_socks(self) -> bool:
        return bool(
            self.socks
            and self.proxy
            and urllib.parse.urlparse(self.proxy).scheme.startswith("socks")
        )

    def _build_opener(self, ctx: Optional[ssl.SSLContext] = None) -> urllib.request.OpenerDirector:
        handlers: List[Any] = []
        if ctx:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        if self.proxy and not self._is_socks():
            handlers.append(
                urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy})
            )
        elif not self.proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        return urllib.request.build_opener(*handlers)

    def http_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Any]:
        hdrs = {"User-Agent": self.ua, "Accept": "application/json, application/rdap+json, */*"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, headers=hdrs)
        opener = self._build_opener()
        try:
            self.log(f"HTTP GET {url}")
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception as exc:
            self.log(f"HTTP error {url}: {exc}")
            return None

    def _fetch(
        self,
        url: str,
        method: str,
        ctx: ssl.SSLContext,
    ) -> Tuple[int, Dict[str, str], str]:
        hdrs = {"User-Agent": self.ua, "Accept": "*/*"}
        opener = self._build_opener(ctx)
        req = urllib.request.Request(url, headers=hdrs, method=method)
        with opener.open(req, timeout=self.timeout) as resp:
            return (
                resp.getcode() or 0,
                {k.lower(): v for k, v in resp.headers.items()},
                str(resp.geturl()),
            )

    def http_headers(
        self,
        url: str,
        insecure: bool = False,
    ) -> Tuple[int, Dict[str, str], str]:
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        for method in ("HEAD", "GET"):
            try:
                return self._fetch(url, method, ctx)
            except urllib.error.HTTPError as exc:
                if exc.code == 405 and method == "HEAD":
                    continue
                return (
                    exc.code,
                    {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])},
                    str(exc.url) if exc.url else url,
                )
            except Exception as exc:
                if not insecure:
                    self.log(f"Retrying {url} with insecure SSL after: {exc}")
                    return self.http_headers(url, insecure=True)
                self.log(f"HTTP headers failed {url}: {exc}")
                return 0, {}, url
        return 0, {}, url

    def tcp_whois(self, server: str, query: str, port: int = 43) -> str:
        payload = (query + "\r\n").encode("utf-8", errors="replace")
        sock: Optional[socket.socket] = None
        try:
            if self._is_socks() and self.proxy:
                u = urllib.parse.urlparse(self.proxy)
                stype = (
                    self.socks.SOCKS5
                    if "5" in (u.scheme or "")
                    else self.socks.SOCKS4
                )
                sock = self.socks.socksocket()
                sock.set_proxy(
                    stype, u.hostname, u.port or 1080,
                    username=u.username, password=u.password,
                )
                sock.settimeout(self.timeout)
                sock.connect((server, port))
            else:
                sock = socket.create_connection((server, port), timeout=self.timeout)
                sock.settimeout(self.timeout)

            sock.sendall(payload)
            chunks: List[bytes] = []
            while True:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as exc:
            self.log(f"WHOIS {server}: {exc}")
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass