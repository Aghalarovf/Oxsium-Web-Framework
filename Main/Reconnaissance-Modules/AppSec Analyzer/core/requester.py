"""
core/requester.py - HTTP request layer.

Wraps the 'requests' library so that every module works through a single
session object.  This means:
  - Connection pooling is shared across modules (fewer TCP handshakes).
  - Retry logic, headers, and timeout live in one place.
  - Modules never import 'requests' directly, making it easy to swap the
    underlying library in the future.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.logger import get_logger

log = get_logger("requester")


# ── Default headers sent with every request ───────────────────────────────────
_DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
        "Gecko/20100101 Firefox/124.0"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


@dataclass
class Response:
    """
    Lightweight wrapper around a raw requests.Response object.

    Modules work with this dataclass rather than the raw response so that
    the rest of the codebase does not depend on requests internals.
    """

    url:          str
    status_code:  int
    headers:      Dict[str, str]
    body:         str
    elapsed_ms:   float                          # Round-trip time in milliseconds
    raw:          requests.Response = field(repr=False)  # Kept for edge cases

    # ── Convenience helpers ───────────────────────────────────────────────────

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), default)

    def contains(self, text: str) -> bool:
        """Return True if *text* appears anywhere in the response body."""
        return text.lower() in self.body.lower()


class Requester:
    """
    Stateful HTTP client used by all analysis modules.

    Parameters
    ----------
    timeout : Per-request timeout in seconds.
    retries : Number of automatic retries on connection errors (not HTTP errors).
    verify  : Validate TLS certificates.  Set False for self-signed certs.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        retries: int = 2,
        verify: bool = False,          # Pentesting often targets self-signed certs
    ) -> None:
        self.timeout = timeout
        self.verify  = verify

        self._session = self._build_session(retries)

    # ── Session construction ──────────────────────────────────────────────────

    @staticmethod
    def _build_session(retries: int) -> requests.Session:
        """
        Create a requests.Session with connection pooling and retry logic.

        The retry object only retries on connection-level errors (e.g.
        ECONNREFUSED, DNS failure) — intentional HTTP error codes such as
        429 or 403 are not retried automatically so modules can inspect them.
        """
        session = requests.Session()
        session.headers.update(_DEFAULT_HEADERS)
        session.verify = False          # Updated per-request via param

        retry_policy = Retry(
            total=retries,
            backoff_factor=0.5,         # 0.5s, 1s, 2s … between retries
            status_forcelist=[],        # Do NOT auto-retry HTTP errors
            allowed_methods=["GET", "HEAD", "POST"],
        )
        adapter = HTTPAdapter(
            max_retries=retry_policy,
            pool_connections=10,
            pool_maxsize=20,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    # ── Public request methods ────────────────────────────────────────────────

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        """
        Perform a GET request and return a Response dataclass.

        Returns None on network errors so callers can continue gracefully.
        """
        return self._send("GET", url, headers=headers,
                          allow_redirects=allow_redirects)

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        """
        Perform a POST request and return a Response dataclass.

        Returns None on network errors.
        """
        return self._send("POST", url, data=data, headers=headers)

    def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        """
        Perform a HEAD request (headers only, no body download).

        Useful for quickly reading response headers without the overhead of
        transferring the full response body.
        """
        return self._send("HEAD", url, headers=headers, allow_redirects=True)

    # ── Internal dispatcher ───────────────────────────────────────────────────

    def _send(
        self,
        method: str,
        url: str,
        data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        """
        Dispatch an HTTP request, measure elapsed time, and wrap the result.

        All exceptions are caught and logged here so that calling modules
        never crash on a single bad request.
        """
        merged_headers = dict(self._session.headers)
        if headers:
            merged_headers.update(headers)

        try:
            t0  = time.perf_counter()
            raw = self._session.request(
                method=method,
                url=url,
                data=data,
                headers=merged_headers,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=allow_redirects,
            )
            elapsed = (time.perf_counter() - t0) * 1000   # → ms

            log.debug(
                f"{method} {url}  →  {raw.status_code}  "
                f"({elapsed:.0f} ms,  {len(raw.content)} B)"
            )

            return Response(
                url=raw.url,
                status_code=raw.status_code,
                headers={k.lower(): v for k, v in raw.headers.items()},
                body=raw.text,
                elapsed_ms=elapsed,
                raw=raw,
            )

        except requests.exceptions.Timeout:
            log.warning(f"Timeout reaching {url} (>{self.timeout}s)")
        except requests.exceptions.SSLError as exc:
            log.warning(f"SSL error for {url}: {exc}")
        except requests.exceptions.ConnectionError as exc:
            log.warning(f"Connection error for {url}: {exc}")
        except requests.exceptions.RequestException as exc:
            log.error(f"Unexpected request error for {url}: {exc}")

        return None

    # ── URL helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def normalise_url(raw: str) -> str:
        """
        Ensure *raw* has an HTTPS scheme so it can be passed to requests.

        Examples
        --------
        >>> Requester.normalise_url("example.com")
        'https://example.com'
        >>> Requester.normalise_url("http://example.com")
        'http://example.com'
        """
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        parsed = urlparse(raw)
        # Rebuild without any stray trailing slashes in the path
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._session.close()