from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import Optional

import requests

from .utils import request_with_retry


class SourceError(Exception):
    pass


class BaseSource(ABC):
    name = "base"
    description = ""
    enabled = True
    requires_api_key = False
    required_keys: tuple[str, ...] = ()
    default_timeout = 30
    url = ""

    def __init__(
        self,
        session: requests.Session,
        timeout: Optional[int] = None,
        verbose: bool = False,
        keys: Optional[dict] = None,
    ):
        self.session = session
        self.timeout = timeout or self.default_timeout
        self.verbose = verbose
        self.keys = keys or {}

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"[v] {self.name}: {message}", file=sys.stderr)

    def _missing_keys(self) -> list[str]:
        return [k for k in self.required_keys if not self.keys.get(k)]

    def _ensure_keys(self) -> None:
        missing = self._missing_keys()
        if missing:
            raise SourceError(
                f"missing API key(s): {', '.join(missing)} (add to api_keys.json)"
            )

    def get(self, url: str, *, attempts: int = 3, **kwargs) -> requests.Response:
        resp = request_with_retry(
            self.session, "GET", url, attempts=attempts, timeout=self.timeout, **kwargs
        )
        if resp.status_code in (401, 403):
            raise SourceError(
                f"{self.name}: authentication failed - check your API key(s) in api_keys.json"
            )
        return resp

    @abstractmethod
    def fetch(self, domain: str) -> set[str]:
        pass
