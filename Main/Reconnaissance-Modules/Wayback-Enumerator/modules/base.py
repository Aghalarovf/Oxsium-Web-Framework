import argparse
from abc import ABC, abstractmethod
from typing import Any

from core.requester import Requester
from core.logger import Logger


class BaseArchiveModule(ABC):

    def __init__(
        self,
        domain: str,
        requester: Requester,
        logger: Logger,
        args: argparse.Namespace,
        prior_results: dict[str, Any] | None = None,
    ):
        self.domain = domain
        self.requester = requester
        self.logger = logger
        self.args = args
        self.prior_results: dict[str, Any] = prior_results or {}

        self.verbose: bool = getattr(args, "verbose", False)
        self.timeout: int = getattr(args, "timeout", 15)
        self.concurrency: int = getattr(args, "concurrency", 10)

    @abstractmethod
    async def run(self) -> dict[str, Any]:
        """Abstract method for running module execution."""

    @staticmethod
    def normalize_url(url: str) -> str:
        url = url.strip()
        if "web.archive.org/web/" in url:
            parts = url.split("/web/", 1)
            if len(parts) == 2:
                after = parts[1]
                slash = after.find("/")
                if slash != -1:
                    url = "https://" + after[slash + 1:]
        return url

    @staticmethod
    def safe_domain(domain: str) -> str:
        return (
            domain.strip()
            .lower()
            .removeprefix("https://")
            .removeprefix("http://")
            .rstrip("/")
        )

    @staticmethod
    def deduplicate(lst: list) -> list:
        return list(dict.fromkeys(lst))

    @staticmethod
    def deduplicate_dicts(lst: list[dict], key: str) -> list[dict]:
        seen: set = set()
        result: list[dict] = []
        for item in lst:
            val = item.get(key)
            if val not in seen:
                seen.add(val)
                result.append(item)
        return result

    def log_found(self, label: str, count: int):
        if count > 0:
            self.logger.success(f"{label}: {count} found")
        else:
            self.logger.warning(f"{label}: nothing found")

    def log_debug(self, msg: str):
        self.logger.debug(f"[{self.__class__.__name__}] {msg}")

    def get_prior_urls(self) -> list[str]:
        sources = self.prior_results.get("sources", {})
        if isinstance(sources, dict):
            return sources.get("urls", [])
        if isinstance(sources, list):
            return sources
        return []