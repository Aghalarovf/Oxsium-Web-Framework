import abc
from typing import Any

from core.cli import ScanConfig
from core.logger import Logger
from core.traffic import TrafficStore, clean_host


class BaseModule(abc.ABC):
    NAME: str = "base"
    DESCRIPTION: str = ""

    def __init__(
        self,
        target: str,
        traffic: TrafficStore,
        logger: Logger,
        config: ScanConfig,
    ):
        self.target = target.rstrip("/")
        self.traffic = traffic
        self.logger = logger
        self.config = config
        self._findings: list[dict[str, Any]] = []

    @abc.abstractmethod
    async def run(self) -> Any:
        ...

    def _add_finding(self, **kwargs: Any):
        entry = {k: v for k, v in kwargs.items() if v not in (None, "", [], {})}
        if entry:
            self._findings.append(entry)

    def _log_finding(self, key: str, value: str):
        self.logger.finding(key, value)

    @property
    def domain(self) -> str:
        return clean_host(self.target)
