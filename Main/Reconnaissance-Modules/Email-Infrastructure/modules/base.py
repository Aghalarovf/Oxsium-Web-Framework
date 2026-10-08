from abc import ABC, abstractmethod
from typing import Optional

from core.dns_resolver import DnsResolver
from core.logger import Logger
from core.requester import Requester


class BaseEmailModule(ABC):

    def __init__(
        self,
        resolver: DnsResolver,
        logger: Logger,
        requester: Optional[Requester] = None,
    ) -> None:
        self._resolver = resolver
        self._logger = logger
        self._requester = requester

    @abstractmethod
    async def run(self, domain: str) -> dict:
        raise NotImplementedError