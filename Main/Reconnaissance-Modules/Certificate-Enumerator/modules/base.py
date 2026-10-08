import abc
from typing import Dict, Any
from core.network import TLSConnection
from core.logger import ScanLogger


class BaseModule(abc.ABC):
    name: str = "base"
    description: str = ""

    def __init__(self, connection: TLSConnection, logger: ScanLogger):
        self.connection = connection
        self.logger = logger

    @abc.abstractmethod
    def run(self) -> Dict[str, Any]:
        raise NotImplementedError

    def _pass(self, label: str, value: str = "") -> None:
        self.logger.result("PASS", label, value)

    def _fail(self, label: str, value: str = "") -> None:
        self.logger.result("FAIL", label, value)

    def _warn(self, label: str, value: str = "") -> None:
        self.logger.result("WARN", label, value)

    def _info(self, label: str, value: str = "") -> None:
        self.logger.result("INFO", label, value)

    def _skip(self, label: str, value: str = "") -> None:
        self.logger.result("SKIP", label, value)