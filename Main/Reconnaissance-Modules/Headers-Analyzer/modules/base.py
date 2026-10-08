from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.intercept_reader import HTTPResponse
    from core.engine import ModuleResult


class BaseHeaderModule(ABC):
    name: str = "Base Module"
    description: str = ""

    def applies_to(self, response: "HTTPResponse") -> bool:
        return True

    @abstractmethod
    def run(self, response: "HTTPResponse") -> "ModuleResult":
        pass

    def _get_header(self, headers: Dict[str, str], name: str) -> Optional[str]:
        return headers.get(name.lower())

    def _header_exists(self, headers: Dict[str, str], name: str) -> bool:
        return name.lower() in headers

    def _parse_directives(self, header_value: str) -> Dict[str, Optional[str]]:
        directives = {}
        for part in header_value.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                key, _, val = part.partition("=")
                directives[key.strip().lower()] = val.strip().strip('"')
            else:
                directives[part.lower()] = None
        return directives
