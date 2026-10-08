from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    module:     str
    severity:   str
    type:       str
    value:      str
    context:    str = ""
    line:       int = 0
    confidence: str = "medium"
    meta:       dict[str, Any] = field(default_factory=dict)


class BaseJSModule(ABC):

    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH     = "high"
    SEVERITY_MEDIUM   = "medium"
    SEVERITY_LOW      = "low"
    SEVERITY_INFO     = "info"

    CONFIDENCE_HIGH   = "high"
    CONFIDENCE_MEDIUM = "medium"
    CONFIDENCE_LOW    = "low"

    def __init__(self, logger: Any | None = None) -> None:
        self.logger   = logger
        self.findings: list[Finding] = []

    @abstractmethod
    def analyze(self, content: str, filename: str = "") -> list[Finding]:
        ...

    def _finding(
        self,
        type:       str,
        value:      str,
        severity:   str,
        context:    str = "",
        line:       int = 0,
        confidence: str = "medium",
        meta:       dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            module     = self.__class__.__name__,
            severity   = severity,
            type       = type,
            value      = value,
            context    = context,
            line       = line,
            confidence = confidence,
            meta       = meta or {},
        )

    def _get_line_number(self, content: str, position: int) -> int:
        return content[:position].count("\n") + 1

    def _get_context(self, content: str, position: int, window: int = 80) -> str:
        start = max(0, position - window)
        end   = min(len(content), position + window)
        return content[start:end].strip()

    def log_debug(self, msg: str) -> None:
        if self.logger:
            self.logger.debug(f"[{self.__class__.__name__}] {msg}")