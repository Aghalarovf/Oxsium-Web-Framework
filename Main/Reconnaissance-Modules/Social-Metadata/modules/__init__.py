import importlib
from typing import Any, Optional

from core.cli import ScanConfig
from core.logger import Logger
from core.traffic import TrafficStore

_MODULE_REGISTRY: dict[str, str] = {
    "social": "modules.social",
    "emails": "modules.emails",
    "html_meta": "modules.html_meta",
    "docs_osint": "modules.docs_osint",
}

_MODULE_CLASS: dict[str, str] = {
    "social": "SocialModule",
    "emails": "EmailsModule",
    "html_meta": "HtmlMetaModule",
    "docs_osint": "DocsOsintModule",
}


def load_module(
    name: str,
    target: str,
    traffic: TrafficStore,
    logger: Logger,
    config: ScanConfig,
) -> Optional[Any]:
    if name not in _MODULE_REGISTRY:
        raise ImportError(f"Unknown module: '{name}'. Available: {list(_MODULE_REGISTRY)}")
    module = importlib.import_module(_MODULE_REGISTRY[name])
    cls = getattr(module, _MODULE_CLASS[name])
    return cls(target=target, traffic=traffic, logger=logger, config=config)


__all__ = ["load_module"]
