from __future__ import annotations

from typing import Optional

from core import BaseSource

from .anubis import Anubis
from .censys import Censys
from .certspotter import CertSpotter
from .chaos import Chaos
from .circl import CirclPDNS
from .commoncrawl import CommonCrawl
from .crtname import CrtName
from .crtsh import CrtSh
from .dnsdumpster import DNSDumpster
from .facebookct import FacebookCT
from .googlect import GoogleCT
from .hackertarget import HackerTarget
from .otx import AlienVaultOTX
from .rapiddns import RapidDNS
from .securitytrails import SecurityTrails
from .shodan import Shodan
from .urlscan import UrlScan
from .virustotal import VirusTotal
from .wayback import WaybackMachine
from .otx_urls import AlienVaultOTXUrls
from .urlscan_urls import UrlScanUrls
from .wayback_urls import WaybackUrls
from .commoncrawl_urls import CommonCrawlUrls

ALL_SOURCES: list[type[BaseSource]] = [
    CrtSh,
    CertSpotter,
    Censys,
    Chaos,
    CrtName,
    HackerTarget,
    RapidDNS,
    Anubis,
    CirclPDNS,
    WaybackMachine,
    CommonCrawl,
    AlienVaultOTX,
    VirusTotal,
    SecurityTrails,
    UrlScan,
    Shodan,
    GoogleCT,
    FacebookCT,
    DNSDumpster,
    AlienVaultOTXUrls,
    UrlScanUrls,
    WaybackUrls,
    CommonCrawlUrls,
]

REGISTRY: dict[str, type[BaseSource]] = {cls.name: cls for cls in ALL_SOURCES}


def resolve_sources(
    names: Optional[list[str]],
) -> tuple[list[type[BaseSource]], list[str]]:
    if not names:
        return [cls for cls in ALL_SOURCES if cls.enabled], []

    resolved: list[type[BaseSource]] = []
    skipped: list[str] = []
    for name in names:
        cls = REGISTRY.get(name.strip().lower())
        if cls is None:
            skipped.append(f"unknown source: {name}")
        elif not cls.enabled:
            skipped.append(f"disabled source: {name}")
        else:
            resolved.append(cls)
    return resolved, skipped