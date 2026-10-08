import re
import json
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from core.logger import Logger
from core.requester import Requester


@dataclass
class DorkTemplate:
    template: str
    description: str
    category: str
    severity: str = "info"
    tags: list[str] = field(default_factory=list)

    def render(self, target: str) -> str:
        return self.template.replace("{target}", target)


@dataclass
class DorkResult:
    dork: str
    description: str
    category: str
    severity: str
    url: Optional[str] = None
    raw_hits: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    module: str = ""

    def to_dict(self) -> dict:
        return {
            "module":      self.module,
            "category":    self.category,
            "description": self.description,
            "dork":        self.dork,
            "url":         self.url or "",
            "severity":    self.severity,
            "tags":        self.tags,
            "hits":        self.raw_hits,
        }


class BaseModule(ABC):
    name: str = "base"
    description: str = ""

    SEVERITY_ORDER = {
        "critical": 4,
        "high":     3,
        "medium":   2,
        "low":      1,
        "info":     0,
    }

    GOOGLE_RESULT_PATTERNS = [
        re.compile(
            r'<a[^>]+href="(https?://(?!(?:www\.)?google\.)[^"]{10,})"[^>]*\s+(?:data-ved|jsname|ping)=',
            re.IGNORECASE,
        ),
        re.compile(
            r'/url\?q=(https?://(?!(?:www\.)?google\.)[^&"]{10,})',
            re.IGNORECASE,
        ),
        re.compile(
            r'<a[^>]+href="(https?://(?!(?:www\.)?google\.)[^"]{10,})"[^>]*>',
            re.IGNORECASE,
        ),
    ]

    GOOGLE_CAPTCHA_INDICATORS = [
        "Our systems have detected unusual traffic",
        "detected unusual traffic from your computer",
        "Please show you're not a robot",
        "recaptcha",
        "g-recaptcha",
    ]

    def __init__(
        self,
        target: str,
        requester: Requester,
        logger: Logger,
        dry_run: bool = False,
    ):
        self.target = target
        self.requester = requester
        self.logger = logger
        self.dry_run = dry_run
        self._results: list[DorkResult] = []

    @abstractmethod
    def dorks(self) -> list[DorkTemplate]:
        ...

    def run(self) -> list[dict]:
        templates = self.dorks()
        self.logger.debug(f"{self.name}: {len(templates)} dork(s) queued.")

        for tmpl in templates:
            rendered = tmpl.render(self.target)
            self.logger.dork(rendered, tmpl.description)

            if self.dry_run:
                result = DorkResult(
                    dork=rendered,
                    description=tmpl.description,
                    category=tmpl.category,
                    severity=tmpl.severity,
                    tags=tmpl.tags,
                    module=self.name,
                )
                self._results.append(result)
                continue

            try:
                response = self.requester.search(rendered)
                if response is None:
                    self.logger.warning(f"No response for: {rendered}")
                    continue

                if response.startswith("\x00SERPAPI\x00"):
                    hits = json.loads(response[len("\x00SERPAPI\x00"):])
                else:
                    if self._is_captcha(response):
                        self.logger.error(
                            "CAPTCHA detected. Increase --delay or use --proxy. "
                            "Halting module."
                        )
                        break
                    hits = self._extract_urls(response)
                dork_url = self.requester.build_dork_url(rendered)

                if hits:
                    for hit in hits:
                        self.logger.result(hit, rendered)

                result = DorkResult(
                    dork=rendered,
                    description=tmpl.description,
                    category=tmpl.category,
                    severity=tmpl.severity,
                    url=dork_url,
                    raw_hits=hits,
                    tags=tmpl.tags,
                    module=self.name,
                )
                self._results.append(result)

            except RuntimeError as exc:
                self.logger.error(str(exc))
                break
            except Exception as exc:
                self.logger.error(f"Unexpected error on dork '{rendered}': {exc}")
                continue

        return [r.to_dict() for r in self._results]

    def _is_captcha(self, html: str) -> bool:
        lower = html.lower()
        return any(indicator.lower() in lower for indicator in self.GOOGLE_CAPTCHA_INDICATORS)

    def _extract_urls(self, html: str) -> list[str]:
        seen = set()
        urls = []
        for pattern in self.GOOGLE_RESULT_PATTERNS:
            for u in pattern.findall(html):
                u = urllib.parse.unquote(u.split("&")[0])
                if u not in seen and "google." not in u and len(u) > 10:
                    seen.add(u)
                    urls.append(u)
            if urls:
                break
        return urls

    def _make_dork(
        self,
        template: str,
        description: str,
        category: str,
        severity: str = "info",
        tags: Optional[list[str]] = None,
    ) -> DorkTemplate:
        return DorkTemplate(
            template=template,
            description=description,
            category=category,
            severity=severity,
            tags=tags or [],
        )