from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import jsbeautifier
from bs4 import BeautifulSoup

from core.fetcher import JSFetcher, FetchResult
from core.ast_parser import ASTParser
from core.reporter import Reporter
from modules.base import BaseJSModule, Finding
from modules.secrets    import SecretsModule
from modules.endpoints  import EndpointsModule
from modules.sourcemaps import SourceMapsModule


ALL_MODULES: list[type[BaseJSModule]] = [
    SecretsModule,
    EndpointsModule,
    SourceMapsModule,
]

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
BEAUTIFY_OPTS  = jsbeautifier.default_options()
BEAUTIFY_OPTS.indent_size = 2

# Matches absolute (http/https/protocol-relative) AND relative JS paths.
JS_URL_PATTERN = re.compile(
    r"""src\s*=\s*["']([^"']+\.(?:js|mjs|cjs)(?:\?[^"']*)?)["\']""",
    re.IGNORECASE,
)

# Fallback: any quoted string that looks like a JS URL
JS_URL_FALLBACK = re.compile(
    r"""["'`]((?:https?:)?//[^"'`\s<>]+\.(?:js|mjs|cjs)(?:\?[^"'`\s<>]*)?)["'`]""",
    re.IGNORECASE,
)


@dataclass
class ScanTarget:
    type:     str
    value:    str
    filename: str = ""


@dataclass
class ScanResult:
    target:   ScanTarget
    findings: list[Finding] = field(default_factory=list)
    error:    str | None    = None
    fetch:    FetchResult | None = None


class Engine:

    def __init__(
        self,
        modules:  list[type[BaseJSModule]] | None = None,
        logger:   Any | None = None,
        workers:  int = 10,
        beautify: bool = True,
        timeout:  int = 20,
    ) -> None:
        self.module_classes = modules if modules is not None else ALL_MODULES
        self.logger         = logger
        self.workers        = workers
        self.beautify       = beautify
        self.timeout        = timeout
        self.parser         = ASTParser(logger=logger)
        self.reporter       = Reporter()

    async def scan_urls(self, urls: list[str]) -> list[ScanResult]:
        targets = [ScanTarget(type="url", value=u, filename=u.split("/")[-1].split("?")[0]) for u in urls]
        return await self._run(targets)

    async def scan_url(self, url: str) -> ScanResult:
        results = await self.scan_urls([url])
        return results[0] if results else ScanResult(target=ScanTarget("url", url), error="No result")

    async def scan_html(self, url: str) -> list[ScanResult]:
        async with JSFetcher(timeout=self.timeout, logger=self.logger) as fetcher:
            page = await fetcher.fetch(url)

        if page.error:
            return [ScanResult(target=ScanTarget("html", url), error=page.error)]

        final_url = page.final_url or url
        self._log(f"Fetched {final_url} ({len(page.content)} bytes)")

        js_urls = self._extract_js_from_html(page.content, final_url)
        self._log(f"Found {len(js_urls)} JS file(s) in {final_url}")

        if js_urls:
            results = await self.scan_urls(js_urls)
            # also scan inline scripts alongside external ones
            inline  = self._analyze_inline_scripts(page.content, final_url)
            return results + [r for r in inline if r.findings]

        self._log("No external JS found – falling back to inline script analysis")
        return self._analyze_inline_scripts(page.content, final_url)

    async def scan_file(self, path: str) -> ScanResult:
        target = ScanTarget(type="file", value=path, filename=os.path.basename(path))
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return ScanResult(target=target, error=str(exc))
        findings = self._analyze_content(content, target.filename)
        return ScanResult(target=target, findings=findings)

    async def scan_directory(self, directory: str) -> list[ScanResult]:
        js_files = [
            str(p) for p in Path(directory).rglob("*")
            if p.suffix.lower() in JS_EXTENSIONS
        ]
        self._log(f"Found {len(js_files)} JS files in {directory}")
        tasks = [self.scan_file(f) for f in js_files]
        return list(await asyncio.gather(*tasks))

    async def _run(self, targets: list[ScanTarget]) -> list[ScanResult]:
        semaphore = asyncio.Semaphore(self.workers)
        async with JSFetcher(timeout=self.timeout, logger=self.logger) as fetcher:
            tasks = [self._process(t, fetcher, semaphore) for t in targets]
            return list(await asyncio.gather(*tasks))

    async def _process(
        self,
        target:    ScanTarget,
        fetcher:   JSFetcher,
        semaphore: asyncio.Semaphore,
    ) -> ScanResult:
        async with semaphore:
            if target.type != "url":
                return ScanResult(target=target, error="Unsupported target type in _process")

            fetch = await fetcher.fetch(target.value)

            if fetch.error:
                self._log(f"Fetch error [{target.value}]: {fetch.error}")
                return ScanResult(target=target, fetch=fetch, error=fetch.error)

            if fetch.status not in range(200, 300):
                self._log(f"HTTP {fetch.status} for {target.value} – skipping")
                return ScanResult(
                    target=target, fetch=fetch,
                    error=f"HTTP {fetch.status}",
                )

            content  = self._prepare_content(fetch.content)
            findings = self._analyze_content(content, target.filename)

            if fetch.sourcemap:
                for src_path, src_content in self._iter_sourcemap_sources(fetch.sourcemap):
                    findings.extend(self._analyze_content(src_content, src_path))

            self._log(f"Scanned {target.value} → {len(findings)} finding(s)")
            return ScanResult(target=target, findings=findings, fetch=fetch)

    def _analyze_inline_scripts(self, html: str, base_url: str) -> list[ScanResult]:
        soup    = BeautifulSoup(html, "html.parser")
        results: list[ScanResult] = []

        for i, tag in enumerate(soup.find_all("script")):
            if tag.get("src"):
                continue
            code = tag.string or tag.get_text()
            if not code or len(code.strip()) < 10:
                continue
            label    = f"{base_url}#inline-{i}"
            target   = ScanTarget(type="inline", value=label, filename=label)
            content  = self._prepare_content(code)
            findings = self._analyze_content(content, label)
            results.append(ScanResult(target=target, findings=findings))

        if not results:
            target   = ScanTarget(type="html", value=base_url, filename=base_url)
            findings = self._analyze_content(html, base_url)
            results.append(ScanResult(target=target, findings=findings))

        return results

    def _analyze_content(self, content: str, filename: str) -> list[Finding]:
        findings: list[Finding] = []
        for ModuleClass in self.module_classes:
            try:
                module = ModuleClass(logger=self.logger)
                findings.extend(module.analyze(content, filename))
            except Exception as exc:
                self._log(f"Module {ModuleClass.__name__} error on {filename}: {exc}")
        return findings

    def _prepare_content(self, content: str) -> str:
        if not self.beautify:
            return content
        try:
            return jsbeautifier.beautify(content, BEAUTIFY_OPTS)
        except Exception:
            return content

    @classmethod
    def _extract_js_from_html(cls, html: str, base_url: str) -> list[str]:
        soup  = BeautifulSoup(html, "html.parser")
        urls: list[str] = []
        seen: set[str]  = set()

        def add(raw: str) -> None:
            if not raw or raw.startswith("data:"):
                return
            full = urljoin(base_url, raw)
            if full not in seen:
                seen.add(full)
                urls.append(full)

        # 1. <script src="...">
        for tag in soup.find_all("script", src=True):
            add(tag["src"].strip())

        # 2. <link rel="modulepreload" href="...">
        for tag in soup.find_all("link", rel=True):
            rel = tag.get("rel", [])
            if isinstance(rel, list):
                rel = " ".join(rel)
            if "modulepreload" in rel.lower() or "preload" in rel.lower():
                href = tag.get("href", "")
                if href.endswith((".js", ".mjs", ".cjs")):
                    add(href.strip())

        # 3. Regex over raw HTML — catches src= inside JS-generated markup
        #    and any remaining relative or absolute .js references
        if not urls:
            for m in JS_URL_PATTERN.finditer(html):
                add(m.group(1))

        # 4. Last resort: quoted absolute JS URLs anywhere in the HTML
        if not urls:
            for m in JS_URL_FALLBACK.finditer(html):
                add(m.group(1))

        return urls

    @staticmethod
    def _iter_sourcemap_sources(sourcemap: dict[str, Any]):
        sources  = sourcemap.get("sources", [])
        contents = sourcemap.get("sourcesContent", [])
        for i, src_path in enumerate(sources):
            if i < len(contents) and contents[i]:
                yield src_path, contents[i]

    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger.info(msg)