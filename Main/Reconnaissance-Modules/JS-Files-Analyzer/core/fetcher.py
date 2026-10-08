from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

SOURCEMAP_COMMENT   = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)", re.MULTILINE)
SOURCEMAP_HEADER    = "SourceMap"
X_SOURCEMAP_HEADER  = "X-SourceMap"

DEFAULT_TIMEOUT    = 20
DEFAULT_CHUNK_SIZE = 1024 * 512
MAX_JS_SIZE        = 1024 * 1024 * 50
MAX_RETRIES        = 3

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (compatible; JSAnalyzer/1.0)",
    "Accept":          "*/*",
    "Accept-Encoding": "gzip, deflate, br",
}


@dataclass
class FetchResult:
    url:          str
    content:      str
    status:       int
    content_type: str
    sourcemap_url: str | None = None
    sourcemap:    dict[str, Any] | None = None
    error:        str | None = None
    size:         int = 0
    headers:      dict[str, str] = field(default_factory=dict)
    final_url:    str | None = None


class JSFetcher:

    def __init__(
        self,
        session:    aiohttp.ClientSession | None = None,
        timeout:    int = DEFAULT_TIMEOUT,
        max_size:   int = MAX_JS_SIZE,
        logger:     Any | None = None,
    ) -> None:
        self._session      = session
        self._owned        = session is None
        self.timeout       = timeout
        self.max_size      = max_size
        self.logger        = logger

    async def __aenter__(self) -> "JSFetcher":
        if self._owned:
            self._session = aiohttp.ClientSession(
                headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False),
            )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._owned and self._session:
            await self._session.close()

    async def fetch(self, url: str) -> FetchResult:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                return await self._fetch_once(url)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt == MAX_RETRIES:
                    return FetchResult(url=url, content="", status=0,
                                       content_type="", error=str(exc))
                await asyncio.sleep(attempt * 1.5)

    async def fetch_many(self, urls: list[str]) -> list[FetchResult]:
        tasks = [self.fetch(url) for url in urls]
        return await asyncio.gather(*tasks)

    async def _fetch_once(self, url: str) -> FetchResult:
        async with self._session.get(url) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw_headers  = dict(resp.headers)

            sourcemap_url = (
                resp.headers.get(SOURCEMAP_HEADER)
                or resp.headers.get(X_SOURCEMAP_HEADER)
            )

            body = b""
            async for chunk in resp.content.iter_chunked(DEFAULT_CHUNK_SIZE):
                body += chunk
                if len(body) > self.max_size:
                    break

            text = body.decode("utf-8", errors="replace")

            if sourcemap_url is None:
                sourcemap_url = self._detect_sourcemap_comment(text)

            sourcemap_url = self._resolve_sourcemap_url(url, sourcemap_url)

            result = FetchResult(
                url          = url,
                content      = text,
                status       = resp.status,
                content_type = content_type,
                sourcemap_url= sourcemap_url,
                size         = len(body),
                headers      = raw_headers,
                final_url    = str(resp.url),
            )

            if sourcemap_url:
                result.sourcemap = await self._fetch_sourcemap(sourcemap_url)

            return result

    async def _fetch_sourcemap(self, url: str) -> dict[str, Any] | None:
        try:
            async with self._session.get(url) as resp:
                if resp.status == 200:
                    import json
                    text = await resp.text(encoding="utf-8", errors="replace")
                    return json.loads(text)
        except Exception:
            pass
        return None

    @staticmethod
    def _detect_sourcemap_comment(content: str) -> str | None:
        match = SOURCEMAP_COMMENT.search(content[-4096:])
        return match.group(1) if match else None

    @staticmethod
    def _resolve_sourcemap_url(base_url: str, sourcemap_url: str | None) -> str | None:
        if not sourcemap_url:
            return None
        if sourcemap_url.startswith(("http://", "https://", "//")):
            return sourcemap_url
        return urljoin(base_url, sourcemap_url)