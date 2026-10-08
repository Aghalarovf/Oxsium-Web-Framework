import asyncio
import aiohttp
from typing import Any
from core.logger import Logger


class Requester:

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; WebArchiveScanner/1.0; "
            "+https://github.com/webarchive-scanner)"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate",
    }

    def __init__(
        self,
        logger: Logger,
        concurrency: int = 10,
        timeout: int = 15,
        retries: int = 3,
        delay: float = 0.5,
    ):
        self.logger = logger
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.delay = delay

        self._semaphore: asyncio.Semaphore | None = None
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "Requester":
        self._semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=False,
            ttl_dns_cache=300,
        )
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_cfg,
            headers=self.DEFAULT_HEADERS,
        )
        return self

    async def __aexit__(self, *_):
        if self._session:
            await self._session.close()
        self._session = None
        self._semaphore = None

    async def get(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
        response_type: str = "json",
    ) -> Any | None:
        if self._session is None or self._semaphore is None:
            raise RuntimeError("Requester must be used within a context manager.")

        last_exc: Exception | None = None

        for attempt in range(1, self.retries + 1):
            try:
                async with self._semaphore:
                    await asyncio.sleep(self.delay)
                    async with self._session.get(
                        url,
                        params=params,
                        headers=headers,
                        allow_redirects=True,
                    ) as resp:

                        self.logger.debug(
                            f"[{resp.status}] {url}"
                            + (f" ?{params}" if params else "")
                        )

                        if resp.status == 429:
                            wait = int(resp.headers.get("Retry-After", 10))
                            self.logger.warning(
                                f"Rate limit 429 — waiting {wait}s. ({url})"
                            )
                            await asyncio.sleep(wait)
                            continue

                        if resp.status >= 500:
                            self.logger.debug(
                                f"Server error {resp.status}, "
                                f"attempt {attempt}/{self.retries}"
                            )
                            last_exc = aiohttp.ClientResponseError(
                                resp.request_info,
                                resp.history,
                                status=resp.status,
                            )
                            await asyncio.sleep(2 ** attempt)
                            continue

                        if resp.status == 404:
                            return None

                        resp.raise_for_status()

                        if response_type == "json":
                            return await resp.json(content_type=None)
                        elif response_type == "text":
                            return await resp.text()
                        else:
                            return await resp.read()

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                self.logger.debug(
                    f"Attempt {attempt}/{self.retries} failed: "
                    f"{type(exc).__name__} — {url}"
                )
                if attempt < self.retries:
                    await asyncio.sleep(2 ** attempt)

        self.logger.warning(f"All retries exhausted: {url} ({last_exc})")
        return None

    async def get_many(
        self,
        requests: list[dict],
    ) -> list[Any | None]:
        tasks = [
            self.get(
                url=r["url"],
                params=r.get("params"),
                headers=r.get("headers"),
                response_type=r.get("response_type", "json"),
            )
            for r in requests
        ]
        return await asyncio.gather(*tasks, return_exceptions=False)