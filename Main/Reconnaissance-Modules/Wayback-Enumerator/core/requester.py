import asyncio
import random
from urllib.parse import urlparse
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

    MAX_BACKOFF = 15.0
    MAX_RETRY_AFTER = 30
    HOST_COOLDOWN_STEP = 1.0
    HOST_COOLDOWN_MAX = 10.0

    def __init__(
        self,
        logger: Logger,
        concurrency: int = 5,
        timeout: int = 20,
        retries: int = 4,
        delay: float = 1.0,
    ):
        self.logger = logger
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.delay = delay

        self._semaphore: asyncio.Semaphore | None = None
        self._session: aiohttp.ClientSession | None = None
        self._host_semaphores: dict[str, asyncio.Semaphore] = {}
        self._host_cooldowns: dict[str, float] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}

    async def __aenter__(self) -> "Requester":
        self._semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=False,
            ttl_dns_cache=300,
            resolver=aiohttp.ThreadedResolver(),
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
        self._host_semaphores = {}
        self._host_cooldowns = {}
        self._host_locks = {}

    def _host_key(self, url: str) -> str:
        return urlparse(url).netloc.lower()

    def _host_semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_semaphores:
            per_host_limit = max(1, min(self.concurrency, 3))
            self._host_semaphores[host] = asyncio.Semaphore(per_host_limit)
        return self._host_semaphores[host]

    def _backoff_seconds(self, attempt: int) -> float:
        base = min(self.MAX_BACKOFF, 2 ** attempt)
        jitter = random.uniform(0, base * 0.4)
        return base + jitter

    async def _apply_host_cooldown(self, host: str) -> None:
        cooldown = self._host_cooldowns.get(host, 0.0)
        if cooldown > 0:
            await asyncio.sleep(cooldown)

    def _raise_host_cooldown(self, host: str) -> None:
        current = self._host_cooldowns.get(host, 0.0)
        self._host_cooldowns[host] = min(
            self.HOST_COOLDOWN_MAX, current + self.HOST_COOLDOWN_STEP
        )

    def _relax_host_cooldown(self, host: str) -> None:
        if host in self._host_cooldowns:
            self._host_cooldowns[host] = max(0.0, self._host_cooldowns[host] - self.HOST_COOLDOWN_STEP)

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
        host = self._host_key(url)
        host_sem = self._host_semaphore(host)

        for attempt in range(1, self.retries + 1):
            try:
                async with self._semaphore, host_sem:
                    await self._apply_host_cooldown(host)
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
                            wait = min(
                                self.MAX_RETRY_AFTER,
                                int(resp.headers.get("Retry-After", 10)),
                            )
                            self._raise_host_cooldown(host)
                            self.logger.warning(
                                f"Rate limit 429 — waiting {wait}s. ({url})"
                            )
                            await asyncio.sleep(wait)
                            continue

                        if resp.status >= 500:
                            self._raise_host_cooldown(host)
                            self.logger.debug(
                                f"Server error {resp.status}, "
                                f"attempt {attempt}/{self.retries}"
                            )
                            last_exc = aiohttp.ClientResponseError(
                                resp.request_info,
                                resp.history,
                                status=resp.status,
                            )
                            await asyncio.sleep(self._backoff_seconds(attempt))
                            continue

                        if resp.status == 404:
                            return None

                        resp.raise_for_status()
                        self._relax_host_cooldown(host)

                        if response_type == "json":
                            return await resp.json(content_type=None)
                        elif response_type == "text":
                            return await resp.text()
                        else:
                            return await resp.read()

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                self._raise_host_cooldown(host)
                self.logger.debug(
                    f"Attempt {attempt}/{self.retries} failed: "
                    f"{type(exc).__name__} — {url}"
                )
                if attempt < self.retries:
                    await asyncio.sleep(self._backoff_seconds(attempt))

        self.logger.warning(f"All retries exhausted: {url} ({last_exc})")
        return None

    async def post(
        self,
        url: str,
        json_body: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        response_type: str = "json",
    ) -> Any | None:
        if self._session is None or self._semaphore is None:
            raise RuntimeError("Requester must be used within a context manager.")

        last_exc: Exception | None = None
        host = self._host_key(url)
        host_sem = self._host_semaphore(host)

        for attempt in range(1, self.retries + 1):
            try:
                async with self._semaphore, host_sem:
                    await self._apply_host_cooldown(host)
                    await asyncio.sleep(self.delay)
                    async with self._session.post(
                        url,
                        json=json_body,
                        params=params,
                        headers=headers,
                        allow_redirects=True,
                    ) as resp:
                        self.logger.debug(f"[{resp.status}] POST {url}")

                        if resp.status == 429:
                            wait = min(
                                self.MAX_RETRY_AFTER,
                                int(resp.headers.get("Retry-After", 10)),
                            )
                            self._raise_host_cooldown(host)
                            self.logger.warning(f"Rate limit 429 — waiting {wait}s. ({url})")
                            await asyncio.sleep(wait)
                            continue

                        if resp.status >= 500:
                            self._raise_host_cooldown(host)
                            last_exc = aiohttp.ClientResponseError(
                                resp.request_info,
                                resp.history,
                                status=resp.status,
                            )
                            await asyncio.sleep(self._backoff_seconds(attempt))
                            continue

                        if resp.status in (401, 403, 404):
                            self.logger.debug(f"POST rejected with {resp.status}: {url}")
                            return None

                        resp.raise_for_status()
                        self._relax_host_cooldown(host)

                        if response_type == "json":
                            return await resp.json(content_type=None)
                        elif response_type == "text":
                            return await resp.text()
                        else:
                            return await resp.read()

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                self._raise_host_cooldown(host)
                if attempt < self.retries:
                    await asyncio.sleep(self._backoff_seconds(attempt))

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