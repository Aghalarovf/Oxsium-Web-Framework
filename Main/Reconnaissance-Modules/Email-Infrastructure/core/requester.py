import asyncio
import socket
from dataclasses import dataclass
from typing import Optional

import aiohttp


@dataclass
class Response:
    status: int
    url: str
    text: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400


class Requester:

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; EmailInfraEnum/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, timeout: float = 10.0, concurrency: int = 10) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._semaphore = asyncio.Semaphore(concurrency)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers=self.DEFAULT_HEADERS,
                timeout=self._timeout,
                connector=aiohttp.TCPConnector(ssl=False),
            )
        return self._session

    async def get(
        self,
        url: str,
        headers: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> Optional[Response]:
        async with self._semaphore:
            try:
                session = await self._get_session()
                request_headers = {**(headers or {}), **(extra_headers or {})}
                async with session.get(url, headers=request_headers, allow_redirects=True) as resp:
                    return Response(
                        status=resp.status,
                        url=str(resp.url),
                        text=await resp.text(errors="replace"),
                    )
            except Exception:
                return Response(status=0, url=url, text="")

    async def get_text(self, url: str, headers: Optional[dict] = None) -> Optional[str]:
        resp = await self.get(url, headers=headers)
        if resp is None:
            return None
        try:
            return resp.text
        except Exception:
            return None

    async def fetch_many(self, urls: list[str]) -> list[Response]:
        responses = await asyncio.gather(*(self.get(url) for url in urls))
        return [response for response in responses if response is not None]

    async def get_status(self, url: str) -> Optional[int]:
        resp = await self.get(url)
        if resp is None:
            return None
        return resp.status

    async def smtp_banner(self, host: str, port: int = 25, timeout: float = 5.0) -> Optional[str]:
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                banner_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return banner_line.decode(errors="replace").strip()
            except Exception:
                return None

    async def is_reachable_smtp(self, host: str, port: int = 25) -> bool:
        return (await self.smtp_banner(host, port=port)) is not None

    async def smtp_vrfy_catch_all(
        self, host: str, test_address: str, port: int = 25, timeout: float = 5.0
    ) -> Optional[bool]:
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                await asyncio.wait_for(reader.readline(), timeout=timeout)

                writer.write(b"EHLO emailinfra.local\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.read(1024), timeout=timeout)

                writer.write(f"MAIL FROM:<probe@emailinfra.local>\r\n".encode())
                await writer.drain()
                await asyncio.wait_for(reader.read(1024), timeout=timeout)

                writer.write(f"RCPT TO:<{test_address}>\r\n".encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout)

                writer.write(b"QUIT\r\n")
                await writer.drain()
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                decoded = response.decode(errors="replace")
                if decoded.startswith("250"):
                    return True
                elif decoded.startswith("550") or decoded.startswith("551"):
                    return False
                return None
            except Exception:
                return None

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()