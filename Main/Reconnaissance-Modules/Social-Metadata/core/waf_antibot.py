import asyncio
import random
import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


logger = logging.getLogger("waf_antibot")


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "az-AZ,az;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9,ru;q=0.8",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
]

WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
    "Akamai":       ["x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"],
    "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":      ["x-iinfo", "x-cdn-forward", "incap_ses"],
    "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop"],
    "F5 BIG-IP":    ["bigipserver", "x-cnection", "f5-trafficshield"],
    "Fastly":       ["x-fastly-request-id", "fastly-restarts"],
    "DDoS-Guard":   ["ddos-guard"],
    "Radware":      ["x-sl-compstate"],
    "Barracuda":    ["barra_counter_session"],
}

BLOCKED_STATUSES = {403, 406, 429, 503, 520, 521, 522, 523, 524}


@dataclass
class FetchResult:
    url: str
    status: int
    html: str
    headers: dict
    waf: Optional[str]
    method: str
    ok: bool
    request_headers: dict = field(default_factory=dict)
    error: Optional[str] = None

    def text(self) -> str:
        return self.html


@dataclass
class HumanBehavior:
    min_delay: float = 1.0
    max_delay: float = 4.0
    burst_every: int = 8
    burst_pause_min: float = 5.0
    burst_pause_max: float = 12.0
    request_count: int = field(default=0, init=False)

    async def wait(self):
        self.request_count += 1
        if self.request_count % self.burst_every == 0:
            pause = random.uniform(self.burst_pause_min, self.burst_pause_max)
            logger.debug(f"Burst pause: {pause:.1f}s after {self.request_count} requests")
            await asyncio.sleep(pause)
        else:
            delay = random.uniform(self.min_delay, self.max_delay)
            jitter = random.uniform(-0.2, 0.2)
            await asyncio.sleep(max(0.3, delay + jitter))


def _detect_waf(headers: dict) -> Optional[str]:
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in lower:
                return waf
    server = lower.get("server", "")
    if "cloudflare" in server:
        return "Cloudflare"
    if "ddos-guard" in server:
        return "DDoS-Guard"
    return None


def _build_headers(ua: str, lang: str, referer: Optional[str] = None) -> dict:
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": lang,
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-CH-UA": '"Chromium";v="125", "Not.A/Brand";v="24"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if not referer else "same-origin",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "DNT": "1",
    }
    if referer:
        headers["Referer"] = referer
    return headers


class SessionPool:
    def __init__(self, size: int = 3):
        self._size = size
        self._sessions: list[aiohttp.ClientSession] = []
        self._index = 0

    async def build(self, target: str):
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        for _ in range(self._size):
            ua = random.choice(USER_AGENTS)
            lang = random.choice(ACCEPT_LANGUAGES)
            session = aiohttp.ClientSession(
                connector=connector,
                headers=_build_headers(ua, lang),
                cookie_jar=aiohttp.CookieJar(),
                timeout=aiohttp.ClientTimeout(total=30),
            )
            try:
                async with session.get(target, allow_redirects=True) as resp:
                    await resp.read()
            except Exception:
                pass
            self._sessions.append(session)

    def next(self) -> aiohttp.ClientSession:
        session = self._sessions[self._index % len(self._sessions)]
        self._index += 1
        return session

    async def close(self):
        for s in self._sessions:
            await s.close()


class BrowserFetcher:
    def __init__(self):
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None

    async def start(self):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("playwright not installed — run: pip install playwright && playwright install chromium")
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--disable-infobars",
                "--window-size=1920,1080",
            ],
        )
        ua = random.choice(USER_AGENTS)
        self._context = await self._browser.new_context(
            user_agent=ua,
            locale=random.choice(["en-US", "az-AZ", "en-GB"]),
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True,
            ignore_https_errors=True,
            extra_http_headers={
                "Accept-Language": random.choice(ACCEPT_LANGUAGES),
                "DNT": "1",
            },
        )
        await self._context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
        """)

    async def fetch(self, url: str) -> tuple[str, int, dict, dict]:
        page = await self._context.new_page()
        captured_request_headers: dict = {}

        async def _on_request(request):
            nonlocal captured_request_headers
            if not captured_request_headers and request.url.startswith(url.split("?")[0]):
                captured_request_headers = dict(request.headers)

        page.on("request", _on_request)

        try:
            await asyncio.sleep(random.uniform(0.5, 1.5))
            response = await page.goto(url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(random.uniform(1.0, 2.5))
            await page.mouse.move(
                random.randint(100, 800),
                random.randint(100, 600),
            )
            await page.evaluate("window.scrollBy(0, Math.random() * 300 + 100)")
            await asyncio.sleep(random.uniform(0.5, 1.0))
            html = await page.content()
            status = response.status if response else 200
            headers = dict(response.headers) if response else {}
            return html, status, headers, captured_request_headers
        finally:
            await page.close()

    async def stop(self):
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()


class HumanRequester:
    def __init__(
        self,
        target: str,
        session_pool_size: int = 3,
        concurrency: int = 3,
        min_delay: float = 1.0,
        max_delay: float = 4.0,
        use_browser_fallback: bool = True,
        retries: int = 2,
    ):
        self.target = target.rstrip("/")
        self._domain = urlparse(target).hostname or ""
        if self._domain.startswith("www."):
            self._domain = self._domain[4:]

        self._pool = SessionPool(size=session_pool_size)
        self._behavior = HumanBehavior(min_delay=min_delay, max_delay=max_delay)
        self._browser: Optional[BrowserFetcher] = None
        self._use_browser_fallback = use_browser_fallback and PLAYWRIGHT_AVAILABLE
        self._retries = retries
        self._semaphore = asyncio.Semaphore(concurrency)
        self._detected_waf: Optional[str] = None
        self._lock = asyncio.Lock()

    async def start(self):
        logger.info(f"Warming up session pool against {self.target}")
        await self._pool.build(self.target)
        if self._use_browser_fallback:
            self._browser = BrowserFetcher()
            await self._browser.start()
            logger.info("Browser fallback ready (Playwright/Chromium)")
        else:
            logger.info("Browser fallback disabled or Playwright not installed")

    async def stop(self):
        await self._pool.close()
        if self._browser:
            await self._browser.stop()

    async def get(self, url: str) -> FetchResult:
        async with self._semaphore:
            await self._behavior.wait()
            return await self._fetch_with_retry(url)

    async def fetch_many(self, urls: list[str]) -> list[FetchResult]:
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _fetch_with_retry(self, url: str) -> FetchResult:
        last_result = None
        for attempt in range(self._retries + 1):
            if attempt > 0:
                backoff = random.uniform(3.0, 8.0) * attempt
                logger.debug(f"Retry {attempt} for {url} after {backoff:.1f}s")
                await asyncio.sleep(backoff)

            result = await self._http_fetch(url)

            async with self._lock:
                if result.waf and not self._detected_waf:
                    self._detected_waf = result.waf
                    logger.info(f"WAF detected: {result.waf}")

            if result.ok:
                return result

            if result.status in BLOCKED_STATUSES and self._browser:
                logger.info(f"HTTP blocked ({result.status}), trying browser for {url}")
                browser_result = await self._browser_fetch(url)
                if browser_result.ok:
                    return browser_result
                last_result = browser_result
            else:
                last_result = result

        return last_result or FetchResult(
            url=url, status=0, html="", headers={},
            waf=None, method="none", ok=False, error="All attempts failed",
        )

    async def _http_fetch(self, url: str) -> FetchResult:
        session = self._pool.next()
        ua = random.choice(USER_AGENTS)
        lang = random.choice(ACCEPT_LANGUAGES)
        headers = _build_headers(ua, lang, referer=self.target if url != self.target else None)
        try:
            async with session.get(url, headers=headers, allow_redirects=True) as resp:
                html = await resp.text(errors="replace")
                h = dict(resp.headers)
                waf = _detect_waf(h)
                ok = resp.status not in BLOCKED_STATUSES and resp.status < 400
                return FetchResult(
                    url=str(resp.url),
                    status=resp.status,
                    html=html,
                    headers=h,
                    waf=waf,
                    method="http",
                    ok=ok,
                    request_headers=headers,
                )
        except aiohttp.ClientError as e:
            return FetchResult(
                url=url, status=0, html="", headers={},
                waf=None, method="http", ok=False, error=str(e),
            )
        except Exception as e:
            return FetchResult(
                url=url, status=0, html="", headers={},
                waf=None, method="http", ok=False, error=str(e),
            )

    async def _browser_fetch(self, url: str) -> FetchResult:
        if not self._browser:
            return FetchResult(
                url=url, status=0, html="", headers={},
                waf=None, method="browser", ok=False, error="Browser not initialized",
            )
        try:
            html, status, headers, req_headers = await self._browser.fetch(url)
            waf = _detect_waf(headers)
            ok = status not in BLOCKED_STATUSES and status < 400
            return FetchResult(
                url=url,
                status=status,
                html=html,
                headers=headers,
                waf=waf,
                method="browser",
                ok=ok,
                request_headers=req_headers,
            )
        except Exception as e:
            return FetchResult(
                url=url, status=0, html="", headers={},
                waf=None, method="browser", ok=False, error=str(e),
            )

    @property
    def detected_waf(self) -> Optional[str]:
        return self._detected_waf

    @property
    def domain(self) -> str:
        return self._domain


def _print_section(title: str):
    width = 60
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


def _summarise_html(html: str) -> dict:
    from html.parser import HTMLParser

    class _Counter(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags: dict[str, int] = {}
            self.title = ""
            self._in_title = False
            self.text_len = 0

        def handle_starttag(self, tag, attrs):
            self.tags[tag] = self.tags.get(tag, 0) + 1
            if tag == "title":
                self._in_title = True

        def handle_endtag(self, tag):
            if tag == "title":
                self._in_title = False

        def handle_data(self, data):
            if self._in_title and not self.title:
                self.title = data.strip()
            self.text_len += len(data.strip())

    c = _Counter()
    try:
        c.feed(html)
    except Exception:
        pass

    top_tags = sorted(c.tags.items(), key=lambda x: x[1], reverse=True)[:8]
    return {
        "title": c.title or "(no title)",
        "total_chars": len(html),
        "text_chars": c.text_len,
        "unique_tags": len(c.tags),
        "top_tags": top_tags,
        "links": c.tags.get("a", 0),
        "scripts": c.tags.get("script", 0),
        "forms": c.tags.get("form", 0),
        "images": c.tags.get("img", 0),
    }


async def _demo(target: str, args):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    requester = HumanRequester(
        target=target,
        session_pool_size=args.pool,
        concurrency=args.concurrency,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        use_browser_fallback=not args.no_browser,
        retries=args.retries,
    )

    await requester.start()

    try:
        result = await requester.get(target)

        _print_section("REQUEST")
        print(f"  Target      : {target}")
        print(f"  Method      : GET")
        print(f"  Sessions    : {args.pool}")
        print(f"  Concurrency : {args.concurrency}")
        print(f"  Delay range : {args.min_delay}s – {args.max_delay}s")
        print(f"  Browser FB  : {'disabled' if args.no_browser else 'enabled (Playwright)'}")
        print(f"  Retries     : {args.retries}")

        _print_section("REQUEST HEADERS")
        if result.request_headers:
            max_key = max(len(k) for k in result.request_headers)
            for key, val in result.request_headers.items():
                print(f"  {key:<{max_key}}  :  {val}")
        else:
            print("  (no request headers captured)")

        _print_section("RESPONSE")
        print(f"  Final URL   : {result.url}")
        print(f"  Status      : {result.status}")
        print(f"  Fetch method: {result.method}")
        print(f"  OK          : {result.ok}")
        print(f"  WAF         : {result.waf or 'None detected'}")
        if result.error:
            print(f"  Error       : {result.error}")

        _print_section("RESPONSE HEADERS")
        if result.headers:
            max_key = max(len(k) for k in result.headers) if result.headers else 12
            for key, val in sorted(result.headers.items()):
                print(f"  {key:<{max_key}}  :  {val}")
        else:
            print("  (no headers)")

        _print_section("HTML CONTENT SUMMARY")
        if result.html:
            info = _summarise_html(result.html)
            print(f"  Page title  : {info['title']}")
            print(f"  Total chars : {info['total_chars']:,}")
            print(f"  Text chars  : {info['text_chars']:,}")
            print(f"  Unique tags : {info['unique_tags']}")
            print(f"  Links (<a>) : {info['links']}")
            print(f"  Scripts     : {info['scripts']}")
            print(f"  Forms       : {info['forms']}")
            print(f"  Images      : {info['images']}")
            print(f"\n  Top tags:")
            for tag, count in info["top_tags"]:
                bar = "█" * min(count, 40)
                print(f"    {tag:<12} {count:>5}  {bar}")

            _print_section("HTML PREVIEW (first 800 chars)")
            preview = result.html[:800].replace("\n", " ").replace("\r", "")
            for i in range(0, len(preview), 100):
                print(f"  {preview[i:i+100]}")
        else:
            print("  (empty body)")

        print(f"\n{'─' * 60}\n")

    finally:
        await requester.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="waf_antibot",
        description="Human-like WAF bypass requester for OSINT",
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. socar.az)")
    parser.add_argument("--scheme", default="https", choices=["http", "https"], help="URL scheme (default: https)")
    parser.add_argument("--pool", type=int, default=3, help="Session pool size (default: 3)")
    parser.add_argument("--concurrency", type=int, default=3, help="Max parallel requests (default: 3)")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Min delay between requests in seconds (default: 1.0)")
    parser.add_argument("--max-delay", type=float, default=4.0, help="Max delay between requests in seconds (default: 4.0)")
    parser.add_argument("--no-browser", action="store_true", help="Disable Playwright browser fallback")
    parser.add_argument("--retries", type=int, default=2, help="Retry attempts on failure (default: 2)")

    args = parser.parse_args()

    domain = args.domain.strip().lstrip("https://").lstrip("http://").rstrip("/")
    target = f"{args.scheme}://{domain}"

    asyncio.run(_demo(target, args))