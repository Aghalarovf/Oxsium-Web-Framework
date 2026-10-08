import time
import random
import urllib.parse
import urllib.request
import urllib.error
import ssl
import json
from typing import Optional


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/16.5 Safari/605.1.15",

    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",

    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

GOOGLE_SEARCH_URL  = "https://www.google.com/search"
SERPAPI_SEARCH_URL = "https://serpapi.com/search.json"


class Requester:
    def __init__(
        self,
        delay: float = 2.0,
        timeout: int = 10,
        proxy: Optional[str] = None,
        serpapi_key: Optional[str] = None,
    ):
        self.delay = delay
        self.timeout = timeout
        self.proxy = proxy
        self.serpapi_key = serpapi_key
        self._last_request_time: float = 0.0
        self._ssl_ctx = ssl.create_default_context()

    @property
    def mode(self) -> str:
        return "serpapi" if self.serpapi_key else "direct"

    def _random_agent(self) -> str:
        return random.choice(USER_AGENTS)

    def _throttle(self):
        elapsed = time.time() - self._last_request_time
        jitter = random.uniform(0.3, 1.2)
        wait = max(0.0, self.delay + jitter - elapsed)
        if wait > 0:
            time.sleep(wait)
        self._last_request_time = time.time()

    def _build_google_url(self, dork: str) -> str:
        params = urllib.parse.urlencode({
            "q":   dork,
            "num": 10,
            "hl":  "en",
        })
        return f"{GOOGLE_SEARCH_URL}?{params}"

    def _build_serpapi_url(self, dork: str) -> str:
        params = urllib.parse.urlencode({
            "q":       dork,
            "engine":  "google",
            "num":     10,
            "hl":      "en",
            "api_key": self.serpapi_key,
        })
        return f"{SERPAPI_SEARCH_URL}?{params}"

    def _build_opener(self):
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http":  self.proxy,
                "https": self.proxy,
            }))
        handlers.append(urllib.request.HTTPSHandler(context=self._ssl_ctx))
        return urllib.request.build_opener(*handlers)

    def _fetch_raw(self, url: str) -> str:
        self._throttle()

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":                self._random_agent(),
                "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language":           "en-US,en;q=0.9",
                "Accept-Encoding":           "gzip, deflate",
                "DNT":                       "1",
                "Connection":                "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            },
        )

        opener = self._build_opener()

        try:
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                encoding = response.headers.get_content_charset() or "utf-8"
                try:
                    return raw.decode(encoding, errors="replace")
                except Exception:
                    import gzip as _gzip
                    try:
                        return _gzip.decompress(raw).decode("utf-8", errors="replace")
                    except Exception:
                        return raw.decode("utf-8", errors="replace")

        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RuntimeError(
                    "Google rate-limited this IP (HTTP 429). "
                    "Increase --delay, use --proxy, or add --serpapi-key."
                )
            raise

        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error: {exc.reason}")

    def _search_serpapi(self, dork: str) -> list[str]:
        url  = self._build_serpapi_url(dork)
        self._throttle()

        request = urllib.request.Request(
            url,
            headers={"User-Agent": self._random_agent()},
        )
        opener = self._build_opener()

        try:
            with opener.open(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"SerpAPI error {exc.code}: {body[:200]}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"SerpAPI network error: {exc.reason}")

        results = data.get("organic_results", [])
        return [r["link"] for r in results if "link" in r]

    def search(self, dork: str) -> Optional[str]:
        if self.serpapi_key:
            hits = self._search_serpapi(dork)
            return "\x00SERPAPI\x00" + json.dumps(hits)
        return self._fetch_raw(self._build_google_url(dork))

    def build_dork_url(self, dork: str) -> str:
        return self._build_google_url(dork)

    def fetch(self, url: str) -> Optional[str]:
        return self._fetch_raw(url)