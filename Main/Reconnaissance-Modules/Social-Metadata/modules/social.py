import html as html_lib
import re
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.traffic import Entry
from .base import BaseModule


SOCIAL_PLATFORMS: dict[str, str] = {
    "LinkedIn": r"linkedin\.com",
    "X / Twitter": r"(?:twitter|x)\.com",
    "GitHub": r"github\.com",
    "GitLab": r"gitlab\.com",
    "Facebook": r"(?:facebook|fb)\.com|fb\.me|m\.me",
    "Instagram": r"instagram\.com|instagr\.am",
    "YouTube": r"youtube\.com|youtu\.be",
    "Telegram": r"t\.me|telegram\.(?:me|org)",
    "Medium": r"medium\.com",
    "TikTok": r"tiktok\.com",
    "Pinterest": r"pinterest\.[a-z.]{2,6}|pin\.it",
    "Snapchat": r"snapchat\.com",
    "WhatsApp": r"wa\.me|whatsapp\.com",
    "Reddit": r"reddit\.com",
    "Discord": r"discord\.(?:gg|com)|discordapp\.com",
    "Vimeo": r"vimeo\.com",
    "Threads": r"threads\.net",
    "Bluesky": r"bsky\.app",
    "Mastodon": r"mastodon\.[a-z.]{2,}",
    "Viber": r"viber\.com|invite\.viber\.com",
    "VK": r"vk\.com|vk\.ru",
    "OK.ru": r"ok\.ru",
    "Twitch": r"twitch\.tv",
    "Tumblr": r"tumblr\.com",
    "Flickr": r"flickr\.com",
    "SoundCloud": r"soundcloud\.com",
    "Behance": r"behance\.net",
    "Dribbble": r"dribbble\.com",
    "Quora": r"quora\.com",
    "Skype": r"join\.skype\.com|skype\.com",
    "WeChat": r"weixin\.qq\.com|wechat\.com",
    "LINE": r"line\.me",
    "Xing": r"xing\.com",
    "Spotify": r"open\.spotify\.com",
    "Rutube": r"rutube\.ru",
    "Patreon": r"patreon\.com",
    "Ko-fi": r"ko-fi\.com",
    "Buy Me a Coffee": r"buymeacoffee\.com|bmc\.link",
    "Linktree": r"linktr\.ee",
    "Link-in-bio": r"beacons\.ai|bio\.link|lnk\.bio|campsite\.bio|carrd\.co|taplink\.(?:cc|at|ws)|linkin\.bio|solo\.to|bento\.me",
    "Substack": r"substack\.com",
    "Clubhouse": r"clubhouse\.com|joinclubhouse\.com",
    "Kick": r"kick\.com",
    "Rumble": r"rumble\.com",
    "Odysee": r"odysee\.com",
    "BitChute": r"bitchute\.com",
    "Dailymotion": r"dailymotion\.com|dai\.ly",
    "Bilibili": r"bilibili\.com|b23\.tv",
    "Douyin": r"douyin\.com",
    "Kuaishou / Kwai": r"kuaishou\.com|kwai\.com|kw\.ai",
    "Likee": r"likee\.video|likee\.com",
    "Lemon8": r"lemon8-app\.com",
    "Weibo": r"weibo\.(?:com|cn)|t\.cn",
    "Zhihu": r"zhihu\.com",
    "Naver": r"(?:blog|cafe|band)\.naver\.com|naver\.me",
    "Band": r"band\.us",
    "KakaoTalk": r"open\.kakao\.com|pf\.kakao\.com|kakao\.com",
    "Zalo": r"zalo\.me|zaloapp\.com",
    "Signal": r"signal\.(?:me|group|org)",
    "Slack": r"slack\.com",
    "Gettr": r"gettr\.com",
    "Truth Social": r"truthsocial\.com",
    "Parler": r"parler\.com",
    "Gab": r"gab\.com",
    "Nextdoor": r"nextdoor\.com",
    "Dzen": r"dzen\.ru|zen\.yandex\.(?:ru|com)",
    "Yandex Music": r"music\.yandex\.(?:ru|com|az|kz|by)",
    "Livejournal": r"livejournal\.com",
    "Habr": r"habr\.com",
    "Stack Overflow": r"stackoverflow\.com|stackexchange\.com",
    "Dev.to": r"dev\.to",
    "Hashnode": r"hashnode\.(?:com|dev)",
    "CodePen": r"codepen\.io",
    "Bitbucket": r"bitbucket\.org",
    "Hugging Face": r"huggingface\.co",
    "Kaggle": r"kaggle\.com",
    "Docker Hub": r"hub\.docker\.com",
    "npm": r"npmjs\.com",
    "PyPI": r"pypi\.org",
    "Product Hunt": r"producthunt\.com",
    "Crunchbase": r"crunchbase\.com",
    "Wellfound": r"wellfound\.com|angel\.co",
    "Glassdoor": r"glassdoor\.(?:com|co\.uk)",
    "Indeed": r"indeed\.com",
    "Meetup": r"meetup\.com",
    "Eventbrite": r"eventbrite\.[a-z.]{2,6}",
    "Calendly": r"calendly\.com",
    "Bandcamp": r"bandcamp\.com",
    "Mixcloud": r"mixcloud\.com",
    "Apple Music": r"music\.apple\.com",
    "Apple Podcasts": r"podcasts\.apple\.com",
    "Deezer": r"deezer\.com|dzr\.page\.link",
    "Tidal": r"tidal\.com",
    "Last.fm": r"last\.fm",
    "Goodreads": r"goodreads\.com",
    "ArtStation": r"artstation\.com",
    "DeviantArt": r"deviantart\.com",
    "500px": r"500px\.com",
    "Unsplash": r"unsplash\.com",
    "Etsy": r"etsy\.com",
    "Yelp": r"yelp\.[a-z.]{2,6}",
    "TripAdvisor": r"tripadvisor\.[a-z.]{2,6}",
    "Foursquare": r"foursquare\.com|4sq\.com",
    "Trustpilot": r"trustpilot\.com",
    "Google Maps": r"maps\.google\.[a-z.]{2,6}|google\.[a-z.]{2,6}/maps|maps\.app\.goo\.gl|goo\.gl/maps|g\.page",
    "Google Business": r"business\.google\.com|share\.google",
    "Wikipedia": r"(?:[a-z]{2,3}\.)?wikipedia\.org",
    "Gravatar": r"gravatar\.com",
    "About.me": r"about\.me",
    "Disqus": r"disqus\.com",
    "Zoom": r"(?:[a-z0-9-]+\.)?zoom\.us",
    "Microsoft Teams": r"teams\.microsoft\.com|teams\.live\.com",
    "Google Chat / Meet": r"meet\.google\.com|chat\.google\.com",
    "Apple Messages / FaceTime": r"facetime\.apple\.com",
    "Trello": r"trello\.com",
    "Notion": r"notion\.(?:so|site)",
    "Figma": r"figma\.com",
}

_PLATFORM_URL_RES: list[tuple[str, re.Pattern]] = [
    (
        name,
        re.compile(
            r"(?<![\w.-])(?:https?:)?//(?:[a-z0-9-]+\.)*(?:" + host + r")"
            r"(?=[/?#:\s\"'<>\\`)]|$)(?:[/?#][^\s\"'<>\\`]*)?",
            re.I,
        ),
    )
    for name, host in SOCIAL_PLATFORMS.items()
]

_HOST_ONLY_RE = re.compile(r"^(?:https?:)?//[^/?#]+/?$", re.I)

_ROOT_RES: dict[str, re.Pattern] = {
    name: re.compile(
        r"^(?:https?:)?//(?:(?:www|m|mobile|web|mbasic|touch|en|l)\.)?(?:" + host + r")/?$",
        re.I,
    )
    for name, host in SOCIAL_PLATFORMS.items()
}

_NOISE_PATH_RE = re.compile(
    r"^/(?:tr/?(?:[?#]|$)|plugins/|dialog/|sharer(?:\.php|/)|share(?:\.php|/)|intent/|widgets\.js|"
    r"embed/|sdk/|sdk\.js|v\d+\.\d+/|en_US/|impression\.php|tr\?)",
    re.I,
)
_NOISE_HOST_RE = re.compile(
    r"^(?:connect\.facebook\.net|platform\.twitter\.com|syndication\.twitter\.com|"
    r"static\.xx\.fbcdn\.net|www\.facebook\.com/tr|platform\.linkedin\.com|snap\.licdn\.com|"
    r"px\.ads\.linkedin\.com|analytics\.tiktok\.com|ads-twitter\.com|static\.ads-twitter\.com|"
    r"assets\.pinterest\.com|s\.pinimg\.com|i\.ytimg\.com)$",
    re.I,
)

_SHARE_RE = re.compile(
    r"(?:sharer|share|intent/tweet|intent/post|shareArticle|share-offsite|sharing|send\?|dialog/share)",
    re.I,
)
_VIDEO_RE = re.compile(r"(?:/watch\?|/embed/|/shorts/|youtu\.be/|/video/|/videos/)", re.I)

_HANDLE_META = {
    "twitter:site": "X / Twitter",
    "twitter:creator": "X / Twitter",
}
_PROFILE_URL_META = {
    "article:publisher": "Facebook",
    "article:author": "Facebook",
    "og:see_also": None,
    "profile:username": None,
}

_APP_STORES: list[tuple[str, str, str | None]] = [
    ("Apple App Store", r"(?:apps|itunes|geo\.itunes)\.apple\.com", None),
    ("Apple TestFlight", r"testflight\.apple\.com", None),
    ("Google Play", r"play\.google\.com", r"/(?:store/)?apps"),
    ("Huawei AppGallery", r"(?:appgal{1,2}ery(?:\.cloud)?\.huawei\.com|url\.cloud\.huawei\.com|app\.hicloud\.com)", None),
    ("Samsung Galaxy Store", r"(?:galaxystore|apps)\.samsung\.com", None),
    ("Microsoft Store", r"(?:apps\.microsoft\.com|(?:www\.)?microsoft\.com/(?:[a-z]{2}-[a-z]{2}/)?(?:p|store)/)", None),
    ("Amazon Appstore", r"(?:amazon\.[a-z.]+/(?:gp/mas|appstore|gp/product/[A-Z0-9]+.*appstore)|appstore\.amazon\.com)", None),
    ("Xiaomi GetApps", r"(?:global\.)?app\.mi\.com", None),
    ("Opera Mobile Store", r"apps\.opera\.com", None),
    ("Oppo/HeyTap App Market", r"(?:store|app)\.heytap\.com|apps\.oppomobile\.com", None),
    ("Vivo App Store", r"(?:developers|apps)\.vivo\.com(?:\.cn)?", None),
    ("F-Droid", r"f-droid\.org", r"/packages"),
    ("Aptoide", r"(?:[a-z0-9-]+\.)?aptoide\.com", None),
    ("APKPure", r"apkpure\.(?:com|net)", None),
    ("APKMirror", r"apkmirror\.com", None),
    ("Uptodown", r"(?:[a-z0-9-]+\.)?uptodown\.com", None),
    ("AppBrain", r"appbrain\.com", None),
    ("Chrome Web Store", r"(?:chromewebstore\.google\.com|chrome\.google\.com/webstore)", None),
    ("Firefox Add-ons", r"addons\.mozilla\.org", None),
    ("Edge Add-ons", r"microsoftedge\.microsoft\.com/addons", None),
    ("Snap Store", r"snapcraft\.io", r"/[A-Za-z0-9._-]+"),
    ("Flathub", r"flathub\.org/apps", None),
    ("OneLink (AppsFlyer)", r"(?:[a-z0-9-]+\.)?onelink\.(?:me|to)|app\.appsflyer\.com", None),
    ("Adjust link", r"(?:app\.adjust\.(?:com|io)|adj\.st|[a-z0-9-]+\.adj\.st)", None),
    ("Branch link", r"(?:[a-z0-9-]+\.)?app\.link|bnc\.lt", None),
    ("Firebase Dynamic Link", r"(?:[a-z0-9-]+\.)?page\.link|(?:[a-z0-9-]+\.)?app\.goo\.gl", None),
    ("Singular link", r"sng\.link", None),
    ("Kochava/Smart link", r"smart\.link|(?:[a-z0-9-]+\.)?go\.link", None),
]

_APP_STORE_RES: list[tuple[str, re.Pattern, re.Pattern | None]] = [
    (
        name,
        re.compile(
            r"(?<![\w.-])(?:(?:https?:)?//)?(?:www\.)?(?:" + host + r")"
            r"(?=[/?#:\s\"'<>\\`)]|$)(?:[/?#][^\s\"'<>\\`]*)?",
            re.I,
        ),
        re.compile(path, re.I) if path else None,
    )
    for name, host, path in _APP_STORES
]

_APP_SCHEMES: list[tuple[str, re.Pattern]] = [
    ("Google Play (market://)", re.compile(r"market://[^\s\"'<>\\`]+", re.I)),
    ("App Store (itms-apps://)", re.compile(r"itms-apps?://[^\s\"'<>\\`]+", re.I)),
    ("iOS OTA install (itms-services)", re.compile(r"itms-services://[^\s\"'<>\\`]+", re.I)),
    ("Microsoft Store (ms-windows-store://)", re.compile(r"ms-windows-store://[^\s\"'<>\\`]+", re.I)),
    ("Huawei AppGallery (appmarket://)", re.compile(r"appmarket://[^\s\"'<>\\`]+", re.I)),
    ("Samsung Galaxy Store (samsungapps://)", re.compile(r"samsungapps://[^\s\"'<>\\`]+", re.I)),
    ("Android app link (android-app://)", re.compile(r"android-app://[^\s\"'<>\\`]+", re.I)),
    ("iOS app link (ios-app://)", re.compile(r"ios-app://[^\s\"'<>\\`]+", re.I)),
]

_APP_PACKAGE_FILE_RE = re.compile(
    r"https?://[^\s\"'<>\\`]+\.(?:apk|xapk|aab|ipa|msix|msixbundle|appx|appxbundle)(?:\?[^\s\"'<>\\`]*)?",
    re.I,
)

_TRAILING_JUNK = ".,;:)&'\"]}"


def _unescape_text(text: str) -> str:
    text = text.replace("\\/", "/").replace("\\u002F", "/").replace("\\u002f", "/")
    text = text.replace("\\u0026", "&").replace("\\x2F", "/").replace("\\x2f", "/")
    return html_lib.unescape(text)


def _clean_url(url: str) -> str:
    url = url.rstrip(_TRAILING_JUNK)
    if url.startswith("//"):
        url = "https:" + url
    elif "://" not in url:
        url = "https://" + url
    return url


def _is_bare_root(url: str, platform: str) -> bool:
    if not _HOST_ONLY_RE.match(url):
        return False
    return bool(_ROOT_RES[platform].match(url))


def _is_noise(url: str) -> bool:
    body = re.sub(r"^https?://", "", url, flags=re.I)
    host, _, rest = body.partition("/")
    if _NOISE_HOST_RE.match(host.split(":")[0]):
        return True
    return bool(_NOISE_PATH_RE.match("/" + rest))


def _link_type(url: str) -> str:
    if _SHARE_RE.search(url):
        return "share"
    if _VIDEO_RE.search(url):
        return "video"
    return "profile"


def _app_id(store: str, url: str) -> str:
    try:
        if store == "Google Play" or "market://" in store:
            m = re.search(r"[?&]id=([A-Za-z0-9._]+)", url)
            return m.group(1) if m else ""
        if "Apple" in store or "itms" in store:
            m = re.search(r"/id(\d{6,})|[?&]id=(\d{6,})", url)
            return (m.group(1) or m.group(2)) if m else ""
        if "Huawei" in store:
            m = re.search(r"/app/(C\d+)|[?&]appId=(C?\d+)", url, re.I)
            return (m.group(1) or m.group(2)) if m else ""
        if store == "F-Droid":
            m = re.search(r"/packages/([A-Za-z0-9._]+)", url)
            return m.group(1) if m else ""
        if store == "Samsung Galaxy Store":
            m = re.search(r"/detail/([A-Za-z0-9._]+)", url)
            return m.group(1) if m else ""
        if store == "Chrome Web Store":
            m = re.search(r"/([a-p]{32})", url)
            return m.group(1) if m else ""
    except Exception:
        pass
    return ""


def _extract_app_links(text: str, soup: BeautifulSoup | None = None) -> list[dict]:
    text = _unescape_text(text)
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(store: str, url: str, app_id: str = "") -> None:
        url = _clean_url(url)
        key = (store, url.lower().rstrip("/"))
        if key in seen:
            return
        seen.add(key)
        entry = {"store": store, "url": url}
        app_id = app_id or _app_id(store, url)
        if app_id:
            entry["app_id"] = app_id
        found.append(entry)

    for store, pattern, path_req in _APP_STORE_RES:
        for m in pattern.finditer(text):
            url = m.group(0)
            if store == "Firebase Dynamic Link" and "maps.app.goo.gl" in url.lower():
                continue
            rest = re.sub(r"^(?:(?:https?:)?//)?(?:www\.)?[^/?#]+", "", url, flags=re.I)
            if path_req is not None and not path_req.match(rest):
                continue
            if not rest.strip("/"):
                continue
            add(store, url)

    for store, pattern in _APP_SCHEMES:
        for m in pattern.finditer(text):
            add(store, m.group(0))

    for m in _APP_PACKAGE_FILE_RE.finditer(text):
        add("Direct app package", m.group(0))

    if soup is not None:
        for tag in soup.find_all("meta"):
            name = (tag.get("name") or tag.get("property") or "").lower()
            content = (tag.get("content") or "").strip()
            if not content:
                continue
            if name == "apple-itunes-app":
                m = re.search(r"app-id=(\d+)", content)
                if m:
                    add("Apple App Store (meta)", f"https://apps.apple.com/app/id{m.group(1)}", m.group(1))
            elif name == "google-play-app":
                m = re.search(r"app-id=([A-Za-z0-9._]+)", content)
                if m:
                    add("Google Play (meta)", f"https://play.google.com/store/apps/details?id={m.group(1)}", m.group(1))
            elif name == "al:ios:app_store_id":
                add("Apple App Store (meta)", f"https://apps.apple.com/app/id{content}", content)
            elif name == "al:android:package":
                add("Google Play (meta)", f"https://play.google.com/store/apps/details?id={content}", content)

    return found


class SocialModule(BaseModule):
    NAME = "social"
    DESCRIPTION = "Social profile and app-store link discovery from captured traffic (offline)"

    async def run(self) -> list[dict[str, Any]]:
        self.logger.section(f"[{self.NAME.upper()}] {self.DESCRIPTION}")

        self._social: dict[str, dict[str, Any]] = {}
        self._apps: dict[tuple[str, str], dict[str, Any]] = {}

        entries = self.traffic.texts()
        self.logger.info(f"Scanning {len(entries)} captured text response(s)")

        for entry in entries:
            self._scan_entry(entry)

        for item in self._social.values():
            self._add_finding(
                source=item["sources"][0],
                sources=item["sources"] if len(item["sources"]) > 1 else None,
                platform=item["platform"],
                type=item["type"],
                url=item["url"],
                found_on=item["found_on"],
            )
            self._log_finding(item["platform"], item["url"])

        for item in self._apps.values():
            self._add_finding(
                source="app_link",
                platform=item["store"],
                url=item["url"],
                app_id=item.get("app_id"),
                found_on=item["found_on"],
            )
            ident = f"{item['app_id']}  " if item.get("app_id") else ""
            self._log_finding(item["store"], f"{ident}({item['url']})" if ident else item["url"])

        self._print_summary()
        return self._findings

    def _scan_entry(self, entry: Entry) -> None:
        text = entry.body
        soup = None
        if entry.is_html:
            soup = BeautifulSoup(text, "lxml")
            for anchor in soup.find_all("a", href=True):
                raw = anchor.get("href", "").strip()
                if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                url = raw if raw.startswith(("http://", "https://")) else urljoin(entry.url, raw)
                self._register_social(url, entry.url, "anchor")
            self._scan_meta_handles(soup, entry.url)

        clean = _unescape_text(text)
        for platform, pattern in _PLATFORM_URL_RES:
            for m in pattern.finditer(clean):
                self._register_social(m.group(0), entry.url, "anchor" if soup is not None else "body_text", platform)

        for app in _extract_app_links(text, soup):
            key = (app["store"], app["url"].lower().rstrip("/"))
            slot = self._apps.setdefault(key, {**app, "found_on": []})
            if entry.url not in slot["found_on"]:
                slot["found_on"].append(entry.url)

    def _register_social(self, url: str, page: str, source: str, platform: str | None = None) -> None:
        url = _clean_url(url)
        if _is_noise(url):
            return
        if platform is None:
            for name, pattern in _PLATFORM_URL_RES:
                if pattern.match(url):
                    platform = name
                    break
        if platform is None or _is_bare_root(url, platform):
            return
        key = url.lower().rstrip("/")
        slot = self._social.get(key)
        if slot is None:
            slot = {
                "platform": platform,
                "url": url,
                "type": _link_type(url),
                "sources": [],
                "found_on": [],
            }
            self._social[key] = slot
        if source not in slot["sources"]:
            slot["sources"].append(source)
        if page not in slot["found_on"]:
            slot["found_on"].append(page)

    def _scan_meta_handles(self, soup: BeautifulSoup, page: str) -> None:
        for tag in soup.find_all("meta"):
            name = (tag.get("name") or tag.get("property") or "").strip().lower()
            content = (tag.get("content") or "").strip()
            if not content:
                continue
            if name in _HANDLE_META:
                handle = content.lstrip("@").strip("/ ")
                if re.fullmatch(r"[A-Za-z0-9_]{1,30}", handle):
                    self._register_social(f"https://x.com/{handle}", page, "meta_handle", _HANDLE_META[name])
            elif name in _PROFILE_URL_META and content.startswith(("http://", "https://")):
                self._register_social(content, page, "meta_tag")

    def _print_summary(self):
        if not self._findings:
            self.logger.warning("No social / app-store links discovered.")
            return
        by_platform: dict[str, int] = {}
        for f in self._findings:
            p = f.get("platform", "unknown")
            by_platform[p] = by_platform.get(p, 0) + 1
        self.logger.table(
            ["Platform", "Count"],
            [[p, str(c)] for p, c in sorted(by_platform.items())],
        )
        self.logger.info(f"Total unique social / app-store links: {len(self._findings)}")