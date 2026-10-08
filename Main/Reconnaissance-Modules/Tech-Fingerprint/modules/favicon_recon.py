import struct
import codecs
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib

try:
    from core.logger import get_logger
    logger = get_logger()
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    logger = logging.getLogger("favicon_recon")


FAVICON_PATHS = [
    "/favicon.ico",
    "/favicon.png",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/assets/favicon.ico",
    "/static/favicon.ico",
    "/images/favicon.ico",
    "/img/favicon.ico",
    "/public/favicon.ico",
]

TECHNOLOGY_FINGERPRINTS = {
    -1856325492: {"name": "WordPress",         "category": "CMS"},
    -1255216943: {"name": "Joomla",            "category": "CMS"},
    -1128487499: {"name": "Drupal",            "category": "CMS"},
     2107506572: {"name": "TYPO3",             "category": "CMS"},
     1248485965: {"name": "Magento",           "category": "E-Commerce"},
    -1148714962: {"name": "PrestaShop",        "category": "E-Commerce"},
     2091018260: {"name": "Shopify",           "category": "E-Commerce"},
     -840750682: {"name": "Ghost",             "category": "CMS"},
     1028868916: {"name": "Wix",               "category": "Website Builder"},
     1270777488: {"name": "Squarespace",       "category": "Website Builder"},
    -1621528840: {"name": "Jenkins",           "category": "CI/CD"},
     1085972930: {"name": "Grafana",           "category": "Monitoring"},
    -1701510933: {"name": "Kibana",            "category": "Analytics"},
    -1622752659: {"name": "phpMyAdmin",        "category": "Database Admin"},
      116606832: {"name": "Prometheus",        "category": "Monitoring"},
    -1016714526: {"name": "GitLab",            "category": "DevOps"},
     -648792148: {"name": "Gitea",             "category": "DevOps"},
    -1279125714: {"name": "Jira",              "category": "Project Management"},
     1811977347: {"name": "Confluence",        "category": "Project Management"},
    -1368191498: {"name": "SonarQube",         "category": "Code Quality"},
      930026470: {"name": "Nexus Repository",  "category": "Artifact Repository"},
    -1136009681: {"name": "Harbor",            "category": "Container Registry"},
     1943685663: {"name": "pfSense",           "category": "Firewall"},
    -1532676002: {"name": "OpenWrt",           "category": "Router"},
    -1336611869: {"name": "MikroTik",          "category": "Network"},
     -380455550: {"name": "Fortinet",          "category": "Security"},
     1219220577: {"name": "Cisco ASA",         "category": "Security"},
    -1427636576: {"name": "Palo Alto",         "category": "Security"},
      561918466: {"name": "Sophos",            "category": "Security"},
     -928428707: {"name": "cPanel",            "category": "Hosting Panel"},
     1289179400: {"name": "Plesk",             "category": "Hosting Panel"},
    -1786734648: {"name": "DirectAdmin",       "category": "Hosting Panel"},
    -1553890546: {"name": "Webmin",            "category": "Admin Panel"},
    -1124962113: {"name": "Django Admin",      "category": "Framework"},
     1328524902: {"name": "Laravel",           "category": "Framework"},
    -1321533895: {"name": "Symfony",           "category": "Framework"},
     -748354153: {"name": "Spring Boot",       "category": "Framework"},
     1801671784: {"name": "Zabbix",            "category": "Monitoring"},
     1496867757: {"name": "Nagios",            "category": "Monitoring"},
     -304557347: {"name": "Splunk",            "category": "SIEM"},
     1469556828: {"name": "Graylog",           "category": "Log Management"},
    -1260886241: {"name": "Traefik",           "category": "Reverse Proxy"},
     -771041581: {"name": "Portainer",         "category": "Container Management"},
     1062022339: {"name": "Rancher",           "category": "Container Management"},
    -1891753143: {"name": "Vault (HashiCorp)", "category": "Secrets Management"},
}

VERSION_PATH_PATTERN = re.compile(
    r"""
    (?:
        (?:v|ver|version|themes?|static|assets?|dist|build|release)
        [-/.]?
        ([\d]+\.[\d]+(?:\.[\d]+)?)
    )
    |
    (?<![.\d])
    ([\d]+\.[\d]+(?:\.[\d]+)?)
    (?![.\d])
    |
    favicon[-_]v?([\d]+(?:\.[\d]+)*)
    """,
    re.IGNORECASE | re.VERBOSE,
)

VALID_CONTENT_TYPES = {
    "image/x-icon", "image/vnd.microsoft.icon", "image/ico",
    "image/png", "image/gif", "image/jpeg", "image/svg+xml",
    "image/webp", "application/octet-stream",
}

_LINK_TAG_RE = re.compile(r"<link\b([^>]*)>", re.IGNORECASE | re.DOTALL)
_ATTR_RE     = re.compile(r"""(\w[\w-]*)=['"]([^'"]*)['""]""", re.IGNORECASE)
_ICO_REL_VALS = {"icon", "shortcut icon", "apple-touch-icon", "apple-touch-icon-precomposed"}


def _fmix(h: int) -> int:
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


def _mmh3_hash(data: bytes) -> int:
    data = codecs.encode(data, "base64")
    length = len(data)
    nblocks = length // 4

    h1 = 0
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = (
            data[block_start]
            | (data[block_start + 1] << 8)
            | (data[block_start + 2] << 16)
            | (data[block_start + 3] << 24)
        )
        if k1 >= 0x80000000:
            k1 -= 0x100000000

        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail_index = nblocks * 4
    k1 = 0
    tail_size = length & 3

    if tail_size >= 3:
        k1 ^= data[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    unsigned_val = _fmix(h1 ^ length)
    if unsigned_val >= 0x80000000:
        return unsigned_val - 0x100000000
    return unsigned_val


def _build_opener() -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPSHandler(context=ctx),
    )
    return opener


_OPENER = _build_opener()


def _fetch_favicon(url: str, timeout: int = 10) -> bytes | None:
    user_agents = [
        "Mozilla/5.0 (compatible; recon-tool/1.0)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    ]
    for ua in user_agents:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with _OPENER.open(req, timeout=timeout) as resp:
                if resp.status != 200:
                    continue
                ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if ct and ct not in VALID_CONTENT_TYPES and "favicon" not in url:
                    logger.debug(f"Skipping {url}: unexpected Content-Type '{ct}'")
                    continue
                content = resp.read()
                if content:
                    return content
        except Exception:
            pass
    return None


def _extract_favicon_url_from_html(base_url: str, timeout: int = 10) -> list[str]:
    found = []
    try:
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; recon-tool/1.0)"},
        )
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")

        parsed_base = urllib.parse.urlparse(base_url)

        for tag_m in _LINK_TAG_RE.finditer(body):
            attrs = {k.lower(): v for k, v in _ATTR_RE.findall(tag_m.group(1))}
            rel = re.sub(r"\s+", " ", attrs.get("rel", "").strip().lower())
            if rel not in _ICO_REL_VALS:
                continue
            href = attrs.get("href", "").strip()
            if not href:
                continue
            if href.startswith("http"):
                found.append(href)
            elif href.startswith("//"):
                found.append(f"{parsed_base.scheme}:{href}")
            else:
                found.append(
                    f"{parsed_base.scheme}://{parsed_base.netloc}/{href.lstrip('/')}"
                )
    except Exception as exc:
        logger.debug(f"HTML parse error for {base_url}: {exc}")

    return list(dict.fromkeys(found))


def _extract_ico_metadata(data: bytes) -> dict:
    meta = {}
    if len(data) < 6 or data[:4] != b"\x00\x00\x01\x00":
        return meta
    try:
        count = struct.unpack_from("<H", data, 4)[0]
        images = []
        for i in range(min(count, 20)):
            offset = 6 + i * 16
            if offset + 16 > len(data):
                break
            images.append({
                "width":       data[offset] or 256,
                "height":      data[offset + 1] or 256,
                "color_count": data[offset + 2],
                "planes":      struct.unpack_from("<H", data, offset + 4)[0],
                "bpp":         struct.unpack_from("<H", data, offset + 6)[0],
            })
        meta["format"]          = "ICO"
        meta["ico_images"]      = images
        meta["ico_image_count"] = len(images)
    except Exception:
        pass
    return meta


def _extract_png_metadata(data: bytes) -> dict:
    meta = {}
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 26:
        return meta
    try:
        color_map = {0: "Grayscale", 2: "RGB", 3: "Indexed",
                     4: "Grayscale+Alpha", 6: "RGBA"}
        meta["format"]     = "PNG"
        meta["width"]      = struct.unpack_from(">I", data, 16)[0]
        meta["height"]     = struct.unpack_from(">I", data, 20)[0]
        meta["bit_depth"]  = data[24]
        meta["color_type"] = color_map.get(data[25], f"Unknown({data[25]})")

        text_chunks = {}
        pos = 8
        while pos + 12 <= len(data):
            chunk_len  = struct.unpack_from(">I", data, pos)[0]
            chunk_type = data[pos + 4: pos + 8]
            chunk_data = data[pos + 8: pos + 8 + chunk_len]
            if chunk_type == b"tEXt":
                try:
                    key, val = chunk_data.split(b"\x00", 1)
                    text_chunks[key.decode()] = val.decode("latin-1")
                except Exception:
                    pass
            elif chunk_type == b"IEND":
                break
            pos += 12 + chunk_len
        if text_chunks:
            meta["text_metadata"] = text_chunks
    except Exception:
        pass
    return meta


def _extract_metadata(data: bytes) -> dict:
    if data[:4] == b"\x00\x00\x01\x00":
        return _extract_ico_metadata(data)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return _extract_png_metadata(data)
    if data[:3] == b"GIF":
        return {"format": "GIF"}
    if b"<svg" in data[:256].lower():
        return {"format": "SVG"}
    return {}


def _check_version_in_path(path: str) -> str:
    m = VERSION_PATH_PATTERN.search(path)
    if not m:
        return ""
    return next((g for g in m.groups() if g), "")


def _build_search_queries(mmh3_val: int, md5: str) -> dict:
    return {
        "shodan":  f"http.favicon.hash:{mmh3_val}",
        "censys":  f"services.http.response.favicons.md5_hash={md5}",
        "fofa":    f'icon_hash="{mmh3_val}"',
        "zoomeye": f"iconhash:{mmh3_val}",
        "quake":   f"favicon:{mmh3_val}",
        "hunter":  f'web.icon="{md5}"',
    }


def _try_both_schemes(origin: str, path: str, timeout: int = 10) -> tuple[bytes | None, str | None]:
    for scheme in ("https", "http"):
        parsed = urllib.parse.urlparse(origin)
        url = f"{scheme}://{parsed.netloc}{path}"
        data = _fetch_favicon(url, timeout=timeout)
        if data:
            return data, url
    return None, None


class FaviconRecon:
    def run(self, domain: str, timeout: int = 10) -> dict:
        base_url = domain if domain.startswith("http") else f"https://{domain}"
        parsed   = urllib.parse.urlparse(base_url)
        origin   = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"Starting favicon recon on: {base_url}")

        favicon_data: bytes | None = None
        favicon_url:  str   | None = None

        html_urls = _extract_favicon_url_from_html(base_url, timeout=timeout)
        logger.info(f"Found {len(html_urls)} favicon reference(s) in HTML")

        for url in html_urls:
            data = _fetch_favicon(url, timeout=timeout)
            if data:
                favicon_data = data
                favicon_url  = url
                logger.info(f"Favicon fetched from HTML link: {url}")
                break

        if not favicon_data:
            for path in FAVICON_PATHS:
                data, url = _try_both_schemes(origin, path, timeout=timeout)
                if data:
                    favicon_data = data
                    favicon_url  = url
                    logger.info(f"Favicon fetched from common path: {url}")
                    break

        if not favicon_data:
            logger.warning("No favicon found for target")
            return {
                "favicon_found":   False,
                "favicon_url":     None,
                "hashes":          {},
                "size_bytes":      0,
                "technology":      None,
                "version_in_path": None,
                "file_metadata":   {},
                "search_queries":  {},
                "technologies":    [],
            }

        mmh3_val   = _mmh3_hash(favicon_data)
        md5_val    = hashlib.md5(favicon_data).hexdigest()
        sha1_val   = hashlib.sha1(favicon_data).hexdigest()
        sha256_val = hashlib.sha256(favicon_data).hexdigest()

        logger.info(f"MMH3: {mmh3_val}  MD5: {md5_val}")

        technology = TECHNOLOGY_FINGERPRINTS.get(mmh3_val)
        if technology:
            logger.info(f"Technology: {technology['name']} ({technology['category']})")
        else:
            logger.info("No technology match in fingerprint DB")

        version_in_path = _check_version_in_path(favicon_url)
        if version_in_path:
            logger.info(f"Version in path: {version_in_path}")

        file_meta  = _extract_metadata(favicon_data)
        queries    = _build_search_queries(mmh3_val, md5_val)

        technologies = []
        if technology:
            technologies.append({
                "name":         technology["name"],
                "version":      version_in_path or "",
                "category":     technology["category"],
                "detected_via": "favicon_hash",
                "raw_value":    str(mmh3_val),
            })

        return {
            "favicon_found":   True,
            "favicon_url":     favicon_url,
            "size_bytes":      len(favicon_data),
            "hashes": {
                "mmh3":   mmh3_val,
                "md5":    md5_val,
                "sha1":   sha1_val,
                "sha256": sha256_val,
            },
            "technology":      technology,
            "version_in_path": version_in_path or None,
            "file_metadata":   file_meta,
            "search_queries":  queries,
            "technologies":    technologies,
        }


if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = FaviconRecon().run(target)
    print(json.dumps(result, indent=2, ensure_ascii=False))