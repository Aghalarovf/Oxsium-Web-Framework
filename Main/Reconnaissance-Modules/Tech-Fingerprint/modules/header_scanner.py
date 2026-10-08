import re
from core.logger import get_logger
from core.requester import fetch

logger = get_logger()

FINGERPRINTS = [
    ("Server",          r"apache(?:[/ ]([\d.]+))?",           "Apache",           "Web Server"),
    ("Server",          r"nginx(?:[/ ]([\d.]+))?",            "Nginx",            "Web Server"),
    ("Server",          r"microsoft-iis(?:[/ ]([\d.]+))?",   "Microsoft IIS",    "Web Server"),
    ("Server",          r"litespeed",                          "LiteSpeed",        "Web Server"),
    ("Server",          r"openresty(?:[/ ]([\d.]+))?",        "OpenResty",        "Web Server"),
    ("Server",          r"cloudflare",                         "Cloudflare",       "CDN"),
    ("Server",          r"AmazonS3",                           "Amazon S3",        "Cloud Storage"),
    ("Server",          r"AmazonEC2",                          "Amazon EC2",       "Hosting"),
    ("Server",          r"GitHub\.com",                        "GitHub Pages",     "Hosting"),
    ("Server",          r"Netlify",                            "Netlify",          "Hosting"),
    ("Server",          r"Vercel",                             "Vercel",           "Hosting"),
    ("X-Powered-By",    r"php(?:[/ ]([\d.]+))?",              "PHP",              "Programming Language"),
    ("X-Powered-By",    r"asp\.net",                          "ASP.NET",          "Framework"),
    ("X-Powered-By",    r"express",                            "Express.js",       "Framework"),
    ("X-Powered-By",    r"next\.js",                           "Next.js",          "Framework"),
    ("X-Powered-By",    r"django",                             "Django",           "Framework"),
    ("X-Powered-By",    r"rails",                              "Ruby on Rails",    "Framework"),
    ("X-Powered-By",    r"laravel",                            "Laravel",          "Framework"),
    ("X-Generator",     r"wordpress(?:[/ ]([\d.]+))?",        "WordPress",        "CMS"),
    ("X-Generator",     r"drupal(?:[/ ]([\d.]+))?",           "Drupal",           "CMS"),
    ("X-Generator",     r"joomla(?:[/ ]([\d.]+))?",           "Joomla",           "CMS"),
    ("X-Drupal-Cache",  r".*",                                 "Drupal",           "CMS"),
    ("X-Shopify-Stage", r".*",                                 "Shopify",          "E-Commerce"),
    ("X-Wix-Request-Id",r".*",                                 "Wix",              "Website Builder"),
    ("Via",             r".*varnish.*",                        "Varnish",          "Cache"),
    ("X-Cache",         r".*",                                 "Caching Layer",    "Cache"),
    ("X-Varnish",       r".*",                                 "Varnish",          "Cache"),
    ("CF-Ray",          r".*",                                 "Cloudflare",       "CDN"),
    ("X-Amz-Cf-Id",     r".*",                                 "Amazon CloudFront","CDN"),
    ("X-Fastly-Request-ID", r".*",                             "Fastly",           "CDN"),
    ("X-Sucuri-ID",     r".*",                                 "Sucuri",           "Security / WAF"),
    ("X-Mod-Pagespeed", r"([\d.]+)?",                          "PageSpeed",        "Performance"),
    ("Strict-Transport-Security", r".*",                       "HSTS",             "Security Header"),
    ("Content-Security-Policy",   r".*",                       "CSP",              "Security Header"),
    ("X-Frame-Options",           r".*",                       "X-Frame-Options",  "Security Header"),
    ("X-Content-Type-Options",    r".*",                       "X-Content-Type-Options", "Security Header"),
    ("Referrer-Policy",           r".*",                       "Referrer-Policy",  "Security Header"),
    ("Permissions-Policy",        r".*",                       "Permissions-Policy","Security Header"),
]

COOKIE_FINGERPRINTS = [
    (r"wordpress_logged_in|wordpress_sec|wp-settings", "WordPress",  "CMS"),
    (r"PHPSESSID",                                      "PHP",        "Programming Language"),
    (r"ASP\.NET_SessionId|\.ASPXAUTH",                  "ASP.NET",    "Framework"),
    (r"laravel_session",                                 "Laravel",    "Framework"),
    (r"csrftoken|sessionid",                             "Django",     "Framework"),
    (r"_rails|_session",                                 "Ruby on Rails","Framework"),
    (r"shopify_session|_secure_session",                 "Shopify",    "E-Commerce"),
    (r"magento",                                          "Magento",    "E-Commerce"),
    (r"PrestaShop",                                       "PrestaShop", "E-Commerce"),
    (r"JSESSIONID",                                       "Java EE",    "Framework"),
    (r"connect\.sid",                                     "Express.js", "Framework"),
    (r"__cf_bm|cf_clearance",                             "Cloudflare", "CDN"),
]


def _match(pattern: str, value: str):
    m = re.search(pattern, value, re.IGNORECASE)
    return m


def _parse_cookies(headers: dict) -> str:
    return " ".join([
        v for k, v in headers.items()
        if k.lower() in ("set-cookie", "cookie")
    ])


class HeaderScanner:
    def run(self, domain: str) -> dict:
        url = domain if domain.startswith("http") else f"https://{domain}"
        logger.info(f"Fetching headers: {url}")

        page = fetch(url)
        headers = {k.lower(): v for k, v in page.get("headers", {}).items()}

        if not headers:
            return {"error": f"No headers received from {url}"}

        raw_headers = page.get("headers", {})
        findings = {}

        for header_name, pattern, tech_name, category in FINGERPRINTS:
            value = headers.get(header_name.lower(), "")
            if not value:
                continue
            m = _match(pattern, value)
            if m:
                version = ""
                if m.lastindex and m.lastindex >= 1:
                    version = m.group(1) or ""
                key = tech_name
                if key not in findings:
                    findings[key] = {
                        "name": tech_name,
                        "version": version,
                        "category": category,
                        "detected_via": header_name,
                        "raw_value": value.strip(),
                    }

        cookie_str = _parse_cookies(raw_headers)
        if cookie_str:
            for pattern, tech_name, category in COOKIE_FINGERPRINTS:
                if tech_name in findings:
                    continue
                m = _match(pattern, cookie_str)
                if m:
                    findings[tech_name] = {
                        "name": tech_name,
                        "version": "",
                        "category": category,
                        "detected_via": "Set-Cookie",
                        "raw_value": "",
                    }

        results = sorted(findings.values(), key=lambda x: x["name"].lower())
        logger.info(f"Header scanner found {len(results)} fingerprints on {url}")

        return {
            "headers_analyzed": len(raw_headers),
            "technologies": results,
        }