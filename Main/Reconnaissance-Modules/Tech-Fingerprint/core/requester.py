import urllib.request
import urllib.error
from core.logger import get_logger

logger = get_logger()


def fetch(url: str, timeout: int = 10) -> dict:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; recon-tool/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                "url": url,
                "status": response.status,
                "headers": dict(response.headers),
                "body": response.read().decode("utf-8", errors="ignore")
            }
    except urllib.error.HTTPError as e:
        logger.warning(f"HTTP error {e.code} for {url}")
        return {"url": url, "status": e.code, "headers": {}, "body": ""}
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return {"url": url, "status": None, "headers": {}, "body": ""}