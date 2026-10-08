import sys
import os
from core.logger import get_logger

logger = get_logger()

CMSEEK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "CMSeeK")


def _ensure_cmseek():
    if not os.path.isdir(CMSEEK_DIR):
        logger.info("Cloning CMSeeK repository...")
        import subprocess
        subprocess.run(
            ["git", "clone", "https://github.com/Tuhinshubhra/CMSeeK", CMSEEK_DIR, "-q"],
            check=True
        )
    if CMSEEK_DIR not in sys.path:
        sys.path.insert(0, CMSEEK_DIR)


def _load_cmseek_modules():
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context

    import cmseekdb.basic as cmseek
    import cmseekdb.cmss as cmsdb
    import cmseekdb.header as header_det
    import cmseekdb.generator as generator
    import cmseekdb.robots as robots_det

    cmseek.batch_mode = True
    cmseek.redirect_conf = "1"
    cmseek.verbose = False

    return cmseek, cmsdb, header_det, generator, robots_det


def _get_cms_info(cms_id: str, cmsdb) -> dict:
    try:
        info = getattr(cmsdb, cms_id)
        return {"name": info.get("name", cms_id), "url": info.get("url", "")}
    except AttributeError:
        return {"name": cms_id, "url": ""}


class CMSeeK:
    def run(self, domain: str) -> dict:
        _ensure_cmseek()

        try:
            cmseek, cmsdb, header_det, generator, robots_det = _load_cmseek_modules()
        except Exception as e:
            return {"error": f"Failed to load CMSeeK modules: {e}"}

        url = domain if domain.startswith("http") else f"https://{domain}"
        logger.info(f"Running CMSeeK on: {url}")

        ua = "Mozilla/5.0 (compatible; recon-tool/1.0)"

        try:
            raw = cmseek.getsource(url, ua)
        except Exception as e:
            return {"error": f"Failed to fetch target: {e}"}

        if raw[0] != "1":
            return {"error": f"Could not connect to target: {raw[1]}"}

        scode = raw[1]
        headers_str = raw[2]

        cms_id = None
        detection_method = None

        logger.info("Stage 1/4 — Header detection")
        h_result = header_det.check(headers_str)
        if h_result[0] == "1":
            cms_id = h_result[1]
            detection_method = "header"

        if not cms_id:
            logger.info("Stage 2/4 — Generator meta tag")
            gen_parsed = generator.parse(scode)
            if gen_parsed[0] == "1":
                gen_result = generator.scan(gen_parsed[1])
                if gen_result[0] == "1":
                    cms_id = gen_result[1]
                    detection_method = "generator"

        if not cms_id:
            logger.info("Stage 3/4 — Source code patterns")
            try:
                import cmseekdb.sc as source_det
                src_result = source_det.check(scode, url)
                if src_result[0] == "1":
                    cms_id = src_result[1]
                    detection_method = "source"
            except Exception as e:
                logger.warning(f"Source detection skipped: {e}")

        if not cms_id:
            logger.info("Stage 4/4 — robots.txt")
            try:
                robots_result = robots_det.check(url, ua)
                if robots_result[0] == "1":
                    cms_id = robots_result[1]
                    detection_method = "robots"
            except Exception as e:
                logger.warning(f"Robots detection skipped: {e}")

        if not cms_id:
            logger.info("No CMS detected by CMSeeK")
            return {
                "cms_detected": False,
                "cms_id": None,
                "cms_name": None,
                "cms_url": None,
                "cms_version": None,
                "detection_method": None,
            }

        cms_info = _get_cms_info(cms_id, cmsdb)
        logger.info(f"CMS detected: {cms_info['name']} via {detection_method}")

        version = None
        try:
            import VersionDetect.detect as version_detect
            version = version_detect.start(cms_id, url, ua, "0", scode, "", headers_str)
            if version in ("0", None, ""):
                version = None
        except Exception as e:
            logger.warning(f"Version detection skipped: {e}")

        return {
            "cms_detected": True,
            "cms_id": cms_id,
            "cms_name": cms_info["name"],
            "cms_url": cms_info["url"],
            "cms_version": version,
            "detection_method": detection_method,
        }