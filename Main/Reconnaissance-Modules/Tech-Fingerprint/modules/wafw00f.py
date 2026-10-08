from core.logger import get_logger

logger = get_logger()


def _ensure_wafw00f():
    try:
        from wafw00f.main import WAFW00F
        return WAFW00F
    except ImportError:
        import subprocess
        import sys
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "wafw00f", "-q", "--break-system-packages"],
            capture_output=True
        )
        from wafw00f.main import WAFW00F
        return WAFW00F


class WafW00f:
    def run(self, domain: str) -> dict:
        WAFW00F = _ensure_wafw00f()

        url = domain if domain.startswith("http") else f"https://{domain}"
        logger.info(f"Running WAF detection on: {url}")

        try:
            waf = WAFW00F(url, debuglevel=0)

            detected, _ = waf.identwaf(findall=True)

            if detected:
                logger.info(f"Identified WAF(s): {detected}")
                return {
                    "waf_detected": True,
                    "waf_names": detected,
                    "generic_detected": waf.knowledge["generic"]["found"],
                    "generic_reason": waf.knowledge["generic"]["reason"] or None,
                }

            generic_found = waf.genericdetect()
            if generic_found:
                logger.info("Generic WAF/security layer detected")
                return {
                    "waf_detected": True,
                    "waf_names": [],
                    "generic_detected": True,
                    "generic_reason": waf.knowledge["generic"]["reason"] or None,
                }

            logger.info("No WAF detected")
            return {
                "waf_detected": False,
                "waf_names": [],
                "generic_detected": False,
                "generic_reason": None,
            }

        except Exception as e:
            logger.error(f"WAF detection failed: {e}")
            return {"error": str(e)}