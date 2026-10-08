import subprocess
import sys
import json
from core.logger import get_logger

logger = get_logger()

SCAN_MODES = ("fast", "balanced", "full")

_RUNNER_SCRIPT = """
import sys, json

def install(pkg):
    import subprocess
    subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg, "-q", "--break-system-packages"],
        check=True, capture_output=True,
    )

try:
    import wappalyzer
except ImportError:
    install("wappalyzer")
    import wappalyzer

from wappalyzer import Wappalyzer

url  = sys.argv[1]
mode = sys.argv[2]

with Wappalyzer(scan_type=mode) as scanner:
    raw = scanner.analyze(url)

techs_by_url = raw.get(url) or next(iter(raw.values()), {})

technologies = []
for tech_name, info in techs_by_url.items():
    technologies.append({
        "name":       tech_name,
        "version":    info.get("version", ""),
        "confidence": info.get("confidence", 0),
        "categories": info.get("categories", []),
    })

technologies.sort(key=lambda x: (-x["confidence"], x["name"].lower()))
print(json.dumps(technologies))
"""


class WappalyzerNext:
    def __init__(self, mode: str = "balanced") -> None:
        if mode not in SCAN_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Choose from: {SCAN_MODES}")
        self.mode = mode

    def run(self, domain: str) -> dict:
        url = domain if domain.startswith("http") else f"https://{domain}"

        logger.info(f"Starting wappalyzer-next scan [{self.mode}] on: {url}")

        result = subprocess.run(
            [sys.executable, "-c", _RUNNER_SCRIPT, url, self.mode],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown error"
            logger.error(f"WappalyzerNext failed: {error_msg}")
            return {"error": error_msg}

        try:
            technologies = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            return {"error": f"Failed to parse output: {e}\nraw: {result.stdout[:200]}"}

        logger.info(
            f"WappalyzerNext [{self.mode}] detected {len(technologies)} technologies on {url}"
        )

        return {
            "scan_mode": self.mode,
            "technologies": technologies,
        }