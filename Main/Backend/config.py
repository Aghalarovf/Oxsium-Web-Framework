import os
import sys
import argparse
import logging

_parser = argparse.ArgumentParser(
    prog="api.py",
    description="Oxsium Web — API backend",
)
_parser.add_argument(
    "--port",
    type=int,
    default=int(os.getenv("PORT", 30300)),
    help="Port the API server listens on (default: 30300)",
)
_parser.add_argument(
    "--web",
    type=int,
    default=int(os.getenv("WEB_PORT", 30305)),
    help="Port of the GUI the backend notifies on start/stop (default: 30305)",
)
_args, _ = _parser.parse_known_args()

API_PORT = _args.port
GUI_PORT = _args.web

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("oxsium.web")

SCRIPT_DIR        = os.path.dirname(os.path.abspath(__file__))
MAIN_DIR          = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT      = os.path.dirname(MAIN_DIR)
DB_DIR            = os.path.join(MAIN_DIR, "SQLite-Engine")
DNS_SCRIPT          = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "DNS-Enumerator", "DNS-Enumeration.py")
TECH_SCRIPT         = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Tech-Fingerprint", "tech_fingerprint.py")
WAYBACK_SCRIPT      = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Wayback-Enumerator", "wayback.py")
WAYBACK_DIR         = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Wayback-Enumerator")
WHOIS_CHECKER_SCRIPT = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Whois-Checker", "whois-checker.py")
SUBDOM_SCRIPT     = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Subdomain-Hunter", "subdomain-hunter.py")
HEADERS_SCRIPT    = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Headers-Analyzer", "headers_analyzer.py")
RESULTS_DIR       = os.path.join(MAIN_DIR, "Scan-Results")
DB_FILE           = os.path.join(RESULTS_DIR, "scan_results.db")
DB_MANAGER_SCRIPT = os.path.join(DB_DIR, "database-manager.py")
DB_API_BASE       = os.getenv("DB_API_BASE", "http://127.0.0.1:30301")
SUBDOMAIN_API_KEYS = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Subdomain-Hunter", "api_keys.json")


def _venv_python() -> str:
    candidates = [
        os.path.join(PROJECT_ROOT, "oxsium-web", "Scripts", "python.exe"),
        os.path.join(PROJECT_ROOT, "oxsium-web", "bin", "python"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            logger.info("oxsium-web venv Python: %s", path)
            return path

    logger.warning(
        "oxsium-web venv not found under %s — falling back to sys.executable (%s). "
        "Run the installer first to create the venv.",
        PROJECT_ROOT, sys.executable,
    )
    return sys.executable


VENV_PYTHON: str = _venv_python()