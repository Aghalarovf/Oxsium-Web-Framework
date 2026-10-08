import os
import logging
import socket
import threading

from config import (
    API_PORT, GUI_PORT,
    DNS_SCRIPT, SUBDOM_SCRIPT, DB_MANAGER_SCRIPT,
    TECH_SCRIPT,
    RESULTS_DIR, DB_API_BASE, MAIN_DIR,
    logger,
)
from app import app
import lifecycle

# ── Core routes ──────────────────────────────────────────────────────────────
import routes.target
import routes.reset

# ── Reconnaissance routes (ready) ────────────────────────────────────────────
import routes.dns
import routes.subdomains

# ── Reconnaissance routes (integrated) ───────────────────────────────────────
import routes.whois
import routes.headers
import routes.tls
import routes.wayback
import routes.email_infra
import routes.js_files
import routes.social
import routes.tech_fingerprint
import routes.proxy

from lifecycle import _startup_notify


if __name__ == "__main__":
    _local_ips: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
            _s.connect(("8.8.8.8", 80))
            _local_ips.append(_s.getsockname()[0])
    except Exception:
        pass

    if "127.0.0.1" not in _local_ips:
        _local_ips.insert(0, "127.0.0.1")

    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    print()
    print("  Oxsium Web Engine")
    print(f"  {'-' * 40}")
    print(f"  API  port : {API_PORT}")
    print(f"  GUI  port : {GUI_PORT}")
    print(f"  {'-' * 40}")
    for _ip in _local_ips:
        print(f"  http://{_ip}:{API_PORT}")
    print(f"  {'-' * 40}")
    print()
    print("  Paths")
    print(f"  {'-' * 40}")

    _RECON = os.path.join(MAIN_DIR, "Reconnaissance-Modules")

    _path_checks = [
        # Ready modules
        ("DNS Script",           os.path.join(_RECON, "DNS-Enumerator", "DNS-Enumeration.py"),        "file"),
        ("Subdomain Script",     SUBDOM_SCRIPT,                                     "file"),
        ("Whois Script",         os.path.join(_RECON, "Whois-Checker", "whois-checker.py"),               "file"),
        ("Headers Script",       os.path.join(_RECON, "Headers-Analyzer", "headers_analyzer.py"),                "file"),
        ("TLS Script",           os.path.join(_RECON, "Certificate-Enumerator", "certificate-enumerator.py"),              "file"),
        ("Wayback Script",       os.path.join(_RECON, "Wayback-Enumerator", "wayback.py"),        "file"),
        ("Email Infra Script",   os.path.join(_RECON, "Email-Infrastructure.py"),   "file"),
        ("JS Files Script",      os.path.join(_RECON, "JS-Files.py"),               "file"),
        ("Social Script",        os.path.join(_RECON, "Social-Metadata", "social_metadata.py"),        "file"),
        ("Tech Fingerprint",     TECH_SCRIPT,                                        "file"),
        ("DB Manager",           DB_MANAGER_SCRIPT,                                 "file"),
        ("Scan Results Dir",     RESULTS_DIR,                                       "dir"),
        ("DB API",               DB_API_BASE,                                       "url"),
    ]

    for _label, _path, _kind in _path_checks:
        if _kind == "url":
            _status = ""
        elif _kind == "dir":
            _status = "  [OK]" if os.path.isdir(_path) else "  [NOT FOUND]"
        else:
            _status = "  [OK]" if os.path.isfile(_path) else "  [NOT FOUND]"
        print(f"  {_label:<22}: {_path}{_status}")

    threading.Thread(target=_startup_notify, daemon=True).start()

    try:
        app.run(
            host="0.0.0.0",
            port=API_PORT,
            debug=bool(os.getenv("DEBUG")),
            use_reloader=False,
        )
    except OSError as exc:
        logger.critical("Server failed to start -- port=%s  error: %s", API_PORT, exc)
        raise