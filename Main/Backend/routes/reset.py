import os

from app import app, limiter
from config import logger, RESULTS_DIR
from helpers import _ok, _err

_FRAMEWORK_RESULT_FILES = frozenset({
    "dns_enum.json",
    "email_infra.json",
    "headers.json",
    "js_files.json",
    "scan_results.db",
    "scan_results.db-shm",
    "scan_results.db-wal",
    "social_metadata_results.json",
    "subdomains_enum.json",
    "tech_fingerprint.json",
    "tls_certs.json",
    "wayback_archive.json",
    "whois_results.json",
})


@app.route("/api/reset", methods=["POST"])
@limiter.limit("30 per minute")
def reset_scan_results():
    """
    Clears framework-generated scan results while preserving user files.
    """
    if not os.path.isdir(RESULTS_DIR):
        logger.info("[RESET] Scan-Results directory does not exist, skipping.")
        return _ok({"removed": 0, "message": "Scan-Results directory did not exist"})

    removed = 0
    errors  = []

    for entry in os.scandir(RESULTS_DIR):
        if entry.name not in _FRAMEWORK_RESULT_FILES:
            continue
        try:
            if entry.is_file(follow_symlinks=False):
                os.remove(entry.path)
            removed += 1
        except Exception as exc:
            msg = f"{entry.name}: {exc}"
            errors.append(msg)
            logger.warning("[RESET] Could not delete — %s", msg)

    logger.info("[RESET] Scan-Results cleared: %d item(s) removed", removed)

    if errors:
        return _ok({
            "removed": removed,
            "errors":  errors,
            "message": f"{removed} item(s) removed, {len(errors)} failed",
        })

    return _ok({
        "removed": removed,
        "message": f"Scan-Results cleared: {removed} item(s) removed",
    })