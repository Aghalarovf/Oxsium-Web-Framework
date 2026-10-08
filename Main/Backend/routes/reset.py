import os
import shutil

from app import app, limiter
from config import logger, RESULTS_DIR
from helpers import _ok, _err

_PRESERVED_FILES = frozenset({"burp_traffic.json"})


@app.route("/api/reset", methods=["POST"])
@limiter.limit("30 per minute")
def reset_scan_results():
    """
    Clears Scan-Results while preserving the hardcoded Burp traffic file.
    """
    if not os.path.isdir(RESULTS_DIR):
        logger.info("[RESET] Scan-Results directory does not exist, skipping.")
        return _ok({"removed": 0, "message": "Scan-Results directory did not exist"})

    removed = 0
    errors  = []

    for entry in os.scandir(RESULTS_DIR):
        if entry.name in _PRESERVED_FILES:
            continue
        try:
            if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                os.remove(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path)
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