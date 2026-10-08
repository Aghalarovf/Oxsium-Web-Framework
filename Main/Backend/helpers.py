import os
import re
import json as _json
import subprocess
import threading
import urllib.request as _ureq
from datetime import datetime, timezone

from flask import jsonify

from config import logger, DB_FILE, DB_MANAGER_SCRIPT, DB_API_BASE, VENV_PYTHON

_state_lock = threading.Lock()
_target: dict = {}

_jobs: dict = {}
_jobs_lock = threading.Lock()

_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_url(v: str) -> bool:
    return bool(_URL_RE.match(v.strip()))


def _strip_scheme(url: str) -> str:
    return re.sub(r"^https?://", "", url.strip()).split("/")[0].split(":")[0]


def _ok(data: dict, code: int = 200):
    return jsonify({"success": True, **data}), code


def _err(msg: str, code: int = 400):
    return jsonify({"success": False, "error": msg, "code": code}), code


def _require_target() -> tuple[dict | None, object | None]:
    with _state_lock:
        t = dict(_target) if _target else None
    if not t:
        return None, _err("No target set. Call /api/target/set first.", 400)
    return t, None


def _write_to_db_and_reload(job_id: str, json_file: str, label: str) -> bool:
    win_flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

    if not os.path.isfile(DB_MANAGER_SCRIPT):
        logger.warning("job=%s [%s]  database-manager.py not found: %s", job_id, label, DB_MANAGER_SCRIPT)
        return False

    try:
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        db_proc = subprocess.run(
            [VENV_PYTHON, DB_MANAGER_SCRIPT, json_file, "-o", DB_FILE, "--quiet"],
            capture_output=True, text=True, encoding="utf-8",
            timeout=120, **win_flags,
        )
        if db_proc.returncode != 0:
            logger.warning("job=%s [%s]  manager error: %s", job_id, label, db_proc.stderr.strip()[-500:])
            return False
        logger.info("job=%s [%s]  DB updated: %s", job_id, label, DB_FILE)
    except subprocess.TimeoutExpired:
        logger.error("job=%s [%s]  database-manager timed out", job_id, label)
        return False
    except Exception as exc:
        logger.error("job=%s [%s]  database-manager exception: %s", job_id, label, exc)
        return False

    try:
        body = _json.dumps({"job_id": job_id, "phase": label}).encode()
        req = _ureq.Request(
            f"{DB_API_BASE}/api/reload", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        _ureq.urlopen(req, timeout=5)
        logger.info("job=%s [%s]  DB API reload triggered", job_id, label)
    except Exception as exc:
        logger.warning("job=%s [%s]  DB API reload failed: %s", job_id, label, exc)

    return True