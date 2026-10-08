import os
import re
import json as _json
import subprocess
import threading
import uuid as _uuid
from typing import Optional

from flask import request

from app import app, limiter
from config import logger, MAIN_DIR, RESULTS_DIR, DB_FILE, VENV_PYTHON
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

SOCIAL_SCRIPT = os.path.join(
    MAIN_DIR, "Reconnaissance-Modules", "Social-Metadata", "social_metadata.py"
)

_INTERCEPT_EXTS      = (".json", ".jsonl")
_INTERCEPT_MAX_BYTES = 200 * 1024 * 1024


def _resolve_intercept(data: dict, job_id: str):
    raw     = (data.get("intercept_log") or "").strip().strip('"')
    content = data.get("intercept_log_content")

    if not raw:
        return None, False, None

    if not raw.lower().endswith(_INTERCEPT_EXTS):
        return None, False, _err("intercept_log must be a .json or .jsonl file", 400)

    if content is not None:
        if not isinstance(content, str) or len(content.encode("utf-8")) > _INTERCEPT_MAX_BYTES:
            return None, False, _err("intercept_log_content is invalid or too large", 400)
        os.makedirs(RESULTS_DIR, exist_ok=True)
        path = os.path.join(RESULTS_DIR, f"intercept_{job_id}{os.path.splitext(raw)[1].lower()}")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        return path, True, None

    if os.path.isabs(raw):
        candidates = [raw]
    else:
        candidates = [
            os.path.abspath(raw),
            os.path.join(RESULTS_DIR, raw),
            os.path.join(os.path.dirname(SOCIAL_SCRIPT), raw),
        ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate), False, None

    return None, False, _err(f"Intercept log not found: {raw}", 400)


def _remove_temp_file(job_id: str, path: Optional[str]) -> None:
    if not path:
        return
    try:
        os.remove(path)
        logger.info("job=%s  [SOCIAL] Removed temporary intercept file: %s", job_id, path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("job=%s  [SOCIAL] Could not remove temporary intercept file %s: %s", job_id, path, exc)


def _run_social_job(job_id: str, cmd: list, output_file: str, temp_file: Optional[str] = None) -> None:
    logger.info("job=%s  [SOCIAL] Starting: social_metadata.py", job_id)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            **_FLAGS,
        )

        stderr_lines: list[str] = []

        def _read_stderr():
            for raw in proc.stderr:
                line = raw.rstrip()
                if not line:
                    continue
                stderr_lines.append(line)
                try:
                    msg = _json.loads(line)
                    if msg.get("event") == "module_done":
                        module = msg.get("module", "unknown")
                        with _jobs_lock:
                            _jobs[job_id].setdefault("modules_done", [])
                            if module not in _jobs[job_id]["modules_done"]:
                                _jobs[job_id]["modules_done"].append(module)
                        logger.info("job=%s  module_done=%s", job_id, module)
                except (_json.JSONDecodeError, KeyError):
                    logger.debug("job=%s [social] %s", job_id, line)

        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_err.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "social_metadata.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [SOCIAL] ERROR: timed out", job_id)
            return

        t_err.join(timeout=5)

        ok     = proc.returncode == 0
        stderr = _strip("\n".join(stderr_lines))[-200000:]

        db_ready = False
        if ok and os.path.isfile(output_file):
            try:
                db_ready = _write_to_db_and_reload(job_id, output_file, "social")
            except Exception as exc:
                logger.error("job=%s  [SOCIAL] DB error: %s", job_id, exc)
                stderr = f"DB write error: {exc}\n" + stderr

        status = "done" if (ok and db_ready) else "error"
        logger.info("job=%s  [SOCIAL] %s", job_id, status.upper())

        with _jobs_lock:
            _jobs[job_id].update({
                "status":      status,
                "returncode":  proc.returncode,
                "stderr":      stderr,
                "output_file": output_file if db_ready else None,
                "finished_at": _now_iso(),
                "db_ready":    db_ready,
                "db_file":     DB_FILE if db_ready else None,
            })

    except Exception as exc:
        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "error",
                "stderr":      str(exc),
                "finished_at": _now_iso(),
                "db_ready":    False,
            })
        logger.error("job=%s  [SOCIAL] EXCEPTION: %s", job_id, exc)
    finally:
        _remove_temp_file(job_id, temp_file)


@app.route("/api/social/scan", methods=["POST"])
@limiter.limit("10 per minute")
def social_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]

    if not os.path.isfile(SOCIAL_SCRIPT):
        return _err(f"social_metadata.py not found: {SOCIAL_SCRIPT}", 500)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(RESULTS_DIR, "social_metadata_results.json")

    job_id = _uuid.uuid4().hex[:12]

    intercept_path, intercept_is_temp, intercept_err = _resolve_intercept(data, job_id)
    if intercept_err:
        return intercept_err

    cmd = [VENV_PYTHON, SOCIAL_SCRIPT]
    if intercept_path:
        cmd += ["--intercept", intercept_path]
    cmd += ["--json", "--all", "-d", domain]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "social",
            "domain":       domain,
            "intercept":    intercept_path,
            "cmd":          " ".join(cmd),
            "output_file":  output_file,
            "stderr":       "",
            "returncode":   None,
            "modules_done": [],
            "started_at":   _now_iso(),
            "finished_at":  None,
            "db_ready":     False,
            "db_file":      None,
        }

    logger.info("social/scan job=%s -> %s", job_id, " ".join(cmd))

    temp_file = intercept_path if intercept_is_temp else None
    t = threading.Thread(target=_run_social_job, args=(job_id, cmd, output_file, temp_file), daemon=True)
    t.start()

    return _ok({
        "job_id":    job_id,
        "domain":    domain,
        "intercept": intercept_path,
        "cmd":       " ".join(cmd),
        "status":    "running",
    })


@app.route("/api/social/job/<job_id>", methods=["GET"])
def social_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})