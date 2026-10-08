import os
import re
import json as _json
import subprocess
import threading
import uuid as _uuid

from flask import request

from app import app, limiter
from config import logger, MAIN_DIR, RESULTS_DIR, DB_FILE, VENV_PYTHON
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

JS_FILES_SCRIPT = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "JS-Files.py")


def _run_js_files_job(job_id: str, cmd: list, output_file: str) -> None:
    logger.info("job=%s  [JS-FILES] Starting: JS-Files.py", job_id)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
                    logger.debug("job=%s [js-files] %s", job_id, line)

        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_err.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "JS-Files.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [JS-FILES] ERROR: timed out", job_id)
            return

        t_err.join(timeout=5)

        ok     = proc.returncode == 0
        stderr = _strip("\n".join(stderr_lines))[-2000:]

        db_ready = False
        if ok and os.path.isfile(output_file):
            try:
                db_ready = _write_to_db_and_reload(job_id, output_file, "js_files")
            except Exception as exc:
                logger.error("job=%s  [JS-FILES] DB error: %s", job_id, exc)
                stderr = f"DB write error: {exc}\n" + stderr

        status = "done" if (ok and db_ready) else "error"
        logger.info("job=%s  [JS-FILES] %s", job_id, status.upper())

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
        logger.error("job=%s  [JS-FILES] EXCEPTION: %s", job_id, exc)


@app.route("/api/js-files/scan", methods=["POST"])
@limiter.limit("10 per minute")
def js_files_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]

    if not os.path.isfile(JS_FILES_SCRIPT):
        return _err(f"JS-Files.py not found: {JS_FILES_SCRIPT}", 500)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(RESULTS_DIR, "js_files.json")

    cmd = [VENV_PYTHON, JS_FILES_SCRIPT, "-t", domain, "-o", output_file, "--json", "-q"]

    job_id = _uuid.uuid4().hex[:12]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "js_files",
            "domain":       domain,
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

    logger.info("js-files/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_js_files_job, args=(job_id, cmd, output_file), daemon=True)
    t.start()

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    " ".join(cmd),
        "status": "running",
    })


@app.route("/api/js-files/job/<job_id>", methods=["GET"])
def js_files_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})