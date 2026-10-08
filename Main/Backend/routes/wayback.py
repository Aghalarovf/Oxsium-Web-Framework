import os
import re
import json as _json
import subprocess
import threading
import uuid as _uuid

from flask import request

from app import app, limiter
from config import logger, MAIN_DIR, RESULTS_DIR, DB_FILE, VENV_PYTHON, WAYBACK_SCRIPT, WAYBACK_DIR
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def _run_wayback_job(job_id: str, cmd: list, output_file: str) -> None:
    logger.info("job=%s  [WAYBACK] Starting: wayback.py", job_id)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            cwd=WAYBACK_DIR,
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
            **_FLAGS,
        )

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        def _read_stdout():
            for raw in proc.stdout:
                line = raw.rstrip()
                if line:
                    stdout_lines.append(line)

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
                    logger.warning("job=%s [wayback] %s", job_id, line)

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "wayback.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [WAYBACK] ERROR: timed out", job_id)
            return

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        ok     = proc.returncode == 0
        stdout = _strip("\n".join(stdout_lines))[-4000:]
        stderr = _strip("\n".join(stderr_lines))[-2000:]

        if not ok:
            logger.error("job=%s  [WAYBACK] ERROR: returncode=%d\nstderr: %s", job_id, proc.returncode, stderr)
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stdout":      stdout,
                    "stderr":      stderr,
                    "returncode":  proc.returncode,
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            return

        db_ready = False
        if os.path.isfile(output_file):
            try:
                db_ready = _write_to_db_and_reload(job_id, output_file, "wayback")
            except Exception as exc:
                logger.error("job=%s  [WAYBACK] DB error: %s", job_id, exc)
                stderr = f"DB write error: {exc}\n" + stderr

        status = "done" if db_ready else "error"
        logger.info("job=%s  [WAYBACK] %s", job_id, status.upper())

        with _jobs_lock:
            _jobs[job_id].update({
                "status":      status,
                "stdout":      stdout,
                "stderr":      stderr,
                "returncode":  proc.returncode,
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
        logger.error("job=%s  [WAYBACK] EXCEPTION: %s", job_id, exc)


@app.route("/api/wayback/scan", methods=["POST"])
@limiter.limit("10 per minute")
def wayback_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]

    if not os.path.isfile(WAYBACK_SCRIPT):
        return _err(f"wayback.py not found: {WAYBACK_SCRIPT}", 500)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(RESULTS_DIR, "wayback_archive.json")

    cmd = [
        VENV_PYTHON, WAYBACK_SCRIPT,
        "-d", domain,
        "--all",
        "-o", output_file,
        "--format", "json",
    ]

    job_id = _uuid.uuid4().hex[:12]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "wayback",
            "domain":       domain,
            "cmd":          " ".join(cmd),
            "output_file":  output_file,
            "stdout":       "",
            "stderr":       "",
            "returncode":   None,
            "modules_done": [],
            "started_at":   _now_iso(),
            "finished_at":  None,
            "db_ready":     False,
            "db_file":      None,
        }

    logger.info("wayback/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_wayback_job, args=(job_id, cmd, output_file), daemon=True)
    t.start()

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    " ".join(cmd),
        "status": "running",
    })


@app.route("/api/wayback/job/<job_id>", methods=["GET"])
def wayback_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})