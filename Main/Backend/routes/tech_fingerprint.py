import os
import re
import json as _json
import subprocess
import threading
import uuid as _uuid

from flask import request

from app import app, limiter
from config import logger, MAIN_DIR, RESULTS_DIR, DB_FILE, VENV_PYTHON, TECH_SCRIPT
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def _run_tech_job(job_id: str, cmd: list, output_file: str) -> None:
    logger.info("job=%s  [TECH] Starting: Tech-Fingerprint.py", job_id)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
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
                    logger.debug("job=%s [tech] %s", job_id, line)

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "Tech-Fingerprint.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [TECH] ERROR: timed out", job_id)
            return

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        tech_stdout = _strip("\n".join(stdout_lines))[-8000:]
        tech_stderr = _strip("\n".join(stderr_lines))[-2000:]
        tech_ok     = proc.returncode == 0

        if not tech_ok:
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stdout":      tech_stdout,
                    "stderr":      tech_stderr,
                    "returncode":  proc.returncode,
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [TECH] ERROR: returncode=%d", job_id, proc.returncode)
            return

        tech_results = None
        try:
            with open(output_file, encoding="utf-8") as f:
                tech_results = _json.load(f)
        except Exception as exc:
            logger.warning("job=%s  Tech JSON unreadable: %s", job_id, exc)

        tech_db_ready = False
        if tech_results:
            logger.info("job=%s  [TECH] JSON -> database-manager.py -> DB", job_id)
            tech_db_ready = _write_to_db_and_reload(job_id, output_file, "tech_fingerprint")

        if not tech_db_ready:
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stdout":      tech_stdout,
                    "stderr":      tech_stderr,
                    "returncode":  proc.returncode,
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [TECH] ERROR: database-manager.py failed", job_id)
            return

    except Exception as exc:
        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "error",
                "stderr":      str(exc),
                "finished_at": _now_iso(),
                "db_ready":    False,
            })
        logger.error("job=%s  [TECH] EXCEPTION: %s", job_id, exc)
        return

    logger.info("job=%s  [TECH] DONE: results in DB", job_id)
    with _jobs_lock:
        _jobs[job_id].update({
            "status":      "done",
            "stdout":      tech_stdout,
            "stderr":      tech_stderr,
            "returncode":  proc.returncode,
            "output_file": output_file,
            "finished_at": _now_iso(),
            "db_ready":    True,
            "db_file":     DB_FILE,
        })


@app.route("/api/tech/scan", methods=["POST"])
@limiter.limit("10 per minute")
def tech_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]
    proxy  = str(data.get("proxy") or target.get("proxy") or "").strip() or None

    if not os.path.isfile(TECH_SCRIPT):
        return _err(f"Tech-Fingerprint.py not found: {TECH_SCRIPT}", 500)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(RESULTS_DIR, "tech_fingerprint.json")

    cmd = [VENV_PYTHON, TECH_SCRIPT, "-d", domain, "-o", output_file, "--all", "--quiet"]

    if proxy:
        cmd += ["--proxy", proxy]

    job_id = _uuid.uuid4().hex[:12]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "tech_fingerprint",
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

    logger.info("tech/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_tech_job, args=(job_id, cmd, output_file), daemon=True)
    t.start()

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    " ".join(cmd),
        "status": "running",
    })


@app.route("/api/tech/job/<job_id>", methods=["GET"])
def tech_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})