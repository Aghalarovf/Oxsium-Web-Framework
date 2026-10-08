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

EMAIL_SCRIPT = os.path.join(MAIN_DIR, "Reconnaissance-Modules", "Email-Infrastructure", "email_infra.py")


_OPTION_FLAGS = (
    ("mail_dns_security",  "--ds",       True),
    ("service_scanner",    "--sc",       True),
    ("exchange_endpoints", "--exchange", True),
    ("ntlm",               "--ntlm",     False),
)


def _as_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _run_email_job(job_id: str, cmd: list, output_file: str) -> None:
    logger.info("job=%s  [EMAIL] Starting: Email-Infrastructure.py", job_id)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
                    logger.debug("job=%s [email] %s", job_id, line)

        def _read_stdout():
            for raw in proc.stdout:
                line = raw.rstrip()
                if not line:
                    continue
                stderr_lines.append(f"[stdout] {line}")
                logger.debug("job=%s [email/stdout] %s", job_id, line)

        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err.start()
        t_out.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "Email-Infrastructure.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [EMAIL] ERROR: timed out", job_id)
            return

        t_err.join(timeout=5)
        t_out.join(timeout=5)

        ok     = proc.returncode == 0
        stderr = _strip("\n".join(stderr_lines))[-2000:]

        db_ready = False
        if ok and os.path.isfile(output_file):
            try:
                db_ready = _write_to_db_and_reload(job_id, output_file, "email_infra")
            except Exception as exc:
                logger.error("job=%s  [EMAIL] DB error: %s", job_id, exc)
                stderr = f"DB write error: {exc}\n" + stderr

        status = "done" if (ok and db_ready) else "error"
        logger.info("job=%s  [EMAIL] %s", job_id, status.upper())

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
        logger.error("job=%s  [EMAIL] EXCEPTION: %s", job_id, exc)


@app.route("/api/email/scan", methods=["POST"])
@limiter.limit("10 per minute")
def email_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]

    if not os.path.isfile(EMAIL_SCRIPT):
        return _err(f"Email-Infrastructure.py not found: {EMAIL_SCRIPT}", 500)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file = os.path.join(RESULTS_DIR, "email_infra.json")

    cmd = [VENV_PYTHON, EMAIL_SCRIPT, "-d", domain, "--json", "--pg", "--breaches", "--hr", "--hs"]

    for key, flag, default in _OPTION_FLAGS:
        if _as_bool(data.get(key), default):
            cmd.append(flag)

    job_id = _uuid.uuid4().hex[:12]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "email_infra",
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

    logger.info("email/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_email_job, args=(job_id, cmd, output_file), daemon=True)
    t.start()

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    " ".join(cmd),
        "status": "running",
    })


@app.route("/api/email/job/<job_id>", methods=["GET"])
def email_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})