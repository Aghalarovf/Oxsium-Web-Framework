import os
import re
import json as _json
import subprocess
import threading
import uuid as _uuid

from flask import request

from app import app, limiter
from config import logger, MAIN_DIR, RESULTS_DIR, DB_FILE, VENV_PYTHON, WHOIS_CHECKER_SCRIPT
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}

# whois-checker.py --json writes to this path (relative to project root)
_WHOIS_JSON = os.path.join(RESULTS_DIR, "whois_results.json")


def _run_whois_job(job_id: str, cmd: list) -> None:
    logger.info("job=%s  [WHOIS] Starting: whois-checker.py", job_id)
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
                    logger.debug("job=%s [whois] %s", job_id, line)

        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_err.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "whois-checker.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [WHOIS] ERROR: timed out", job_id)
            return

        t_err.join(timeout=5)

        ok     = proc.returncode == 0
        stderr = _strip("\n".join(stderr_lines))[-2000:]

        if not ok:
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "returncode":  proc.returncode,
                    "stderr":      stderr,
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [WHOIS] ERROR (rc=%d)", job_id, proc.returncode)
            return

        logger.info("job=%s  [WHOIS] DONE — writing to DB…", job_id)

        # ── Write JSON → SQLite and reload DB API ──────────────────────
        db_ok = False
        if os.path.isfile(_WHOIS_JSON):
            db_ok = _write_to_db_and_reload(job_id, _WHOIS_JSON, "whois")
        else:
            logger.warning("job=%s  [WHOIS] JSON not found: %s", job_id, _WHOIS_JSON)

        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "done",
                "returncode":  proc.returncode,
                "stderr":      stderr,
                "finished_at": _now_iso(),
                "db_ready":    db_ok,
            })

    except Exception as exc:
        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "error",
                "stderr":      str(exc),
                "finished_at": _now_iso(),
                "db_ready":    False,
            })
        logger.error("job=%s  [WHOIS] EXCEPTION: %s", job_id, exc)


@app.route("/api/whois/scan", methods=["POST"])
@limiter.limit("10 per minute")
def whois_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]
    proxy  = str(data.get("proxy") or target.get("proxy") or "").strip() or None

    if not os.path.isfile(WHOIS_CHECKER_SCRIPT):
        return _err(f"whois-checker.py not found: {WHOIS_CHECKER_SCRIPT}", 500)

    job_id = _uuid.uuid4().hex[:12]
    cmd    = [VENV_PYTHON, WHOIS_CHECKER_SCRIPT, "-d", domain, "--json"]
    if proxy:
        cmd += ["--proxy", proxy]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "whois",
            "domain":       domain,
            "cmd":          " ".join(cmd),
            "stderr":       "",
            "returncode":   None,
            "modules_done": [],
            "started_at":   _now_iso(),
            "finished_at":  None,
            "db_ready":     False,
        }

    logger.info("whois/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_whois_job, args=(job_id, cmd), daemon=True)
    t.start()

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    " ".join(cmd),
        "status": "running",
    })


@app.route("/api/whois/job/<job_id>", methods=["GET"])
def whois_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})