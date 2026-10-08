import os
import re
import json as _json
import subprocess
import threading
import uuid as _uuid

from flask import request

from app import app, limiter
from config import logger, DNS_SCRIPT, RESULTS_DIR, DB_FILE, VENV_PYTHON, MAIN_DIR
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def _run_dns_job(job_id: str, cmd: list, output_file: str) -> None:
    logger.info("job=%s  [DNS] Starting: DNS-Enumeration.py", job_id)
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
                    pass

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start(); t_err.start()

        try:
            proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "DNS scan timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [DNS] ERROR: timed out", job_id)
            return

        t_out.join(timeout=5); t_err.join(timeout=5)

        dns_stdout = _strip("\n".join(stdout_lines))[-8000:]
        dns_stderr = _strip("\n".join(stderr_lines))[-2000:]
        dns_ok     = proc.returncode == 0

        dns_results = None
        try:
            with open(output_file, encoding="utf-8") as f:
                dns_results = _json.load(f)
        except Exception as exc:
            logger.warning("job=%s  DNS JSON unreadable: %s", job_id, exc)

        if not dns_ok:
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stdout":      dns_stdout,
                    "stderr":      dns_stderr,
                    "returncode":  proc.returncode,
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [DNS] ERROR: returncode=%d", job_id, proc.returncode)
            return

        dns_db_ready = False
        if dns_results:
            logger.info("job=%s  [DNS] JSON -> database-manager.py -> DB", job_id)
            dns_db_ready = _write_to_db_and_reload(job_id, output_file, "dns")

        if not dns_db_ready:
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stdout":      dns_stdout,
                    "stderr":      dns_stderr,
                    "returncode":  proc.returncode,
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [DNS] ERROR: database-manager.py failed", job_id)
            return

    except Exception as exc:
        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "error",
                "stderr":      str(exc),
                "finished_at": _now_iso(),
                "db_ready":    False,
            })
        logger.error("job=%s  [DNS] EXCEPTION: %s", job_id, exc)
        return

    logger.info("job=%s  [DNS] DONE: results in DB", job_id)
    with _jobs_lock:
        _jobs[job_id].update({
            "status":      "done",
            "stdout":      dns_stdout,
            "stderr":      dns_stderr,
            "returncode":  proc.returncode,
            "output_file": output_file,
            "finished_at": _now_iso(),
            "db_ready":    True,
            "db_file":     DB_FILE,
        })




@app.route("/api/dns/scan", methods=["POST"])
@limiter.limit("10 per minute")
def dns_scan():
    target, err = _require_target()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    domain     = target["host"]
    proxy      = str(data.get("proxy")      or target.get("proxy") or "").strip() or None
    nameserver = str(data.get("nameserver") or "").strip() or None
    port       = data.get("port") or target.get("port") or None
    try:
        port = int(port) if port else None
    except (ValueError, TypeError):
        port = None
    try:
        threads = max(1, min(5, int(data.get("threads") or 10)))
    except (ValueError, TypeError):
        threads = 10

    if not os.path.isfile(DNS_SCRIPT):
        return _err(f"DNS-Enumeration.py not found: {DNS_SCRIPT}", 500)

    _scan_results_dir = RESULTS_DIR or os.path.join(MAIN_DIR, "Scan-Results")
    os.makedirs(_scan_results_dir, exist_ok=True)
    output_file = os.path.join(_scan_results_dir, "dns_enum.json")

    cmd = [VENV_PYTHON, DNS_SCRIPT, "-d", domain, "-o", output_file, "--all", "--quiet"]

    if proxy:
        cmd += ["--proxy", proxy]
    if nameserver:
        cmd += ["--nameserver", nameserver]
    if port and port != 53:
        cmd += ["-p", str(port)]
    cmd += ["--threads", str(threads)]

    job_id = _uuid.uuid4().hex[:12]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "dns",
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

    logger.info("dns/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_dns_job, args=(job_id, cmd, output_file), daemon=True)
    t.start()

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    " ".join(cmd),
        "status": "running",
    })


@app.route("/api/dns/job/<job_id>", methods=["GET"])
def dns_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})