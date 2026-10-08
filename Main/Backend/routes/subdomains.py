import os
import re
import json as _json
import sqlite3
import subprocess
import threading
import uuid as _uuid
import urllib.request as _ureq

from flask import request

from app import app, limiter
from config import (
    logger, SUBDOM_SCRIPT, SUBDOMAIN_API_KEYS, RESULTS_DIR, DB_FILE,
    DB_API_BASE, VENV_PYTHON,
)
from helpers import _jobs, _jobs_lock, _ok, _err, _require_target, _now_iso, _write_to_db_and_reload

_ANSI  = re.compile(r"\x1b\[[0-9;]*m")
_strip = lambda s: _ANSI.sub("", s)
_FLAGS = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def _clear_previous_subdomain_results() -> bool:
    """Remove prior subdomain rows and their scan records before a new scan."""
    if not os.path.isfile(DB_FILE):
        return True

    try:
        with sqlite3.connect(DB_FILE, timeout=30) as conn:
            conn.execute("BEGIN IMMEDIATE")
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            result_tables = {"subdomains", "subdomain_sources"} & tables
            scan_ids = set()
            for table in result_tables:
                scan_ids.update(
                    row[0]
                    for row in conn.execute(
                        f'SELECT DISTINCT "scan_id" FROM "{table}" WHERE "scan_id" IS NOT NULL'
                    )
                )

            for table in result_tables:
                conn.execute(f'DELETE FROM "{table}"')
            if scan_ids and "scans" in tables:
                placeholders = ",".join("?" for _ in scan_ids)
                conn.execute(
                    f'DELETE FROM "scans" WHERE "id" IN ({placeholders})',
                    tuple(scan_ids),
                )
            conn.commit()

        try:
            _ureq.urlopen(
                _ureq.Request(
                    f"{DB_API_BASE}/api/reload",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                ),
                timeout=5,
            )
        except Exception as exc:
            logger.warning("[SUBDOMAIN] DB API reload after cleanup failed: %s", exc)

        logger.info(
            "[SUBDOMAIN] Removed previous results: %d scan record(s)",
            len(scan_ids),
        )
        return True
    except (OSError, sqlite3.Error) as exc:
        logger.error("[SUBDOMAIN] Could not remove previous DB results: %s", exc)
        return False


def _run_subdomain_job(job_id: str, cmd: list, output_file: str) -> None:
    logger.info("job=%s  [SUBDOMAIN] Starting: subdomain-hunter.py", job_id)
    try:
        try:
            os.remove(output_file)
        except FileNotFoundError:
            pass
        except OSError as exc:
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      f"Could not remove previous output: {exc}",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [SUBDOMAIN] Could not remove previous output: %s", job_id, exc)
            return

        sh_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            **_FLAGS,
        )

        stderr_lines: list[str] = []

        def _read_stderr():
            for raw in sh_proc.stderr:
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
                    logger.debug("job=%s [subdomain] %s", job_id, line)

        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_err.start()

        try:
            sh_proc.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            sh_proc.kill(); sh_proc.wait()
            with _jobs_lock:
                _jobs[job_id].update({
                    "status":      "error",
                    "stderr":      "subdomain-hunter.py timed out after 30 minutes.",
                    "finished_at": _now_iso(),
                    "db_ready":    False,
                })
            logger.error("job=%s  [SUBDOMAIN] ERROR: timed out", job_id)
            return

        t_err.join(timeout=5)

        sh_ok              = sh_proc.returncode == 0
        sh_stderr_combined = _strip("\n".join(stderr_lines))[-2000:]

        db_ready = False
        if sh_ok and os.path.isfile(output_file):
            try:
                logger.info("job=%s  [SUBDOMAIN] JSON -> database-manager.py -> DB", job_id)
                db_ready = _write_to_db_and_reload(job_id, output_file, "subdomain")
            except Exception as exc:
                logger.error("job=%s  [SUBDOMAIN] ERROR: database-manager.py failed: %s", job_id, exc)
                sh_stderr_combined = f"DB write error: {exc}\n" + sh_stderr_combined

        status = "done" if (sh_ok and db_ready) else "error"

        if status == "done":
            logger.info("job=%s  [SUBDOMAIN] DONE: results in DB", job_id)
        else:
            logger.error("job=%s  [SUBDOMAIN] ERROR: sh_ok=%s  db_ready=%s", job_id, sh_ok, db_ready)

        with _jobs_lock:
            _jobs[job_id].update({
                "status":      status,
                "returncode":  sh_proc.returncode,
                "stderr":      sh_stderr_combined,
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
        logger.error("job=%s  [SUBDOMAIN] EXCEPTION: %s", job_id, exc)


def _watch_dns_and_start(
    dns_job_id: str,
    domain: str,
    workers: int = 10,
    takeover: bool = False,
    check_live: bool = False,
    resolve_dns: bool = True,
    wildcard_filter: bool = True,
) -> None:
    """DNS job bitənə qədər gözləyir, bitdikdən sonra subdomain job-unu başladır."""
    import time
    while True:
        with _jobs_lock:
            status = _jobs.get(dns_job_id, {}).get("status")
        if status == "done":
            logger.info("dns_job=%s DONE → subdomain job başladılır", dns_job_id)
            sub_job_id = _start_subdomain_job(domain, workers=workers, takeover=takeover, check_live=check_live, resolve_dns=resolve_dns, wildcard_filter=wildcard_filter)
            if sub_job_id:
                with _jobs_lock:
                    _jobs[dns_job_id]["subdomain_job_id"] = sub_job_id
            return
        if status == "error":
            logger.warning("dns_job=%s ERROR → subdomain job başladılmır", dns_job_id)
            return
        time.sleep(2)


def _start_subdomain_job(domain: str, workers: int = 10, takeover: bool = False, check_live: bool = False, resolve_dns: bool = True, wildcard_filter: bool = True) -> str:

    if not os.path.isfile(SUBDOM_SCRIPT):
        logger.error("[SUBDOMAIN] Script is not found: %s", SUBDOM_SCRIPT)
        return ""

    if not _clear_previous_subdomain_results():
        return ""

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_file        = os.path.join(RESULTS_DIR, "subdomains_enum.json")
    configuration_file = os.path.join(os.path.dirname(RESULTS_DIR), "Configuration", "api_keys.json")

    cmd = [
        VENV_PYTHON, SUBDOM_SCRIPT,
        "-d", domain,
        "-o", output_file,
        "--json",
        "--api-keys", configuration_file,
        "-q",
        "--workers", str(workers),
    ]
    if check_live:
        cmd.append("-c")
    if takeover:
        cmd.append("--takeover")
    if resolve_dns:
        cmd.append("--resolve")
    if not wildcard_filter:
        cmd.append("--no-wildcard-filter")

    job_id = _uuid.uuid4().hex[:12]

    with _jobs_lock:
        _jobs[job_id] = {
            "status":       "running",
            "type":         "subdomain",
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

    logger.info("subdomain/scan job=%s -> %s", job_id, " ".join(cmd))

    t = threading.Thread(target=_run_subdomain_job, args=(job_id, cmd, output_file), daemon=True)
    t.start()

    return job_id


@app.route("/api/subdomain/scan", methods=["POST"])
@limiter.limit("10 per minute")
def subdomain_scan():
    target, err = _require_target()
    if err:
        return err

    data   = request.get_json(silent=True) or {}
    domain = target["host"]

    def _to_bool(val, default: bool = False) -> bool:
        """JSON boolean-ı təhlükəsiz şəkildə Python bool-a çevirir.
        'false' / 'False' kimi string dəyərləri düzgün False qaytarır."""
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.strip().lower() == "true"
        if val is None:
            return default
        return bool(val)

    job_id = _start_subdomain_job(
        domain,
        workers=int(data.get("workers", 10)),
        takeover=_to_bool(data.get("takeover"),    default=False),
        check_live=_to_bool(data.get("check_live"), default=False),
        resolve_dns=_to_bool(data.get("resolve_dns"), default=True),
        wildcard_filter=_to_bool(data.get("wildcard_filter"), default=True),
    )
    if not job_id:
        if not os.path.isfile(SUBDOM_SCRIPT):
            return _err(f"subdomain-hunter.py not found: {SUBDOM_SCRIPT}", 500)
        return _err("Could not clear previous subdomain results from the database", 500)

    with _jobs_lock:
        cmd = _jobs[job_id]["cmd"]

    return _ok({
        "job_id": job_id,
        "domain": domain,
        "cmd":    cmd,
        "status": "running",
    })


@app.route("/api/subdomain/job/<job_id>", methods=["GET"])
def subdomain_job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return _err(f"Job not found: {job_id}", 404)

    return _ok({"job_id": job_id, **job})


@app.route("/api/subdomain/configure", methods=["POST"])
def subdomain_configure():
    pass