import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

from helpers.burpsuite_jar import add_burp_jar_args, resolve_burp_jar
from helpers.burpsuite_jar import auto_find as burp_auto_find
from helpers.burpsuite_jar import get_jar_required_java_version
from helpers.java_path import add_java_path_args, resolve_java_path
from helpers.java_path import auto_find as java_auto_find
from helpers.java_path import find_best_java, get_java_major_version
from helpers.java_path import list_java_candidates, tested_java_major
from helpers.burp_user_config import apply_jython_and_extension, detect_edition
from helpers import launch_burpsuite
from helpers import vuln_scanner


ROOT = Path(__file__).resolve().parents[2]
MAIN_DIR = ROOT / "Main"
JYTHON_JAR = MAIN_DIR / "Burp API" / "helpers" / "jython-standalone-2.7.4.jar"
Burp_exporter = MAIN_DIR / "Reconnaissance-Modules" / "Burp Exporter" / "burp_exporter.py"
VULN_SCANNER = MAIN_DIR / "Reconnaissance-Modules" / "Vulnerability-Scanner" / "vulnerability_scanner.py"
RESULTS_DIR = MAIN_DIR / "Scan-Results"
DB_DIR = MAIN_DIR / "SQLite-Engine"
DB_FILE = RESULTS_DIR / "scan_results.db"
DB_MANAGER = DB_DIR / "database-manager.py"
DB_API_BASE = os.getenv("DB_API_BASE", "http://127.0.0.1:30301")
PYTHON = Path(sys.executable)
FLUSH_EVERY = 25
ENTRIES_LIMIT = 500
EXPORTER_TIMEOUT = 15
REQUEST_BODY_LIMIT = 4000
INTERCEPT_FILE = RESULTS_DIR / "burp_traffic.json"
FINDINGS_FILE = RESULTS_DIR / "findings.json"
FINDINGS_LIMIT = 1000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("oxsium.burp_api")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

jobs = {}
jobs_lock = threading.Lock()

config = {
    "burp_jar": None,
    "java_path": None,
    "jython_jar": str(JYTHON_JAR),
    "burp_exporter": str(Burp_exporter),
}
config_lock = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ok(data, status=200):
    return jsonify({"success": True, **data}), status


def error(message, status=400):
    return jsonify({"success": False, "error": message, "code": status}), status


def active_job():
    with jobs_lock:
        for job_id, job in jobs.items():
            if job["status"] == "running" and job["mode"] == "push":
                return job_id, job
    return None, None


def write_database(job_id, entries):
    if not entries:
        return False

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_file = RESULTS_DIR / "burp_traffic.json"
    try:
        output_file.write_text(
            json.dumps(entries, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        logger.error("job=%s [BURP] output write failed: %s", job_id, exc)
        return False

    if not DB_MANAGER.is_file():
        logger.warning("job=%s [BURP] database manager not found: %s", job_id, DB_MANAGER)
        return False

    try:
        process = subprocess.run(
            [str(PYTHON), str(DB_MANAGER), str(output_file), "-o", str(DB_FILE), "--quiet"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("job=%s [BURP] database update failed: %s", job_id, exc)
        return False

    if process.returncode != 0:
        logger.error("job=%s [BURP] database manager failed: %s", job_id, process.stderr[-500:])
        return False

    try:
        payload = json.dumps({"job_id": job_id, "phase": "burp"}).encode()
        req = urllib.request.Request(
            f"{DB_API_BASE}/api/reload",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5).close()
    except OSError as exc:
        logger.warning("job=%s [BURP] database reload failed: %s", job_id, exc)

    with jobs_lock:
        job = jobs.get(job_id)
        if job:
            job["db_ready"] = True
            job["db_file"] = str(DB_FILE)
            job["output_file"] = str(output_file)
    return True


@app.get("/api/ping")
def ping():
    return ok({"service": "burp_api", "status": "running"})


def _required_java_version():
    with config_lock:
        jar = config.get("burp_jar")
    if not jar:
        return None
    try:
        return get_jar_required_java_version(Path(jar))
    except OSError:
        return None


def _java_candidates():
    with config_lock:
        jar = config.get("burp_jar")
    required = _required_java_version()
    candidates = list_java_candidates(required, Path(jar) if jar else None)
    return required, candidates


def _auto_detect(target):
    if target == "burp-jar":
        logger.info("Searching system for BurpSuite JAR...")
        found = burp_auto_find()
        if not found:
            return error("BurpSuite JAR not found on this system.", 404)
        with config_lock:
            config["burp_jar"] = str(found)
        logger.info("BurpSuite JAR found: %s", found)
        return ok({"target": target, "path": str(found)})

    if target == "java":
        logger.info("Searching system for Java binary...")
        required, candidates = _java_candidates()
        if not candidates:
            return error("Java binary not found on this system.", 404)

        default = candidates[0]
        with config_lock:
            config["java_path"] = default["path"]
        logger.info("Java binary selected: %s (Java %s, %s)", default["path"], default["major"], default["vendor"])

        payload = {
            "target": target,
            "path": default["path"],
            "java_version": default["major"],
            "required_java_version": required,
            "tested_java_major": tested_java_major(required),
            "default_recommended": default["recommended"],
            "candidates": candidates,
        }
        if required and default["major"] < required:
            payload["warning"] = (
                f"Burp JAR requires Java {required}+, but the most suitable version found on this system was "
                f"Java {default['major']}. Install Java {required}+ and "
                f"browse to the Java Path manually."
            )
            logger.warning(payload["warning"])
        elif not default["recommended"]:
            payload["warning"] = (
                f"Java {tested_java_major(required)} was not found on this system. "
                f"Burp may show a JRE warning dialog on startup."
            )
            logger.warning(payload["warning"])
        return ok(payload)

    return error(f"Unknown detection target: {target}", 400)


@app.post("/api/burp/auto")
def burp_auto():
    return _auto_detect("burp-jar")


@app.post("/api/java/auto")
def java_auto():
    return _auto_detect("java")


@app.get("/api/java/list")
def java_list():
    required, candidates = _java_candidates()
    default = candidates[0] if candidates else None
    return ok({
        "required_java_version": required,
        "tested_java_major": tested_java_major(required),
        "default_path": default["path"] if default else None,
        "default_recommended": bool(default and default["recommended"]),
        "candidates": candidates,
    })


@app.get("/api/burp/detect/<target>")
def detect(target):
    return _auto_detect(target)


@app.get("/api/burp/config")
def get_config():
    with config_lock:
        return ok({
            "burp_jar": config["burp_jar"],
            "java_path": config["java_path"],
            "jython_jar": config["jython_jar"],
            "burp_exporter": config["burp_exporter"],
        })


@app.post("/api/burp/config")
def set_config():
    data = request.get_json(silent=True) or {}
    with config_lock:
        if "burp_jar" in data:
            config["burp_jar"] = str(data["burp_jar"]).strip() or None
        if "java_path" in data:
            config["java_path"] = str(data["java_path"]).strip() or None
        burp_jar, jython_jar, burp_exporter = (
            config["burp_jar"], config["jython_jar"], config["burp_exporter"],
        )

    response = {
        "burp_jar": burp_jar,
        "java_path": config["java_path"],
        "jython_jar": jython_jar,
        "burp_exporter": burp_exporter,
    }

    if burp_jar:
        try:
            integration = apply_jython_and_extension(
                jython_jar=jython_jar,
                extension_file=burp_exporter,
                burp_jar=Path(burp_jar),
            )
            response["jython_integration"] = integration
            logger.info(
                "Jython + Burp Exporter registered in %s",
                integration["user_config_file"],
            )
        except (OSError, FileNotFoundError) as exc:
            response["jython_integration_error"] = str(exc)
            logger.warning("Jython/extension integration failed: %s", exc)

    return ok(response)


@app.get("/api/burp/status")
def burp_status():
    return ok(launch_burpsuite.get_status())


@app.post("/api/burp/launch")
def launch_burp():
    with config_lock:
        burp_jar = config.get("burp_jar")
        java_path = config.get("java_path")

    try:
        result = launch_burpsuite.start(burp_jar, java_path)
    except RuntimeError as exc:
        return error(str(exc), 409)
    except ValueError as exc:
        return error(str(exc), 400)
    except FileNotFoundError as exc:
        return error(str(exc), 404)

    logger.info("BurpSuite launched: pid=%s", result["pid"])
    return ok(result)


@app.post("/api/burp/close")
def close_burp():
    result = launch_burpsuite.stop()
    logger.info("BurpSuite close requested: %s", result)
    return ok(result)


@app.post("/api/burp/reconfig")
def reconfig_burp():
    with config_lock:
        burp_jar = config.get("burp_jar")
        java_path = config.get("java_path")
        jython_jar = config["jython_jar"]
        burp_exporter = config["burp_exporter"]

    try:
        result = launch_burpsuite.reconfig(burp_jar, java_path, jython_jar, burp_exporter)
    except ValueError as exc:
        return error(str(exc), 400)
    except FileNotFoundError as exc:
        return error(str(exc), 404)
    except OSError as exc:
        return error(str(exc), 500)

    logger.info("BurpSuite reconfigured and relaunched: pid=%s", result["pid"])
    return ok(result)


@app.post("/api/burp/configure")
def configure():
    data = request.get_json(silent=True) or {}
    burp_jar = str(data.get("burp_jar") or "").strip()
    java_path = str(data.get("java_path") or "").strip()

    if not burp_jar:
        return error("burp_jar is required", 400)
    if not java_path:
        return error("java_path is required", 400)

    jar_path = Path(burp_jar)
    if not jar_path.is_file():
        return error(f"Burp JAR not found: {jar_path}", 404)
    if not Path(java_path).is_file():
        return error(f"Java binary not found: {java_path}", 404)

    with config_lock:
        config["burp_jar"] = burp_jar
        if java_path:
            config["java_path"] = java_path
        jython_jar = config["jython_jar"]
        burp_exporter = config["burp_exporter"]
        resolved_java_path = config.get("java_path")

    edition = detect_edition(jar_path)

    response = {
        "burp_jar": burp_jar,
        "java_path": resolved_java_path,
        "edition": edition,
    }

    try:
        integration = apply_jython_and_extension(
            jython_jar=jython_jar,
            extension_file=burp_exporter,
            burp_jar=jar_path,
        )
    except FileNotFoundError as exc:
        return error(str(exc), 404)
    except OSError as exc:
        return error(str(exc), 500)

    response["jython_integration"] = integration
    logger.info("Jython + Burp Exporter registered in %s", integration["user_config_file"])

    return ok(response)


@app.post("/api/burp/integrate-jython")
def integrate_jython():
    with config_lock:
        burp_jar = config.get("burp_jar")
        jython_jar = config["jython_jar"]
        burp_exporter = config["burp_exporter"]

    try:
        result = apply_jython_and_extension(
            jython_jar=jython_jar,
            extension_file=burp_exporter,
            burp_jar=Path(burp_jar) if burp_jar else None,
        )
    except FileNotFoundError as exc:
        return error(str(exc), 404)
    except OSError as exc:
        return error(f"Failed to write configuration file: {exc}", 500)

    return ok(result)


@app.get("/api/burp/validate")
def validate_config():
    with config_lock:
        jar = config.get("burp_jar")
        java = config.get("java_path")

    if not jar or not java:
        return error("Both Burp JAR and Java Path must be selected.", 400)

    jar_path = Path(jar)
    java_path = Path(java)

    if not jar_path.is_file():
        return error(f"Burp JAR not found: {jar_path}", 404)
    if not java_path.is_file():
        return error(f"Java binary not found: {java_path}", 404)

    required_version = get_jar_required_java_version(jar_path)
    installed_version = get_java_major_version(java_path)

    compatible = (
        required_version is not None
        and installed_version is not None
        and installed_version >= required_version
    )

    result = {
        "burp_jar": str(jar_path),
        "java_path": str(java_path),
        "required_java_version": required_version,
        "installed_java_version": installed_version,
        "compatible": compatible,
    }

    if not compatible and required_version and installed_version:
        result["message"] = (
            f"Mismatch: the selected Burp JAR requires Java {required_version}+, "
            f"but the selected java.exe is Java {installed_version}."
        )

    return ok(result)


def _touch_exporter(job):
    job["exporter_seen"] = time.time()


@app.post("/api/burp/push/start")
def push_start():
    data = request.get_json(silent=True) or {}
    from_exporter = str(data.get("client") or "") == "exporter"
    existing_id, existing = active_job()
    if existing:
        if from_exporter:
            with jobs_lock:
                _touch_exporter(existing)
        return ok({
            "job_id": existing_id,
            "mode": "push",
            "status": "running",
            "host": existing["host"],
            "port": existing["port"],
        })

    host = str(data.get("host") or "127.0.0.1").strip()
    try:
        port = int(data.get("port") or 30302)
    except (TypeError, ValueError):
        return error("Port must be an integer", 400)

    if not host:
        return error("Host is required", 400)
    if not 1 <= port <= 65535:
        return error("Port must be in range 1-65535", 400)

    job_id = uuid.uuid4().hex[:12]
    with jobs_lock:
        jobs[job_id] = {
            "status": "running",
            "type": "burp",
            "mode": "push",
            "host": host,
            "port": port,
            "buffer": [],
            "captured_count": 0,
            "last_entry_at": None,
            "started_at": now_iso(),
            "finished_at": None,
            "db_ready": False,
            "db_file": None,
            "exporter_seen": time.time() if from_exporter else None,
        }

    logger.info("Burp API job started: %s", job_id)

    try:
        result = vuln_scanner.start(PYTHON, VULN_SCANNER, INTERCEPT_FILE, FINDINGS_FILE)
        logger.info("Vulnerability scanner auto-started: pid=%s output=%s", result["pid"], result["output"])
    except vuln_scanner.ScannerAlreadyRunning:
        pass
    except (FileNotFoundError, vuln_scanner.ScannerLaunchFailed) as exc:
        logger.warning("Vulnerability scanner not started: %s", exc)

    return ok({"job_id": job_id, "mode": "push", "status": "running", "host": host, "port": port})


@app.post("/api/burp/push/stop/<job_id>")
def push_stop(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job or job["mode"] != "push":
            return error(f"Burp job not found: {job_id}", 404)
        entries = list(job["buffer"])
        job.update({"status": "done", "finished_at": now_iso()})

    write_database(job_id, entries)
    vuln_scanner.stop()
    return ok({"job_id": job_id, "status": "done", "captured_count": len(entries)})


@app.post("/api/burp/exporter/heartbeat")
def exporter_heartbeat():
    data = request.get_json(silent=True) or {}
    job_id = str(data.get("job_id") or "").strip()
    with jobs_lock:
        job = jobs.get(job_id)
        if not job or job["mode"] != "push":
            return error(f"Burp job not found: {job_id}", 404)
        if job["status"] != "running":
            return error(f"Burp job is not running: {job_id}", 409)
        _touch_exporter(job)
    return ok({"job_id": job_id})


@app.post("/api/burp/ingest")
def ingest():
    data = request.get_json(silent=True) or {}
    job_id = str(data.get("job_id") or "").strip()
    entry = data.get("entry")
    if not job_id or not isinstance(entry, dict):
        return error("job_id and entry are required", 400)

    with jobs_lock:
        job = jobs.get(job_id)
        if not job or job["mode"] != "push":
            return error(f"Burp job not found: {job_id}", 404)
        if job["status"] != "running":
            return error(f"Burp job is not running: {job_id}", 409)
        _touch_exporter(job)
        job["buffer"].append(entry)
        job["captured_count"] = len(job["buffer"])
        job["last_entry_at"] = now_iso()
        count = len(job["buffer"])
        entries = list(job["buffer"]) if count % FLUSH_EVERY == 0 else None

    if entries:
        write_database(job_id, entries)

    return ok({"job_id": job_id, "captured_count": count})


def _gui_entry(entry):
    req = entry.get("request")
    if isinstance(req, dict):
        body = req.get("body")
        if isinstance(body, str) and len(body) > REQUEST_BODY_LIMIT:
            entry = {**entry, "request": {**req, "body": body[:REQUEST_BODY_LIMIT]}}
    return entry


@app.get("/api/burp/job/<job_id>")
def job_status(job_id):
    try:
        limit = max(1, min(int(request.args.get("limit", ENTRIES_LIMIT)), 2000))
    except (TypeError, ValueError):
        limit = ENTRIES_LIMIT
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return error(f"Burp job not found: {job_id}", 404)
        result = dict(job)
        recent = list(job["buffer"][-limit:])
    result.pop("buffer", None)
    seen = result.pop("exporter_seen", None)
    result["exporter_connected"] = bool(
        result["status"] == "running" and seen and time.time() - seen < EXPORTER_TIMEOUT
    )
    result["exporter_last_seen"] = (
        datetime.fromtimestamp(seen, timezone.utc).isoformat() if seen else None
    )
    result["entries"] = [_gui_entry(e) for e in recent]
    result["findings"] = vuln_scanner.get_results(FINDINGS_LIMIT)["results"]
    return ok({"job_id": job_id, **result})


@app.post("/api/vuln/start")
def vuln_start():
    data = request.get_json(silent=True) or {}
    target = Path(str(data.get("target") or INTERCEPT_FILE))
    output = Path(str(data.get("output") or FINDINGS_FILE))
    extra_args = data.get("args") if isinstance(data.get("args"), list) else None

    try:
        result = vuln_scanner.start(PYTHON, VULN_SCANNER, target, output, extra_args=extra_args)
    except vuln_scanner.ScannerAlreadyRunning as exc:
        return error(str(exc), 409)
    except FileNotFoundError as exc:
        return error(str(exc), 404)
    except vuln_scanner.ScannerLaunchFailed as exc:
        return error(str(exc), 500)

    logger.info("Vulnerability scanner started: pid=%s", result["pid"])
    return ok(result)


@app.post("/api/vuln/stop")
def vuln_stop():
    result = vuln_scanner.stop()
    logger.info("Vulnerability scanner stop requested: %s", result)
    return ok(result)


@app.get("/api/vuln/status")
def vuln_status():
    return ok(vuln_scanner.get_status())


@app.get("/api/vuln/results")
def vuln_results():
    try:
        limit = max(1, min(int(request.args.get("limit", FINDINGS_LIMIT)), 5000))
    except (TypeError, ValueError):
        limit = FINDINGS_LIMIT
    return ok(vuln_scanner.get_results(limit))


def main():
    parser = argparse.ArgumentParser(description="Oxsium Burp API")
    parser.add_argument("--start", action="store_true", help="Start the Burp API server.")
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "30302")))
    add_burp_jar_args(parser)
    add_java_path_args(parser)
    args = parser.parse_args()

    has_burp_flag = getattr(args, "burp_auto", False) or getattr(args, "burp_browse", None)
    has_java_flag = getattr(args, "java_auto", False) or getattr(args, "java_browse", None)

    if has_burp_flag or has_java_flag:
        if getattr(args, "burp_auto", False):
            logger.info("Searching entire system for BurpSuite JAR, please wait...")
        if getattr(args, "java_auto", False):
            logger.info("Searching system for Java binary...")

        try:
            if has_burp_flag:
                jar = resolve_burp_jar(args)
                with config_lock:
                    config["burp_jar"] = str(jar)
                logger.info("BurpSuite JAR : %s", jar)
            if has_java_flag:
                required_java = None
                with config_lock:
                    jar_cfg = config.get("burp_jar")
                if jar_cfg:
                    try:
                        required_java = get_jar_required_java_version(Path(jar_cfg))
                    except OSError:
                        required_java = None
                java = resolve_java_path(
                    args,
                    required=required_java,
                    burp_jar=Path(jar_cfg) if jar_cfg else None,
                )
                with config_lock:
                    config["java_path"] = str(java)
                logger.info("Java binary   : %s", java)
        except (FileNotFoundError, ValueError) as exc:
            logger.error("Path resolution failed: %s", exc)
            if not args.start:
                sys.exit(1)

        if has_burp_flag and has_java_flag:
            with config_lock:
                jar_cfg, java_cfg = config.get("burp_jar"), config.get("java_path")
            if jar_cfg and java_cfg:
                required = get_jar_required_java_version(Path(jar_cfg))
                installed = get_java_major_version(Path(java_cfg))
                if required and installed and installed < required:
                    logger.warning(
                        "Version mismatch: Burp JAR requires Java %s+, "
                        "configured java is Java %s.",
                        required, installed,
                    )

    if not args.start:
        logger.info("Paths resolved. Use --start to launch the API server.")
        sys.exit(0)

    logger.info("Burp API listening on %s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()