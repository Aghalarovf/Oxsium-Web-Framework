from __future__ import annotations

import os
import signal
import socket
import subprocess
import threading
from pathlib import Path

from flask import request

from app import app, limiter
from config import MAIN_DIR, VENV_PYTHON, logger
from helpers import _err, _ok

_MODULE_DIR = Path(MAIN_DIR) / "Reconnaissance-Modules" / "Oxsintercept"
_CONFIG_DIR = Path(MAIN_DIR) / "Configurations"
_RESULT_DIR = Path(MAIN_DIR) / "Reconnaissance-Modules" / "Scan-Results"
_lock = threading.Lock()
_process: subprocess.Popen | None = None
_logs: list[dict] = []
_config: dict = {}


def _log(message: str, kind: str = "") -> None:
    with _lock:
        _logs.append({"message": message.rstrip(), "type": kind})
        del _logs[:-120]


def _reader(process: subprocess.Popen) -> None:
    if process.stdout:
        for line in process.stdout:
            _log(line)
    code = process.wait()
    _log(f"Process exited with code {code}.", "success" if code == 0 else "error")


def _running() -> bool:
    return _process is not None and _process.poll() is None


def _files() -> dict:
    output = _config.get("output", "oxsproxy")
    return {"crawl": f"{output}_crawl.json", "intercept": f"{output}_intercept.json"}


def _safe_name(value: str, fallback: str) -> str:
    name = Path(value or fallback).name
    return name if name else fallback


def _config_name(value: str, fallback: str) -> str:
    return _safe_name(value, fallback)


def _config_arg(name: str) -> str:
    return str(Path("..") / ".." / "Configurations" / name)


def _port_available(host: str, port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


@app.route("/api/proxy/status", methods=["GET"])
def proxy_status():
    with _lock:
        logs = list(_logs[-40:])
        config = dict(_config)
    return _ok({"running": _running(), "starting": False, "logs": logs, "files": _files(), "config": config})


@app.route("/api/proxy/start", methods=["POST"])
@limiter.limit("20 per minute")
def proxy_start():
    global _process, _config
    data = request.get_json(silent=True) or {}
    with _lock:
        if _running():
            return _err("OxsIntercept is already running", 409)

    port = int(data.get("listener_port") or 8080)
    if not 1 <= port <= 65535:
        return _err("Listener port must be in range 1-65535")
    listener_ip = str(data.get("listener_ip") or "0.0.0.0")
    if not _port_available(listener_ip, port):
        return _err(f"Listener port {listener_ip}:{port} is already in use. Stop the existing proxy or choose another port.", 409)
    domain = str(data.get("domain") or "").strip()
    crawl = bool(data.get("crawl"))
    intercept = bool(data.get("intercept"))
    if (crawl or intercept) and not domain:
        return _err("Target domain is required for crawl or intercept mode")

    output = _safe_name(str(data.get("output") or "oxsproxy"), "oxsproxy")
    ca_cert = _config_name(str(data.get("ca_cert") or "oxsproxy.crt"), "oxsproxy.crt")
    ca_key = _config_name(str(data.get("ca_key") or "oxsproxy.key"), "oxsproxy.key")
    args = [str(VENV_PYTHON), str(_MODULE_DIR / "oxsintercept.py"), "--proxy", "--listener-ip", listener_ip, "--listener-port", str(port), "--ca-cert", _config_arg(ca_cert), "--ca-key", _config_arg(ca_key), "--output", str(_RESULT_DIR / output)]
    if domain:
        args += ["--domain", domain]
    if crawl:
        args.append("--crawl")
        args += ["--max-pages", str(int(data.get("max_pages") or 200)), "--crawl-delay", str(float(data.get("crawl_delay") or 0.1))]
    if intercept:
        args.append("--intercept")
        args += ["--probe-delay", str(float(data.get("probe_delay") or 1))]
    if data.get("full_traffic"):
        args.append("--full-traffic")
    if data.get("user_agent"):
        args += ["--user-agent", str(data["user_agent"])]
    if data.get("limit"):
        args += ["--limit", str(int(data["limit"]))]
    cookies = str(data.get("cookies") or "").splitlines()
    cookies = [item.strip() for item in cookies if "=" in item.strip()]
    if cookies:
        args += ["--cookie", *cookies]

    try:
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "utf-8"
        process = subprocess.Popen(args, cwd=str(_MODULE_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=environment, **flags)
    except Exception as exc:
        logger.exception("Unable to start OxsIntercept")
        return _err(str(exc), 500)

    _process = process
    _config = {"output": str(_RESULT_DIR / output), "domain": domain, "port": port, "ca_cert": str(_CONFIG_DIR / ca_cert), "ca_key": str(_CONFIG_DIR / ca_key), "intercept": intercept, "full_traffic": bool(data.get("full_traffic")), "crawl": crawl, "max_pages": int(data.get("max_pages") or 200), "limit": data.get("limit"), "crawl_delay": float(data.get("crawl_delay") or 0.1), "probe_delay": float(data.get("probe_delay") or 1), "user_agent": str(data.get("user_agent") or "")}
    with _lock:
        _logs.clear()
    _log(f"Started OxsIntercept with PID {process.pid}.", "success")
    threading.Thread(target=_reader, args=(process,), daemon=True).start()
    return _ok({"running": True, "starting": True, "files": _files(), "message": "OxsIntercept is starting."})


@app.route("/api/proxy/stop", methods=["POST"])
@limiter.limit("30 per minute")
def proxy_stop():
    global _process
    with _lock:
        process = _process
    if not process or process.poll() is not None:
        return _ok({"running": False, "message": "OxsIntercept is not running."})
    try:
        if os.name == "nt":
            process.terminate()
        else:
            process.send_signal(signal.SIGINT)
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
    except Exception as exc:
        return _err(str(exc), 500)
    _log("OxsIntercept stopped.", "success")
    return _ok({"running": False, "message": "OxsIntercept stopped."})


@app.route("/api/proxy/cert", methods=["POST"])
@app.route("/api/proxy/certificate", methods=["POST"])
@limiter.limit("10 per minute")
def proxy_cert():
    data = request.get_json(silent=True) or {}
    cert = _config_name(str(data.get("ca_cert") or "oxsproxy.crt"), "oxsproxy.crt")
    key = _config_name(str(data.get("ca_key") or "oxsproxy.key"), "oxsproxy.key")
    cn = str(data.get("ca_cn") or "OxsIntercept CA")
    cert_arg = _config_arg(cert)
    key_arg = _config_arg(key)
    command = [str(VENV_PYTHON), str(_MODULE_DIR / "oxsintercept.py"), "--cert", "--ca-cert", cert_arg, "--ca-key", key_arg, "--ca-cn", cn]
    if data.get("overwrite"):
        command.append("--overwrite-cert")
    try:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(command, cwd=str(_MODULE_DIR), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, env=environment, **flags)
    except Exception as exc:
        return _err(str(exc), 500)
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0:
        _log(output or "Certificate command failed.", "error")
        return _err(output or "Certificate command failed.", 500)
    message = output or f"CA certificate ready: {cert}; private key: {key}"
    _log(message, "success")
    return _ok({"message": message, "certificate": str(_CONFIG_DIR / cert), "key": str(_CONFIG_DIR / key), "command": command})
