"""
Vulnerability Scanner process helper.

Mirrors the lifecycle pattern used by helpers/launch_burpsuite.py, but instead
of launching a GUI application it spawns the real CLI of

    Main/Reconnaissance-Modules/Vulnerability-Scanner/vulnerability_scanner.py

Invocation contract:

    vulnerability_scanner.py --intercept TARGET_PATH --all -o OUTPUT_PATH --live

  - TARGET_PATH is the intercept traffic log file to read (typically
    burp_api.py's RESULTS_DIR / "burp_traffic.json", which is rewritten
    live as Burp traffic is ingested).
  - "--all" runs every detection module.
  - "-o OUTPUT_PATH" is the findings file the scanner writes to.
  - "--live" makes the scanner keep re-scanning and rewriting OUTPUT_PATH
    as new traffic appears, instead of exiting after a single pass.

This module does not parse the scanner's stdout. Instead, once the process
is launched, a background thread polls OUTPUT_PATH every POLL_INTERVAL
seconds, reads whatever JSON array of findings is currently there, and
keeps the most recent snapshot in memory so the Flask layer (burp_api.py)
can expose it over HTTP without re-reading the file itself on every
request.

Only one scan runs at a time, same restriction BurpSuite launch already has.
"""

import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

POLL_INTERVAL = 3.0


class ScannerAlreadyRunning(RuntimeError):
    pass


class ScannerLaunchFailed(RuntimeError):
    pass


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


_lock = threading.Lock()
_state = {
    "proc": None,
    "pid": None,
    "poll_thread": None,
    "stop_polling": None,
    "script": None,
    "target": None,
    "output": None,
    "args": None,
    "started_at": None,
    "finished_at": None,
    "exit_code": None,
    "results": [],
    "captured_count": 0,
    "last_result_at": None,
    "last_poll_at": None,
    "last_poll_error": None,
    "error": None,
}


def is_running():
    proc = _state["proc"]
    return proc is not None and proc.poll() is None


def _log_file_path(script_path: Path) -> Path:
    log_dir = script_path.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "vulnerability_scanner.log"


def _build_command(python_exec, script_path, target_path, output_path, extra_args=None):
    cmd = [
        str(python_exec), str(script_path),
        "--intercept", str(target_path),
        "--all",
        "-o", str(output_path),
        "--live",
    ]
    if extra_args:
        cmd.extend(str(a) for a in extra_args)
    return cmd


def _extract_findings(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("findings", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return [payload]
    return []


def _read_findings_file(output_path: Path):
    if not output_path.is_file():
        return None
    text = output_path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    return _extract_findings(json.loads(text))


def _poll_loop(output_path: Path, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            findings = _read_findings_file(output_path)
            if findings is not None:
                with _lock:
                    _state["results"] = findings
                    _state["captured_count"] = len(findings)
                    _state["last_result_at"] = _now_iso()
                    _state["last_poll_at"] = _now_iso()
                    _state["last_poll_error"] = None
            else:
                with _lock:
                    _state["last_poll_at"] = _now_iso()
        except (OSError, json.JSONDecodeError) as exc:
            with _lock:
                _state["last_poll_at"] = _now_iso()
                _state["last_poll_error"] = str(exc)
        stop_event.wait(POLL_INTERVAL)


def _watch_process(proc, log_path):
    with open(log_path, "a", encoding="utf-8") as log_handle:
        log_handle.write(f"\n--- scan {_now_iso()} ---\n")
        log_handle.flush()
        try:
            for raw_line in iter(proc.stdout.readline, ""):
                log_handle.write(raw_line)
                log_handle.flush()
        except (OSError, ValueError):
            pass

    proc.wait()
    with _lock:
        _state["finished_at"] = _now_iso()
        _state["exit_code"] = proc.returncode
        if _state["proc"] is proc:
            _state["proc"] = None
            _state["pid"] = None


def start(python_exec, script_path, target_path, output_path, extra_args=None, cwd=None, create_if_missing=True):
    """
    Launch:
        vulnerability_scanner.py --intercept <target_path> --all -o <output_path> --live
    and start polling output_path every POLL_INTERVAL seconds in a
    background thread.

    target_path is the intercept traffic log file to read -- typically
    burp_api.py's RESULTS_DIR / "burp_traffic.json", which is rewritten
    live as Burp traffic is ingested.

    output_path is the findings file the scanner writes to -- typically
    RESULTS_DIR / "findings.json".
    """
    with _lock:
        if is_running():
            raise ScannerAlreadyRunning("Vulnerability scan is already running")

        script_path = Path(script_path)
        if not script_path.is_file():
            raise FileNotFoundError(f"vulnerability_scanner.py not found: {script_path}")

        target = Path(target_path)
        if not target.is_file():
            if create_if_missing:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch()
            else:
                raise FileNotFoundError(f"Intercept target file not found: {target}")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        cmd = _build_command(python_exec, script_path, target, output, extra_args)
        log_path = _log_file_path(script_path)

        popen_kwargs = {
            "cwd": str(cwd) if cwd else str(script_path.parent),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(cmd, **popen_kwargs)
        except OSError as exc:
            raise ScannerLaunchFailed(f"Failed to start vulnerability scanner: {exc}") from exc

        stop_event = threading.Event()
        watcher = threading.Thread(target=_watch_process, args=(proc, log_path), daemon=True)
        poller = threading.Thread(target=_poll_loop, args=(output, stop_event), daemon=True)

        _state["proc"] = proc
        _state["pid"] = proc.pid
        _state["poll_thread"] = poller
        _state["stop_polling"] = stop_event
        _state["script"] = str(script_path)
        _state["target"] = str(target)
        _state["output"] = str(output)
        _state["args"] = cmd
        _state["started_at"] = _now_iso()
        _state["finished_at"] = None
        _state["exit_code"] = None
        _state["results"] = []
        _state["captured_count"] = 0
        _state["last_result_at"] = None
        _state["last_poll_at"] = None
        _state["last_poll_error"] = None
        _state["error"] = None

        watcher.start()
        poller.start()

    time.sleep(0.5)
    if proc.poll() is not None and proc.returncode not in (None, 0):
        with _lock:
            _state["error"] = "Scanner process exited immediately"
        raise ScannerLaunchFailed(
            f"Vulnerability scanner exited immediately (exit code {proc.returncode}). "
            f"Check {log_path} for details."
        )

    return {
        "pid": proc.pid,
        "script": str(script_path),
        "target": str(target),
        "output": str(output),
        "command": cmd,
        "log_file": str(log_path),
        "started_at": _state["started_at"],
    }


def stop(timeout=20):
    with _lock:
        proc = _state["proc"]
        stop_event = _state["stop_polling"]
        was_running = proc is not None and is_running()

    if stop_event:
        stop_event.set()

    if not was_running:
        return {"stopped": False, "already_stopped": True}

    pid = proc.pid
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T"], capture_output=True, text=True, timeout=5)
        else:
            proc.terminate()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True, text=True, timeout=10)
            else:
                proc.kill()
            proc.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            pass
    except OSError:
        pass

    with _lock:
        _state["finished_at"] = _state["finished_at"] or _now_iso()
        if _state["proc"] is proc:
            _state["proc"] = None
            _state["pid"] = None

    return {"stopped": True, "pid": pid}


def get_status():
    with _lock:
        running = is_running()
        return {
            "running": running,
            "pid": _state["pid"] if running else None,
            "script": _state["script"],
            "target": _state["target"],
            "output": _state["output"],
            "command": _state["args"],
            "started_at": _state["started_at"],
            "finished_at": _state["finished_at"],
            "exit_code": _state["exit_code"],
            "captured_count": _state["captured_count"],
            "last_result_at": _state["last_result_at"],
            "last_poll_at": _state["last_poll_at"],
            "last_poll_error": _state["last_poll_error"],
            "error": _state["error"],
        }


def get_results(limit=500):
    """
    Live read of the findings currently held in memory, refreshed from
    output_path every POLL_INTERVAL seconds by the background poller
    started in start().
    """
    limit = max(1, int(limit))
    with _lock:
        results = list(_state["results"])[-limit:]
        return {
            "results": results,
            "captured_count": _state["captured_count"],
            "last_result_at": _state["last_result_at"],
        }