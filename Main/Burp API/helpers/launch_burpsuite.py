import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from helpers.burp_user_config import apply_jython_and_extension
from helpers.burp_user_config import default_user_config_path
from helpers.burp_user_config import detect_edition
from helpers.dismiss_jre_dialog import start_auto_dismiss
from helpers.java_path import get_java_major_version


_lock = threading.Lock()
_state = {"proc": None, "pid": None}


class BurpAlreadyRunning(RuntimeError):
    pass


class BurpLaunchFailed(RuntimeError):
    pass


def is_running():
    proc = _state["proc"]
    return proc is not None and proc.poll() is None


def get_status():
    with _lock:
        running = is_running()
        pid = _state["pid"] if running else None
    return {"running": running, "pid": pid}


def _resolve_launch_target(burp_jar, java_path):
    if not burp_jar:
        raise ValueError("Burp JAR is not configured")
    if not java_path:
        raise ValueError("Java Path is not configured")

    jar_path = Path(burp_jar)
    java_bin = Path(java_path)

    if not jar_path.is_file():
        raise FileNotFoundError(f"Burp JAR not found: {jar_path}")
    if not java_bin.is_file():
        raise FileNotFoundError(f"Java binary not found: {java_bin}")

    edition = detect_edition(jar_path)
    user_config_path = default_user_config_path(edition)

    cmd = [str(java_bin)]
    java_major = get_java_major_version(java_bin)
    if java_major is not None and java_major >= 22:
        cmd.append("--enable-native-access=ALL-UNNAMED")
    cmd += ["-jar", str(jar_path), f"--user-config-file={user_config_path}"]

    return cmd, jar_path, user_config_path


def _log_file_path(jar_path):
    log_dir = jar_path.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "burpsuite.log"


def _spawn(cmd, cwd, log_path):
    popen_kwargs = {"cwd": cwd}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    with open(log_path, "a", encoding="utf-8") as log_handle:
        log_handle.write(f"\n--- launch {datetime.now(timezone.utc).isoformat()} ---\n")
        log_handle.write(f"cmd: {' '.join(cmd)}\n")
        log_handle.flush()
        return subprocess.Popen(cmd, stdout=log_handle, stderr=subprocess.STDOUT, **popen_kwargs)


def _tail(path, max_chars=4000):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[-max_chars:]


def _ensure_started(proc, log_path, wait_seconds=2.5):
    time.sleep(wait_seconds)
    if proc.poll() is not None:
        exit_code = proc.returncode
        tail = _tail(log_path)
        raise BurpLaunchFailed(
            f"BurpSuite process exited immediately (exit code {exit_code}). "
            f"Log tail:\n{tail}"
        )


def _graceful_terminate(proc, timeout=20):
    pid = proc.pid

    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True, text=True, timeout=5)
        else:
            proc.terminate()
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        pass

    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True, text=True, timeout=10)
        else:
            proc.kill()
        proc.wait(timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        pass

    return proc.poll() is not None


def _register(proc):
    with _lock:
        _state["proc"] = proc
        _state["pid"] = proc.pid


def _unregister(proc):
    with _lock:
        if _state["proc"] is proc:
            _state["proc"] = None
            _state["pid"] = None


def _confirm_started(proc, log_path):
    start_auto_dismiss(proc)
    try:
        _ensure_started(proc, log_path)
    except BurpLaunchFailed:
        _unregister(proc)
        raise


def start(burp_jar, java_path):
    with _lock:
        if is_running():
            raise BurpAlreadyRunning("BurpSuite is already running")

        cmd, jar_path, user_config_path = _resolve_launch_target(burp_jar, java_path)
        log_path = _log_file_path(jar_path)
        proc = _spawn(cmd, str(jar_path.parent), log_path)
        _state["proc"] = proc
        _state["pid"] = proc.pid

    _confirm_started(proc, log_path)

    return {
        "pid": proc.pid,
        "user_config_file": str(user_config_path),
        "log_file": str(log_path),
    }


def stop():
    with _lock:
        proc = _state["proc"]
        if proc is None or not is_running():
            _state["proc"] = None
            _state["pid"] = None
            return {"closed": False, "already_stopped": True}

        closed = _graceful_terminate(proc)
        _state["proc"] = None
        _state["pid"] = None

    return {"closed": closed}


def reconfig(burp_jar, java_path, jython_jar, extension_file):
    with _lock:
        proc = _state["proc"]
        was_running = proc is not None and is_running()
        if was_running:
            _graceful_terminate(proc)
        _state["proc"] = None
        _state["pid"] = None

    if not burp_jar:
        raise ValueError("Burp JAR is not configured")

    jar_path = Path(burp_jar)
    if not jar_path.is_file():
        raise FileNotFoundError(f"Burp JAR not found: {jar_path}")

    integration = apply_jython_and_extension(
        jython_jar=jython_jar,
        extension_file=extension_file,
        burp_jar=jar_path,
        overwrite=False,
    )

    cmd, _, user_config_path = _resolve_launch_target(burp_jar, java_path)
    log_path = _log_file_path(jar_path)
    proc = _spawn(cmd, str(jar_path.parent), log_path)
    _register(proc)
    _confirm_started(proc, log_path)

    return {
        "pid": proc.pid,
        "was_running": was_running,
        "jython_integration": integration,
        "user_config_file": str(user_config_path),
        "log_file": str(log_path),
    }