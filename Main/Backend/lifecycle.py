import os
import time
import atexit
import signal
import threading
import json as _json
import urllib.request

from app import app
from config import logger, GUI_PORT
from helpers import _ok, _now_iso

_GUI_BASE  = f"http://127.0.0.1:{GUI_PORT}"
_stop_sent = False
_stop_lock = threading.Lock()


def _notify_gui(endpoint: str) -> None:
    url  = f"{_GUI_BASE}{endpoint}"
    body = _json.dumps({"ts": time.time()}).encode()
    try:
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass


def _send_stop_once() -> None:
    global _stop_sent
    with _stop_lock:
        if _stop_sent:
            return
        _stop_sent = True
    logger.info("Sending /api/stop to GUI on port %d ...", GUI_PORT)
    _notify_gui("/api/stop")


def _startup_notify() -> None:
    time.sleep(0.8)
    logger.info("Sending /api/start to GUI on port %d ...", GUI_PORT)
    _notify_gui("/api/start")


def _signal_handler(signum, frame) -> None:
    _send_stop_once()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


atexit.register(_send_stop_once)
signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


@app.route("/api/ping", methods=["GET"])
def ping():
    return _ok({"message": "pong", "ts": _now_iso()})


@app.route("/api/start", methods=["POST", "GET"])
def backend_start():
    return _ok({"status": "started", "ts": _now_iso()})


@app.route("/api/stop", methods=["POST", "GET"])
def backend_stop():
    _send_stop_once()
    return _ok({"status": "stopping", "ts": _now_iso()})