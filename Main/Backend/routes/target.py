from flask import request

from app import app, limiter
from config import logger
from helpers import (
    _state_lock, _target,
    _ok, _err,
    _validate_url, _strip_scheme, _now_iso,
)


@app.route("/api/target/set", methods=["POST"])
@limiter.limit("60 per minute")
def target_set():
    data = request.get_json(silent=True) or {}

    url = str(data.get("url") or "").strip()
    if not url:
        return _err("url is required")
    if not _validate_url(url):
        return _err("Invalid URL format. Example: https://example.com or http://10.10.10.10")

    port = data.get("port")
    if port is not None:
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            return _err("Port must be in range 1–65535")

    vhost       = str(data.get("vhost")   or "").strip() or None
    proxy       = str(data.get("proxy")   or "").strip() or None
    headers_raw = str(data.get("headers") or "").strip() or None

    parsed_headers: dict[str, str] = {}
    if headers_raw:
        for line in headers_raw.splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                parsed_headers[k.strip()] = v.strip()

    target = {
        "url":            url,
        "host":           _strip_scheme(url),
        "port":           port,
        "vhost":          vhost,
        "proxy":          proxy,
        "headers_raw":    headers_raw,
        "headers_parsed": parsed_headers,
        "set_at":         _now_iso(),
    }

    with _state_lock:
        _target.clear()
        _target.update(target)

    logger.info("Target set -> %s (port=%s vhost=%s)", url, port, vhost)
    return _ok({"target": target})


@app.route("/api/target", methods=["GET"])
def target_get():
    with _state_lock:
        t = dict(_target) if _target else None
    return _ok({"target": t})