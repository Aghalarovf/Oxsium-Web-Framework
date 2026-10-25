import socket
import time

from protocol.smb.smb_negotiate import build_negotiate_request
from protocol.smb.smb_packet_parser import wrap_netbios_frame

MODULE_NAME = "smbtimeoutbehaviorprober"

TRUNCATE_RATIO = 0.4

BEHAVIOR_FINGERPRINT_HINTS = {
    "response_received": "stack_parsed_partial_frame",
    "tcp_fin_graceful_close": "stack_closed_gracefully_without_reply",
    "tcp_rst": "stack_reset_on_malformed_input",
    "no_response_timeout": "stack_silently_dropped_malformed_input",
}


def _build_truncated_frame() -> bytes:
    full_request = build_negotiate_request(message_id=0)
    full_frame = wrap_netbios_frame(full_request)
    cut_point = max(5, int(len(full_frame) * TRUNCATE_RATIO))
    return full_frame[:cut_point]


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    truncated_frame = _build_truncated_frame()

    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
    except socket.timeout as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": f"Timeout connecting to {host}:{port}",
        }
    except OSError as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": f"Failed to connect to {host}:{port}: {exc}",
        }

    bytes_sent = 0
    behavior = "error"
    response_byte_count = 0
    start_time = time.monotonic()
    elapsed_seconds = 0.0

    try:
        sock.settimeout(read_timeout)
        sock.sendall(truncated_frame)
        bytes_sent = len(truncated_frame)

        try:
            data = sock.recv(4096)
            elapsed_seconds = time.monotonic() - start_time
            if data:
                behavior = "response_received"
                response_byte_count = len(data)
            else:
                behavior = "tcp_fin_graceful_close"
        except ConnectionResetError:
            elapsed_seconds = time.monotonic() - start_time
            behavior = "tcp_rst"
        except socket.timeout:
            elapsed_seconds = time.monotonic() - start_time
            behavior = "no_response_timeout"
    except (BrokenPipeError, ConnectionResetError):
        elapsed_seconds = time.monotonic() - start_time
        behavior = "tcp_rst"
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }
    finally:
        try:
            sock.close()
        except OSError:
            pass

    data_out = {
        "bytes_sent": bytes_sent,
        "full_frame_bytes": len(wrap_netbios_frame(build_negotiate_request(message_id=0))),
        "socket_behavior": behavior,
        "response_byte_count": response_byte_count,
        "elapsed_seconds": round(elapsed_seconds, 4),
        "fingerprint_hint": BEHAVIOR_FINGERPRINT_HINTS.get(behavior, "unclassified"),
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data_out,
        "error": None,
    }
