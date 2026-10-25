from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel, tree_connect, tree_disconnect
from protocol.rpc.rpc_constants import NAMED_PIPE_MAP
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup

MODULE_NAME = "smbnullsessionprober"


def _probe_rpc_endpoints(transport) -> list:
    endpoints = []
    for pipe_name, (interface_uuid, version, version_minor) in NAMED_PIPE_MAP.items():
        entry = {
            "pipe": pipe_name,
            "interface_uuid": interface_uuid,
            "interface_version": f"{version}.{version_minor}",
            "pipe_opened": False,
            "bind_accepted": False,
            "error": None,
        }

        channel = RPCChannel(transport, pipe_name)
        try:
            channel.open()
            entry["pipe_opened"] = True
            channel.bind()
            entry["bind_accepted"] = channel.bound
        except (OxSMBError, OSError) as exc:
            entry["error"] = str(exc)
        finally:
            channel.close()

        endpoints.append(entry)

    return endpoints


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    # Reuse a shared session only when it is actually a null session; a
    # credentialed or guest session doesn't tell us whether anonymous
    # access is possible, so those fall through to a dedicated probe below.
    if (
        credentials is not None
        and auth_session is not None
        and auth_session.authenticated
        and auth_session.is_null
    ):
        try:
            tree_connect(auth_session.transport, f"\\\\{host}\\IPC$")
            ipc_reachable = True
            try:
                tree_disconnect(auth_session.transport)
            except (OxSMBError, OSError):
                pass
        except (OxSMBError, OSError):
            ipc_reachable = False

        endpoints = _probe_rpc_endpoints(auth_session.transport)

        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": _build_data(True, ipc_reachable, endpoints),
            "error": None,
        }

    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()
        negotiate(transport)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    null_session_possible = False
    try:
        null_session_setup(transport)
        null_session_possible = True
    except (OxSMBError, OSError):
        null_session_possible = False

    if not null_session_possible:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": _build_data(False, False, []),
            "error": None,
        }

    try:
        tree_connect(transport, f"\\\\{host}\\IPC$")
        ipc_reachable = True
    except (OxSMBError, OSError):
        ipc_reachable = False

    endpoints = _probe_rpc_endpoints(transport)
    transport.close()

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": _build_data(True, ipc_reachable, endpoints),
        "error": None,
    }


def _build_data(null_session_possible: bool, ipc_reachable: bool, endpoints: list) -> dict:
    bindable = [entry["pipe"] for entry in endpoints if entry["bind_accepted"]]
    return {
        "null_session_possible": null_session_possible,
        "ipc_share_reachable": ipc_reachable,
        "rpc_endpoints": endpoints,
        "bindable_rpc_pipes": bindable,
    }
