from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import close_handle, open_named_pipe, tree_connect, tree_disconnect
from protocol.rpc.rpc_constants import NAME_ONLY_PIPES, NAMED_PIPE_MAP
from protocol.smb.smb_directory import list_directory_names, open_directory
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "namedpipeenumerator"

WELL_KNOWN_PIPES = sorted(set(list(NAMED_PIPE_MAP.keys()) + NAME_ONLY_PIPES))


def _probe_pipe(transport: SMBTransport, pipe_name: str) -> dict:
    entry = {"pipe": pipe_name, "open": False, "error": None}
    try:
        file_id = open_named_pipe(transport, pipe_name)
        entry["open"] = True
        close_handle(transport, file_id)
    except (OxSMBError, OSError) as exc:
        entry["error"] = str(exc)
    return entry


def _enumerate(transport: SMBTransport, host: str) -> dict:
    try:
        tree_connect(transport, f"\\\\{host}\\IPC$")
    except (OxSMBError, OSError):
        return _build_data(False, False, None, [], [])

    directory_listing_supported = False
    directory_listing_error = None
    listed_names = []

    try:
        file_id = open_directory(transport, "")
        try:
            listed_names = list_directory_names(transport, file_id)
            directory_listing_supported = True
        finally:
            close_handle(transport, file_id)
    except (OxSMBError, OSError) as exc:
        directory_listing_error = str(exc)

    probed = [_probe_pipe(transport, pipe_name) for pipe_name in WELL_KNOWN_PIPES]

    try:
        tree_disconnect(transport)
    except (OxSMBError, OSError):
        pass

    return _build_data(True, directory_listing_supported, directory_listing_error, listed_names, probed)


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    if credentials is not None and auth_session is not None and auth_session.authenticated:
        data = _enumerate(auth_session.transport, host)
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": data,
            "error": None,
        }

    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()
        negotiate(transport)

        if credentials is not None and not credentials.is_null_session:
            session_setup(transport, credentials)
        else:
            null_session_setup(transport)

        data = _enumerate(transport, host)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    transport.close()

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }


def _build_data(
    ipc_share_reachable: bool,
    directory_listing_supported: bool,
    directory_listing_error,
    listed_names: list,
    probed: list,
) -> dict:
    open_pipes = sorted({entry["pipe"] for entry in probed if entry["open"]} | set(listed_names))
    return {
        "ipc_share_reachable": ipc_share_reachable,
        "directory_listing_supported": directory_listing_supported,
        "directory_listing_error": directory_listing_error,
        "pipes_from_directory_listing": listed_names,
        "well_known_pipes_probed": probed,
        "open_named_pipes": open_pipes,
    }
