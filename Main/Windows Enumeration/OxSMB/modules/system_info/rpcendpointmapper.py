from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.epm import ept_lookup_all
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "rpcendpointmapper"

PIPE_NAME = "epmapper"


def _enumerate_endpoints(transport):
    with RPCChannel(transport, PIPE_NAME) as channel:
        return ept_lookup_all(channel)


def _entries_to_list(entries) -> list:
    return [
        {
            "interface_uuid": entry.interface_uuid,
            "annotation": entry.annotation,
            "tower_raw_hex": entry.tower_raw_hex,
        }
        for entry in entries
    ]


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    if credentials is not None and auth_session is not None and auth_session.authenticated:
        try:
            entries = _enumerate_endpoints(auth_session.transport)
        except (OxSMBError, OSError) as exc:
            return {
                "module": MODULE_NAME,
                "target": host,
                "status": "error",
                "data": None,
                "error": str(exc),
            }

        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": _build_data(entries),
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

        entries = _enumerate_endpoints(transport)
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
        "data": _build_data(entries),
        "error": None,
    }


def _build_data(entries) -> dict:
    endpoints = _entries_to_list(entries)
    return {
        "epmapper_reachable": True,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }
