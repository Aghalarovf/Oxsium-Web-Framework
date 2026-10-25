from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.srvsvc import net_server_get_info_101
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "computerdescriptionreader"

PIPE_NAME = "srvsvc"


def _query_server_info(transport, host: str):
    with RPCChannel(transport, PIPE_NAME) as channel:
        return net_server_get_info_101(channel, server_name=host)


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
            info = _query_server_info(auth_session.transport, host)
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
            "data": _info_to_dict(info),
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

        info = _query_server_info(transport, host)
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
        "data": _info_to_dict(info),
        "error": None,
    }


def _info_to_dict(info) -> dict:
    return {
        "server_name": info.name,
        "server_description": info.comment or None,
        "description_disclosed": bool(info.comment),
        "os_version": info.os_version,
        "platform_id": info.platform_id,
        "server_type_flags": info.server_type_flags,
    }
