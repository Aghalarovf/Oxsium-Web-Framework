from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.wkssvc import net_wksta_get_info_102
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "wkssvcinfogatherer"


def _query_wksta_info(transport, host: str):
    with RPCChannel(transport, "wkssvc") as channel:
        return net_wksta_get_info_102(channel, server_name=host)


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    # Reuse an already-authenticated shared session when the engine
    # established one for this target, instead of opening a second one.
    if credentials is not None and auth_session is not None and auth_session.authenticated:
        try:
            info = _query_wksta_info(auth_session.transport, host)
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
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    try:
        if credentials is not None and not credentials.is_null_session:
            session_setup(transport, credentials)
        else:
            null_session_setup(transport)

        info = _query_wksta_info(transport, host)
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
        "computer_name": info.computer_name,
        "domain_name": info.domain_name,
        "platform_id": info.platform_id,
        "platform_name": info.platform_name,
        "os_version": info.os_version,
        "os_version_major": info.version_major,
        "os_version_minor": info.version_minor,
        # [MS-WKST] 2.2.5.3: wki102_logged_on_users is the number of users
        # currently active on the computer. WKSTA_INFO_102 has no field
        # describing LAN channels; "logged_on_users" is the real field name.
        "logged_on_users": info.logged_on_users,
    }
