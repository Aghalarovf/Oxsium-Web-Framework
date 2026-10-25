from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.srvsvc import net_remote_tod
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "systemtimereader"

PIPE_NAME = "srvsvc"

# Kerberos tolerates at most this many minutes of clock skew between
# client and KDC before authentication is rejected (MS-KILE default).
KERBEROS_SKEW_TOLERANCE_MINUTES = 5


def _query_remote_tod(transport, host: str):
    with RPCChannel(transport, PIPE_NAME) as channel:
        return net_remote_tod(channel, server_name=host)


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
            tod = _query_remote_tod(auth_session.transport, host)
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
            "data": _tod_to_dict(tod),
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

        tod = _query_remote_tod(transport, host)
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
        "data": _tod_to_dict(tod),
        "error": None,
    }


def _tod_to_dict(tod) -> dict:
    return {
        "remote_system_time": tod.remote_datetime,
        "timezone": tod.timezone_offset,
        "tick_interval_hundredths": tod.tick_interval,
        "elapsed_seconds": tod.elapsed_seconds,
        "kerberos_skew_tolerance_minutes": KERBEROS_SKEW_TOLERANCE_MINUTES,
    }
