from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import tree_connect, tree_disconnect
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import session_setup

MODULE_NAME = "guestaccessprober"

GUEST_CREDENTIALS = Credentials(username="Guest", password="", domain="")

ADMIN_SHARES = ["ADMIN$", "C$", "IPC$"]


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    guest_access_allowed = False
    session_is_guest = False
    session_is_null = False
    accessible_shares = []

    if credentials is not None and auth_session is not None:
        if auth_session.authenticated:
            guest_access_allowed = True
            session_is_guest = auth_session.is_guest
            session_is_null = auth_session.is_null

            for share in ADMIN_SHARES:
                try:
                    tree_connect(auth_session.transport, f"\\\\{host}\\{share}")
                    accessible_shares.append(share)
                    try:
                        tree_disconnect(auth_session.transport)
                    except (OxSMBError, OSError):
                        pass
                except (OxSMBError, OSError):
                    pass
        else:
            guest_access_allowed = False

        data = {
            "guest_access_allowed": guest_access_allowed,
            "session_is_guest": session_is_guest,
            "session_is_null": session_is_null,
            "admin_shares_reachable": accessible_shares,
            "admin_share_access": bool(accessible_shares),
        }

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
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    auth_credentials = credentials if credentials is not None else GUEST_CREDENTIALS

    try:
        session_result = session_setup(transport, auth_credentials)
        guest_access_allowed = True
        session_is_guest = session_result.is_guest
        session_is_null = session_result.is_null

        for share in ADMIN_SHARES:
            try:
                tree_connect(transport, f"\\\\{host}\\{share}")
                accessible_shares.append(share)
            except (OxSMBError, OSError):
                pass
    except (OxSMBError, OSError):
        guest_access_allowed = False
    finally:
        transport.close()

    data = {
        "guest_access_allowed": guest_access_allowed,
        "session_is_guest": session_is_guest,
        "session_is_null": session_is_null,
        "admin_shares_reachable": accessible_shares,
        "admin_share_access": bool(accessible_shares),
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
