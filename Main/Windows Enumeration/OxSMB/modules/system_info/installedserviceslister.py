from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.svcctl import (
    SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE,
    close_service_handle,
    enum_services_status_ex,
    open_scm,
)
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "installedserviceslister"

PIPE_NAME = "svcctl"

SC_MANAGER_ACCESS = SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE


def _enumerate_services(transport):
    with RPCChannel(transport, PIPE_NAME) as channel:
        scm_handle = open_scm(channel, desired_access=SC_MANAGER_ACCESS)
        try:
            return enum_services_status_ex(channel, scm_handle)
        finally:
            close_service_handle(channel, scm_handle)


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
            services = _enumerate_services(auth_session.transport)
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
            "data": _build_data(services),
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

        services = _enumerate_services(transport)
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
        "data": _build_data(services),
        "error": None,
    }


def _build_data(services) -> dict:
    return {
        "service_count": len(services),
        "services": [
            {
                "service_name": svc.service_name,
                "display_name": svc.display_name,
                "state": svc.state_name,
                "process_id": svc.process_id or None,
            }
            for svc in services
        ],
    }
