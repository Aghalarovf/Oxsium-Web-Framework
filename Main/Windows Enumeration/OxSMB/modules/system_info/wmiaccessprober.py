from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.epm import ept_lookup_all
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "wmiaccessprober"

PIPE_NAME = "epmapper"

WMI_INTERFACE_UUIDS = {
    "8bc3f05e-d86b-11d0-a075-00c04fb68820": "IWbemLevel1Login",
    "f309ad18-d86a-11d0-a075-00c04fb68820": "IWbemLoginClientID",
    "9ad05965-8b89-11d1-ad09-00c04fd8fdff": "IWbemLoginHelper",
}

DCOM_NOTE = (
    "This probe checks whether the WMI DCOM interfaces are registered on the "
    "target's RPC endpoint mapper (reached here over the SMB named-pipe epmapper "
    "transport). It does not perform a full DCOM activation / IWbemServices::ExecQuery, "
    "which requires a separate ncacn_ip_tcp (TCP/135 + dynamic port) transport that this "
    "tool does not implement. A positive result is a strong signal that WMI is exposed for "
    "remote/lateral-movement use (e.g. wmic, Impacket wmiexec); a negative result is weaker "
    "evidence of the opposite, since some endpoints are only resolvable via a targeted "
    "ept_map lookup rather than a full ept_lookup enumeration."
)


def _probe_wmi_endpoints(transport):
    with RPCChannel(transport, PIPE_NAME) as channel:
        return ept_lookup_all(channel)


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
            entries = _probe_wmi_endpoints(auth_session.transport)
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

        entries = _probe_wmi_endpoints(transport)
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
    matched = []
    for entry in entries:
        interface_name = WMI_INTERFACE_UUIDS.get(entry.interface_uuid.lower())
        if interface_name is None:
            continue
        matched.append(
            {
                "interface_name": interface_name,
                "interface_uuid": entry.interface_uuid,
                "annotation": entry.annotation,
            }
        )

    return {
        "wmi_remotely_accessible": bool(matched),
        "matched_interfaces": matched,
        "endpoints_scanned": len(entries),
        "note": DCOM_NOTE,
    }
