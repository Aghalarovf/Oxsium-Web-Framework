from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb1_negotiate import build_smb1_negotiate_request, parse_smb1_negotiate_response

MODULE_NAME = "smbv1detector"


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()
    except (OxSMBError, OSError) as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    try:
        request = build_smb1_negotiate_request(mid=transport.next_message_id())
        response = transport.send_and_recv(request)
        result = parse_smb1_negotiate_response(response)
        smb1_enabled = result.responded_as_smb1 and result.dialect_selected
    except (OxSMBError, OSError):
        smb1_enabled = False
    finally:
        transport.close()

    data = {
        "smb1_enabled": smb1_enabled,
        "probed_dialect": "PC NETWORK PROGRAM 1.0",
        "eternalblue_wannacry_precondition": "met" if smb1_enabled else "not_met",
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
