from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb1_ms17010_probe import (
    STATUS_ACCESS_DENIED,
    STATUS_INSUFF_SERVER_RESOURCES,
    STATUS_INVALID_HANDLE,
    peek_named_pipe_probe,
    session_setup_anonymous,
    tree_connect_ipc,
)
from protocol.smb.smb1_negotiate import build_smb1_negotiate_request, parse_smb1_negotiate_response

MODULE_NAME = "eternalbluechecker"

CVE_ID = "CVE-2017-0144"
MS_ADVISORY = "MS17-010"

VERDICT_VULNERABLE = "vulnerable"
VERDICT_PATCHED = "patched"
VERDICT_UNKNOWN = "unknown"
VERDICT_NOT_APPLICABLE = "not_applicable"

STATUS_VERDICT_NAMES = {
    STATUS_INSUFF_SERVER_RESOURCES: VERDICT_VULNERABLE,
    STATUS_ACCESS_DENIED: VERDICT_PATCHED,
    STATUS_INVALID_HANDLE: VERDICT_PATCHED,
}


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()

        negotiate_request = build_smb1_negotiate_request(mid=transport.next_message_id())
        negotiate_response = transport.send_and_recv(negotiate_request)
        negotiate_result = parse_smb1_negotiate_response(negotiate_response)

        if not negotiate_result.responded_as_smb1 or not negotiate_result.dialect_selected:
            transport.close()
            return {
                "module": MODULE_NAME,
                "target": host,
                "status": "ok",
                "data": {
                    "cve_id": CVE_ID,
                    "advisory": MS_ADVISORY,
                    "smb1_enabled": False,
                    "probe_sent": False,
                    "ntstatus": None,
                    "verdict": VERDICT_PATCHED,
                    "note": "SMBv1 is disabled or not selected by the server, so the MS17-010 "
                    "precondition is not met.",
                },
                "error": None,
            }

        session_header = session_setup_anonymous(transport)
        tree_id = tree_connect_ipc(transport, session_header.uid)
        ntstatus = peek_named_pipe_probe(transport, session_header.uid, tree_id, fid=0)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": {
                "cve_id": CVE_ID,
                "advisory": MS_ADVISORY,
                "smb1_enabled": None,
                "probe_sent": False,
                "ntstatus": None,
                "verdict": VERDICT_NOT_APPLICABLE,
                "note": "Detection only: the SMB connection/negotiation could not be completed "
                f"({exc}), so the MS17-010 PeekNamedPipe probe was never sent and no verdict on "
                "CVE-2017-0144 could be established for this target.",
            },
            "error": None,
        }

    transport.close()

    verdict = STATUS_VERDICT_NAMES.get(ntstatus, VERDICT_UNKNOWN)

    data = {
        "cve_id": CVE_ID,
        "advisory": MS_ADVISORY,
        "smb1_enabled": True,
        "probe_sent": True,
        "ntstatus": f"0x{ntstatus:08x}",
        "verdict": verdict,
        "note": (
            "Detection only: a crafted SMB_COM_TRANSACTION PeekNamedPipe request is sent "
            "against an invalid FID on IPC$ and the server's NTSTATUS response is inspected. "
            "STATUS_INSUFF_SERVER_RESOURCES indicates the MS17-010 kernel pool overflow is "
            "unpatched; STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE indicate the patch is "
            "present. No exploit payload is sent and no memory corruption is triggered."
        ),
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }