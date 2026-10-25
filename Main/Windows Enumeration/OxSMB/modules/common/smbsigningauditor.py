from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb_negotiate import negotiate

MODULE_NAME = "smbsigningauditor"


def _classify_signing(signing_enabled: bool, signing_required: bool) -> str:
    if signing_required:
        return "required"
    if signing_enabled:
        return "enabled_not_required"
    return "disabled"


def _relay_verdict(signing_required: bool) -> str:
    if signing_required:
        return "not_vulnerable"
    return "vulnerable_to_smb_relay"


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    try:
        transport.connect()
        negotiate_result = negotiate(transport)
    except (OxSMBError, OSError) as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }
    finally:
        transport.close()

    signing_state = _classify_signing(
        negotiate_result.signing_enabled, negotiate_result.signing_required
    )
    relay_verdict = _relay_verdict(negotiate_result.signing_required)

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": {
            "signing_enabled": negotiate_result.signing_enabled,
            "signing_required": negotiate_result.signing_required,
            "signing_state": signing_state,
            "smb_relay_verdict": relay_verdict,
        },
        "error": None,
    }
