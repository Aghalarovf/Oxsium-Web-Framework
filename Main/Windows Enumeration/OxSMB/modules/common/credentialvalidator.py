from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb_constants import STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE, STATUS_SUCCESS
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import probe_authentication_status

MODULE_NAME = "credentialvalidator"

STATUS_ACCOUNT_DISABLED = 0xC0000072
STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234
STATUS_PASSWORD_EXPIRED = 0xC0000071
STATUS_PASSWORD_MUST_CHANGE = 0xC0000224
STATUS_ACCOUNT_EXPIRED = 0xC0000193
STATUS_INVALID_LOGON_HOURS = 0xC000006F
STATUS_INVALID_WORKSTATION = 0xC0000070

STATUS_LABELS = {
    STATUS_SUCCESS: "valid",
    STATUS_LOGON_FAILURE: "invalid_credentials",
    STATUS_ACCESS_DENIED: "access_denied",
    STATUS_ACCOUNT_DISABLED: "account_disabled",
    STATUS_ACCOUNT_LOCKED_OUT: "account_locked_out",
    STATUS_PASSWORD_EXPIRED: "password_expired",
    STATUS_PASSWORD_MUST_CHANGE: "password_must_change",
    STATUS_ACCOUNT_EXPIRED: "account_expired",
    STATUS_INVALID_LOGON_HOURS: "invalid_logon_hours",
    STATUS_INVALID_WORKSTATION: "invalid_workstation",
}


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    if credentials is None or credentials.is_anonymous:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": {
                "credentials_provided": False,
                "credentials_valid": None,
                "verdict": "no_credentials_supplied",
                "raw_status": None,
            },
            "error": None,
        }

    if auth_session is not None:
        if not auth_session.authenticated:
            raw_status = auth_session.raw_status
            if raw_status is None:
                return {
                    "module": MODULE_NAME,
                    "target": host,
                    "status": "error",
                    "data": None,
                    "error": auth_session.error,
                }
        else:
            raw_status = STATUS_SUCCESS
    else:
        transport = SMBTransport(
            host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout
        )

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
            raw_status = probe_authentication_status(transport, credentials)
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

    verdict = STATUS_LABELS.get(raw_status, f"unknown(0x{raw_status:08x})")
    credentials_valid = raw_status == STATUS_SUCCESS

    data = {
        "credentials_provided": True,
        "username": credentials.username,
        "domain": credentials.domain,
        "auth_method": "ntlm_hash" if credentials.uses_hash else "password",
        "credentials_valid": credentials_valid,
        "verdict": verdict,
        "raw_status": f"0x{raw_status:08x}",
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
