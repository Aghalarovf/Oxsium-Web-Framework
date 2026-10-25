from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb_constants import (
    SMB2_DIALECT_3_0,
    SMB2_GLOBAL_CAP_ENCRYPTION,
    SMB2_SESSION_FLAG_ENCRYPT_DATA,
)
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "smbencryptionchecker"


def _classify_encryption(encryption_supported: bool, encryption_required: bool) -> str:
    if encryption_required:
        return "required"
    if encryption_supported:
        return "supported_not_required"
    return "not_supported"


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
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

    if negotiate_result.dialect_revision < SMB2_DIALECT_3_0:
        data = {
            "negotiated_dialect": hex(negotiate_result.dialect_revision),
            "encryption_supported": False,
            "encryption_required": False,
            "encryption_state": "not_applicable",
        }
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": data,
            "error": None,
        }

    encryption_supported = bool(negotiate_result.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION)

    encryption_required = False
    required_check_error = None
    if encryption_supported:
        if credentials is not None and not credentials.is_null_session and auth_session is not None:
            if auth_session.authenticated:
                encryption_required = bool(
                    auth_session.session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA
                )
            else:
                required_check_error = auth_session.error
        else:
            probe_transport = SMBTransport(
                host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout
            )
            try:
                probe_transport.connect()
                negotiate(probe_transport)
                if credentials is not None and not credentials.is_null_session:
                    session_result = session_setup(probe_transport, credentials)
                else:
                    session_result = null_session_setup(probe_transport)
                encryption_required = bool(
                    session_result.session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA
                )
            except (OxSMBError, OSError) as exc:
                required_check_error = str(exc)
            finally:
                probe_transport.close()

    encryption_state = _classify_encryption(encryption_supported, encryption_required)

    data = {
        "negotiated_dialect": "SMB 3.x" if negotiate_result.dialect_revision >= SMB2_DIALECT_3_0 else hex(
            negotiate_result.dialect_revision
        ),
        "encryption_supported": encryption_supported,
        "encryption_required": encryption_required,
        "encryption_state": encryption_state,
        "required_check_error": required_check_error,
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
