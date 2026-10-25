from dataclasses import dataclass, field
from typing import List

from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb_constants import ALL_SMB2_DIALECTS, DIALECT_NAMES
from protocol.smb.smb_negotiate import negotiate, negotiate_single_dialect

MODULE_NAME = "smbdialectprober"


@dataclass
class DialectProbeResult:
    supported_dialects: List[str] = field(default_factory=list)
    unsupported_dialects: List[str] = field(default_factory=list)
    preferred_dialect: str = ""
    server_guid: str = ""


def _probe_single_dialect(host: str, port: int, dialect: int, connect_timeout: float, read_timeout: float) -> bool:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    try:
        transport.connect()
        negotiate_single_dialect(transport, dialect)
        return True
    except OxSMBError:
        return False
    except OSError:
        return False
    finally:
        transport.close()


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    result = DialectProbeResult()

    for dialect in ALL_SMB2_DIALECTS:
        dialect_name = DIALECT_NAMES.get(dialect, hex(dialect))
        if _probe_single_dialect(host, port, dialect, connect_timeout, read_timeout):
            result.supported_dialects.append(dialect_name)
        else:
            result.unsupported_dialects.append(dialect_name)

    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    negotiate_result = None
    try:
        transport.connect()
        negotiate_result = negotiate(transport)
    except (OxSMBError, OSError):
        negotiate_result = None
    finally:
        transport.close()

    if negotiate_result is not None:
        result.preferred_dialect = DIALECT_NAMES.get(
            negotiate_result.dialect_revision, hex(negotiate_result.dialect_revision)
        )
        result.server_guid = negotiate_result.server_guid.hex()

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": {
            "supported_dialects": result.supported_dialects,
            "unsupported_dialects": result.unsupported_dialects,
            "preferred_dialect": result.preferred_dialect,
            "server_guid": result.server_guid,
        },
        "error": None,
    }
