import struct

from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb2_constants import SMB2_NEGOTIATE_CONTEXT_COMPRESSION
from protocol.smb.smb_constants import SMB2_DIALECT_3_1_1
from protocol.smb.smb_negotiate import negotiate, parse_negotiate_contexts

MODULE_NAME = "smbghostchecker"

CVE_ID = "CVE-2020-0796"


def _parse_compression_context(context_data: bytes):
    if len(context_data) < 8:
        return None

    algorithm_count, _padding, _flags = struct.unpack_from("<HHI", context_data, 0)
    algorithms = []
    offset = 8
    for _ in range(algorithm_count):
        if offset + 2 > len(context_data):
            break
        algorithm = struct.unpack_from("<H", context_data, offset)[0]
        algorithms.append(algorithm)
        offset += 2
    return algorithms


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()
        result = negotiate(
            transport,
            dialects=[SMB2_DIALECT_3_1_1],
            include_compression_context=True,
        )
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

    negotiated_311 = result.dialect_revision == SMB2_DIALECT_3_1_1
    compression_negotiated = False
    compression_algorithms = []

    if negotiated_311 and result.negotiate_context_count > 0:
        contexts = parse_negotiate_contexts(
            result.raw_body, result.negotiate_context_offset, result.negotiate_context_count
        )
        for context_type, context_data in contexts:
            if context_type == SMB2_NEGOTIATE_CONTEXT_COMPRESSION:
                compression_negotiated = True
                compression_algorithms = _parse_compression_context(context_data) or []

    potentially_vulnerable = negotiated_311 and compression_negotiated

    data = {
        "cve_id": CVE_ID,
        "dialect_negotiated": hex(result.dialect_revision),
        "smb_3_1_1_supported": negotiated_311,
        "compression_capability_negotiated": compression_negotiated,
        "compression_algorithms_offered_by_server": compression_algorithms,
        "potentially_vulnerable": potentially_vulnerable,
        "note": (
            "Detection only: a host that negotiates SMB 3.1.1 compression meets the "
            "precondition for CVE-2020-0796. This check does not attempt exploitation, "
            "so it cannot confirm whether a patch for the decompression overflow is "
            "installed; treat a positive result as 'needs patch verification', not as "
            "confirmed exploitability."
        ),
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
