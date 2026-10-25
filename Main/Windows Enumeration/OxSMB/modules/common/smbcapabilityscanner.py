import struct

from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb2_constants import (
    COMPRESSION_ALGORITHM_NAMES,
    SMB2_NEGOTIATE_CONTEXT_COMPRESSION,
)
from protocol.smb.smb_constants import (
    ALL_SMB2_DIALECTS,
    DIALECT_NAMES,
    SMB2_DIALECT_3_1_1,
    SMB2_GLOBAL_CAP_DFS,
    SMB2_GLOBAL_CAP_DIRECTORY_LEASING,
    SMB2_GLOBAL_CAP_ENCRYPTION,
    SMB2_GLOBAL_CAP_LEASING,
    SMB2_GLOBAL_CAP_MULTI_CHANNEL,
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES,
)
from protocol.smb.smb_negotiate import negotiate, parse_negotiate_contexts

MODULE_NAME = "smbcapabilityscanner"


def _parse_compression_algorithms(context_data: bytes) -> list:
    # SMB2_COMPRESSION_CAPABILITIES: CompressionAlgorithmCount(2), Padding(2), Flags(4), Algorithms[](2 each)
    if len(context_data) < 8:
        return []

    algorithm_count = struct.unpack("<H", context_data[0:2])[0]
    algorithms_end = 8 + (algorithm_count * 2)
    if len(context_data) < algorithms_end:
        return []

    raw_algorithms = struct.unpack(f"<{algorithm_count}H", context_data[8:algorithms_end])
    return [COMPRESSION_ALGORITHM_NAMES.get(algorithm, f"unknown(0x{algorithm:04x})") for algorithm in raw_algorithms]


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    try:
        transport.connect()
        negotiate_result = negotiate(
            transport, dialects=ALL_SMB2_DIALECTS, include_compression_context=True
        )
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

    capabilities = negotiate_result.capabilities

    compression_supported = False
    compression_algorithms = []
    if (
        negotiate_result.dialect_revision == SMB2_DIALECT_3_1_1
        and negotiate_result.negotiate_context_count
    ):
        contexts = parse_negotiate_contexts(
            negotiate_result.raw_body,
            negotiate_result.negotiate_context_offset,
            negotiate_result.negotiate_context_count,
        )
        for context_type, context_data in contexts:
            if context_type == SMB2_NEGOTIATE_CONTEXT_COMPRESSION:
                compression_algorithms = _parse_compression_algorithms(context_data)
                compression_supported = len(compression_algorithms) > 0

    data = {
        "negotiated_dialect": DIALECT_NAMES.get(
            negotiate_result.dialect_revision, hex(negotiate_result.dialect_revision)
        ),
        "encryption_supported": bool(capabilities & SMB2_GLOBAL_CAP_ENCRYPTION),
        "multichannel_supported": bool(capabilities & SMB2_GLOBAL_CAP_MULTI_CHANNEL),
        "compression_supported": compression_supported,
        "compression_algorithms": compression_algorithms,
        "dfs_supported": bool(capabilities & SMB2_GLOBAL_CAP_DFS),
        "leasing_supported": bool(capabilities & SMB2_GLOBAL_CAP_LEASING),
        "directory_leasing_supported": bool(capabilities & SMB2_GLOBAL_CAP_DIRECTORY_LEASING),
        "persistent_handles_supported": bool(capabilities & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES),
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
