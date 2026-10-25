import os
import struct
import uuid
from dataclasses import dataclass, field
from typing import List

from core.exceptions import SMBNegotiateError
from core.smb_transport import SMBTransport
from protocol.smb.smb_constants import (
    ALL_SMB2_DIALECTS,
    SMB2_COM_NEGOTIATE,
    SMB2_DIALECT_3_1_1,
    SMB2_GLOBAL_CAP_DFS,
    SMB2_GLOBAL_CAP_LARGE_MTU,
    SMB2_HEADER_LEN,
    STATUS_SUCCESS,
)
from protocol.smb.smb2_constants import (
    HASH_ALGO_SHA512,
    OFFERED_COMPRESSION_ALGORITHMS,
    SMB2_NEGOTIATE_CONTEXT_COMPRESSION,
    SMB2_NEGOTIATE_CONTEXT_PREAUTH_INTEGRITY,
)
from protocol.smb.smb_packet_parser import build_smb2_header, split_header_and_body


@dataclass
class NegotiateResult:
    status: int
    dialect_revision: int
    security_mode: int
    server_guid: bytes
    capabilities: int
    max_transact_size: int
    max_read_size: int
    max_write_size: int
    signing_enabled: bool
    signing_required: bool
    negotiate_context_count: int = 0
    negotiate_context_offset: int = 0
    raw_body: bytes = field(repr=False, default=b"")


def _build_preauth_integrity_context() -> bytes:
    salt = os.urandom(32)
    context_data = struct.pack("<HH", 1, len(salt))
    context_data += struct.pack("<H", HASH_ALGO_SHA512)
    context_data += salt

    pad_len = (-len(context_data)) % 8
    context_data += b"\x00" * pad_len

    context_entry = struct.pack(
        "<HHI", SMB2_NEGOTIATE_CONTEXT_PREAUTH_INTEGRITY, len(context_data) - pad_len, 0
    )
    context_entry += context_data
    return context_entry


def _build_compression_context() -> bytes:
    algorithms = OFFERED_COMPRESSION_ALGORITHMS
    context_data = struct.pack("<HHI", len(algorithms), 0, 0)
    for algorithm in algorithms:
        context_data += struct.pack("<H", algorithm)

    pad_len = (-len(context_data)) % 8
    context_data += b"\x00" * pad_len

    context_entry = struct.pack(
        "<HHI", SMB2_NEGOTIATE_CONTEXT_COMPRESSION, len(context_data) - pad_len, 0
    )
    context_entry += context_data
    return context_entry


def build_negotiate_request(
    message_id: int,
    dialects: List[int] = None,
    client_guid: bytes = None,
    include_compression_context: bool = False,
) -> bytes:
    dialects = dialects or ALL_SMB2_DIALECTS
    client_guid = client_guid or uuid.uuid4().bytes

    header = build_smb2_header(command=SMB2_COM_NEGOTIATE, message_id=message_id)

    dialect_count = len(dialects)
    security_mode = 0x0001
    reserved = 0
    capabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LARGE_MTU

    dialects_bytes = b"".join(struct.pack("<H", dialect) for dialect in dialects)
    includes_311 = SMB2_DIALECT_3_1_1 in dialects

    if includes_311:
        fixed_part_len = 36
        dialects_offset = 64 + fixed_part_len
        dialects_end = dialects_offset + len(dialects_bytes)
        padding_len = (-dialects_end) % 8
        context_offset = dialects_end + padding_len

        negotiate_context_list = _build_preauth_integrity_context()
        negotiate_context_count = 1
        if include_compression_context:
            negotiate_context_list += _build_compression_context()
            negotiate_context_count = 2

        body = struct.pack("<HHHH", 36, dialect_count, security_mode, reserved)
        body += struct.pack("<I", capabilities)
        body += client_guid
        body += struct.pack("<IHH", context_offset, negotiate_context_count, 0)
        body += dialects_bytes
        body += b"\x00" * padding_len
        body += negotiate_context_list
    else:
        body = struct.pack("<HHHH", 36, dialect_count, security_mode, reserved)
        body += struct.pack("<I", capabilities)
        body += client_guid
        body += struct.pack("<Q", 0)
        body += dialects_bytes

    return header + body


def parse_negotiate_response(data: bytes) -> NegotiateResult:
    header, body = split_header_and_body(data)
    if len(body) < 64:
        raise SMBNegotiateError("Negotiate response body too short")

    (
        structure_size,
        security_mode,
        dialect_revision,
    ) = struct.unpack("<HHH", body[0:6])
    negotiate_context_count = struct.unpack("<H", body[6:8])[0]
    server_guid = body[8:24]
    capabilities = struct.unpack("<I", body[24:28])[0]
    max_transact_size = struct.unpack("<I", body[28:32])[0]
    max_read_size = struct.unpack("<I", body[32:36])[0]
    max_write_size = struct.unpack("<I", body[36:40])[0]

    signing_enabled = bool(security_mode & 0x0001)
    signing_required = bool(security_mode & 0x0002)

    negotiate_context_offset = 0
    if dialect_revision == SMB2_DIALECT_3_1_1 and len(body) >= 64:
        negotiate_context_offset = struct.unpack("<I", body[60:64])[0]

    return NegotiateResult(
        status=header.status,
        dialect_revision=dialect_revision,
        security_mode=security_mode,
        server_guid=server_guid,
        capabilities=capabilities,
        max_transact_size=max_transact_size,
        max_read_size=max_read_size,
        max_write_size=max_write_size,
        signing_enabled=signing_enabled,
        signing_required=signing_required,
        negotiate_context_count=negotiate_context_count,
        negotiate_context_offset=negotiate_context_offset,
        raw_body=body,
    )


def parse_negotiate_contexts(raw_body: bytes, context_offset: int, context_count: int) -> List[tuple]:
    contexts = []
    offset = context_offset - SMB2_HEADER_LEN

    for _ in range(context_count):
        if offset < 0 or offset + 8 > len(raw_body):
            break

        context_type, data_length = struct.unpack("<HH", raw_body[offset:offset + 4])
        data_start = offset + 8
        data_end = data_start + data_length
        if data_end > len(raw_body):
            break

        contexts.append((context_type, raw_body[data_start:data_end]))

        consumed = 8 + data_length
        offset += consumed + ((-consumed) % 8)

    return contexts


def negotiate(
    transport: SMBTransport,
    dialects: List[int] = None,
    include_compression_context: bool = False,
) -> NegotiateResult:
    message_id = transport.next_message_id()
    request = build_negotiate_request(
        message_id, dialects=dialects, include_compression_context=include_compression_context
    )
    transport.update_preauth_hash(request)
    response = transport.send_and_recv(request)
    transport.update_preauth_hash(response)
    result = parse_negotiate_response(response)

    if result.status != STATUS_SUCCESS:
        raise SMBNegotiateError(f"Negotiate failed with status 0x{result.status:08x}")

    transport.negotiated_dialect = result.dialect_revision
    transport.max_transact_size = result.max_transact_size
    transport.max_read_size = result.max_read_size
    transport.max_write_size = result.max_write_size
    transport.security_mode = result.security_mode
    transport.server_guid = result.server_guid
    transport.server_capabilities = result.capabilities
    transport.signing_enabled = result.signing_enabled
    transport.signing_required = result.signing_required

    return result


def negotiate_single_dialect(transport: SMBTransport, dialect: int) -> NegotiateResult:
    return negotiate(transport, dialects=[dialect])
