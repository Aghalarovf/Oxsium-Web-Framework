import struct
from dataclasses import dataclass
from typing import Optional

from core.exceptions import PacketParseError
from protocol.smb.smb_constants import SMB2_HEADER_LEN, SMB2_HEADER_SIGNATURE


@dataclass
class SMB2Header:
    protocol_id: bytes
    structure_size: int
    credit_charge: int
    status: int
    command: int
    credit_request_response: int
    flags: int
    next_command: int
    message_id: int
    process_id: int
    tree_id: int
    session_id: int
    signature: bytes


def build_smb2_header(
    command: int,
    message_id: int,
    tree_id: int = 0,
    session_id: int = 0,
    credit_charge: int = 1,
    credit_request: int = 1,
    flags: int = 0,
    next_command: int = 0,
    process_id: int = 0xFEFF,
    signature: bytes = b"\x00" * 16,
) -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        SMB2_HEADER_SIGNATURE,
        64,
        credit_charge,
        0,
        command,
        credit_request,
        flags,
        next_command,
        message_id,
        process_id,
        tree_id,
        session_id,
        signature,
    )


def parse_smb2_header(data: bytes) -> SMB2Header:
    if len(data) < SMB2_HEADER_LEN:
        raise PacketParseError("Buffer shorter than SMB2 header length")
    protocol_id = data[0:4]
    if protocol_id != SMB2_HEADER_SIGNATURE:
        raise PacketParseError(f"Invalid SMB2 protocol signature: {protocol_id!r}")
    (
        structure_size,
        credit_charge,
        status,
        command,
        credit_rr,
        flags,
        next_command,
        message_id,
    ) = struct.unpack("<HHIHHIIQ", data[4:32])
    process_id, tree_id = struct.unpack("<II", data[32:40])
    session_id = struct.unpack("<Q", data[40:48])[0]
    signature = data[48:64]
    return SMB2Header(
        protocol_id=protocol_id,
        structure_size=structure_size,
        credit_charge=credit_charge,
        status=status,
        command=command,
        credit_request_response=credit_rr,
        flags=flags,
        next_command=next_command,
        message_id=message_id,
        process_id=process_id,
        tree_id=tree_id,
        session_id=session_id,
        signature=signature,
    )


def split_header_and_body(data: bytes):
    header = parse_smb2_header(data)
    body = data[SMB2_HEADER_LEN:]
    return header, body


def is_smb2_response(data: bytes) -> bool:
    return len(data) >= 4 and data[0:4] == SMB2_HEADER_SIGNATURE


def read_netbios_frame(sock, timeout: Optional[float] = None) -> bytes:
    if timeout is not None:
        sock.settimeout(timeout)
    header = _recv_exact(sock, 4)
    length = struct.unpack(">I", header)[0] & 0x00FFFFFF
    body = _recv_exact(sock, length)
    return body


def wrap_netbios_frame(payload: bytes) -> bytes:
    length = len(payload)
    header = struct.pack(">I", length & 0x00FFFFFF)
    return header + payload


def _recv_exact(sock, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise PacketParseError("Connection closed before expected bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
