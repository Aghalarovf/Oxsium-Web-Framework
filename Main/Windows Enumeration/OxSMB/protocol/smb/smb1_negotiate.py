import struct
from dataclasses import dataclass

from core.exceptions import PacketParseError
from protocol.smb.smb2_constants import SMB1_COM_NEGOTIATE, SMB1_SIGNATURE

SMB1_HEADER_LEN = 32
SMB1_LEGACY_DIALECT = "PC NETWORK PROGRAM 1.0"
SMB1_DIALECT_NOT_SELECTED = 0xFFFF


@dataclass
class SMB1NegotiateResult:
    responded_as_smb1: bool
    dialect_index: int
    dialect_selected: bool
    raw: bytes


def build_smb1_header(command: int, pid: int = 0, tid: int = 0, uid: int = 0, mid: int = 0) -> bytes:
    return struct.pack(
        "<4sBIBHH8sHHHHH",
        SMB1_SIGNATURE,
        command,
        0,
        0x18,
        0x0000,
        (pid >> 16) & 0xFFFF,
        b"\x00" * 8,
        0,
        tid,
        pid & 0xFFFF,
        uid,
        mid,
    )


def build_smb1_negotiate_request(mid: int = 0) -> bytes:
    header = build_smb1_header(command=SMB1_COM_NEGOTIATE, mid=mid)

    dialect_buffer = b"\x02" + SMB1_LEGACY_DIALECT.encode("ascii") + b"\x00"
    word_count = 0
    body = struct.pack("<B", word_count)
    body += struct.pack("<H", len(dialect_buffer))
    body += dialect_buffer

    return header + body


def parse_smb1_negotiate_response(data: bytes) -> SMB1NegotiateResult:
    if len(data) < 4 or data[0:4] != SMB1_SIGNATURE:
        return SMB1NegotiateResult(
            responded_as_smb1=False, dialect_index=SMB1_DIALECT_NOT_SELECTED, dialect_selected=False, raw=data
        )

    if len(data) < SMB1_HEADER_LEN + 1:
        raise PacketParseError("SMB1 negotiate response too short")

    word_count = data[SMB1_HEADER_LEN]
    if word_count < 1 or len(data) < SMB1_HEADER_LEN + 1 + 2:
        return SMB1NegotiateResult(
            responded_as_smb1=True, dialect_index=SMB1_DIALECT_NOT_SELECTED, dialect_selected=False, raw=data
        )

    dialect_index = struct.unpack("<H", data[SMB1_HEADER_LEN + 1:SMB1_HEADER_LEN + 3])[0]
    dialect_selected = dialect_index == 0

    return SMB1NegotiateResult(
        responded_as_smb1=True,
        dialect_index=dialect_index,
        dialect_selected=dialect_selected,
        raw=data,
    )
