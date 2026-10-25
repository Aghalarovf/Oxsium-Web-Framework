import struct
from dataclasses import dataclass

from core.exceptions import PacketParseError, SMBNegotiateError
from core.smb_transport import SMBTransport
from protocol.smb.smb2_constants import SMB1_SIGNATURE
from protocol.smb.smb1_negotiate import SMB1_HEADER_LEN

SMB1_COM_SESSION_SETUP_ANDX = 0x73
SMB1_COM_TREE_CONNECT_ANDX = 0x75
SMB1_COM_TRANSACTION = 0x25

SMB1_ANDX_NO_FURTHER = 0xFF

SMB1_FLAGS2_NT_STATUS = 0x4000

SMB1_CAP_STATUS32 = 0x00000040
SMB1_CAP_NT_SMBS = 0x00000010
SMB1_CAP_LARGE_FILES = 0x00000008

TRANS_PEEK_NMPIPE = 0x0023

STATUS_SUCCESS = 0x00000000
STATUS_INSUFF_SERVER_RESOURCES = 0xC000009A
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_INVALID_HANDLE = 0xC0000008


class SMB1PDUError(SMBNegotiateError):
    pass


@dataclass
class SMB1Header:
    command: int
    status: int
    flags: int
    flags2: int
    tid: int
    pid: int
    uid: int
    mid: int


def build_smb1_header_with_status(
    command: int, tid: int = 0, uid: int = 0, mid: int = 0, pid: int = 0
) -> bytes:
    return struct.pack(
        "<4sBIBHH8sHHHHH",
        SMB1_SIGNATURE,
        command,
        0,
        0x18,
        SMB1_FLAGS2_NT_STATUS,
        (pid >> 16) & 0xFFFF,
        b"\x00" * 8,
        0,
        tid,
        pid & 0xFFFF,
        uid,
        mid,
    )


def parse_smb1_header(data: bytes) -> SMB1Header:
    if len(data) < SMB1_HEADER_LEN or data[0:4] != SMB1_SIGNATURE:
        raise PacketParseError("Not a valid SMB1 response")

    (
        _signature,
        command,
        status,
        flags,
        flags2,
        _pid_high,
        _security,
        _reserved,
        tid,
        pid_low,
        uid,
        mid,
    ) = struct.unpack("<4sBIBHH8sHHHHH", data[0:SMB1_HEADER_LEN])

    return SMB1Header(
        command=command,
        status=status,
        flags=flags,
        flags2=flags2,
        tid=tid,
        pid=pid_low,
        uid=uid,
        mid=mid,
    )


def _build_session_setup_request(mid: int) -> bytes:
    header = build_smb1_header_with_status(SMB1_COM_SESSION_SETUP_ANDX, mid=mid)

    capabilities = SMB1_CAP_STATUS32 | SMB1_CAP_NT_SMBS | SMB1_CAP_LARGE_FILES

    params = struct.pack(
        "<BBBHHHHIHHII",
        13,
        SMB1_ANDX_NO_FURTHER,
        0,
        0,
        0xFFFF,
        2,
        1,
        0,
        1,
        0,
        0,
        capabilities,
    )

    data = b"\x00" + b"\x00" + b"\x00" + b"\x00" + b"\x00"
    body = params + struct.pack("<H", len(data)) + data

    return header + body


def session_setup_anonymous(transport: SMBTransport) -> SMB1Header:
    request = _build_session_setup_request(transport.next_message_id())
    response = transport.send_and_recv(request)
    header = parse_smb1_header(response)
    if header.status != STATUS_SUCCESS:
        raise SMB1PDUError(f"SMB1 anonymous session setup failed with NTSTATUS 0x{header.status:08x}")
    return header


def _build_tree_connect_request(mid: int, uid: int, unc_path: str) -> bytes:
    header = build_smb1_header_with_status(SMB1_COM_TREE_CONNECT_ANDX, uid=uid, mid=mid)

    params = struct.pack("<BBBHHH", 4, SMB1_ANDX_NO_FURTHER, 0, 0, 0, 1)

    path_bytes = unc_path.encode("ascii") + b"\x00"
    service_bytes = b"IPC\x00"
    data = b"\x00" + path_bytes + service_bytes
    body = params + struct.pack("<H", len(data)) + data

    return header + body


def tree_connect_ipc(transport: SMBTransport, uid: int) -> int:
    unc_path = f"\\\\{transport.host}\\IPC$"
    request = _build_tree_connect_request(transport.next_message_id(), uid, unc_path)
    response = transport.send_and_recv(request)
    header = parse_smb1_header(response)
    if header.status != STATUS_SUCCESS:
        raise SMB1PDUError(f"SMB1 tree connect to IPC$ failed with NTSTATUS 0x{header.status:08x}")
    return header.tid


def _build_peek_named_pipe_request(mid: int, uid: int, tid: int, fid: int) -> bytes:
    header = build_smb1_header_with_status(SMB1_COM_TRANSACTION, tid=tid, uid=uid, mid=mid)

    name = b"\\PIPE\\\x00"

    setup_count = 2
    word_count = 14 + setup_count

    body_relative_header_len = 1 + word_count * 2 + 2
    name_end = body_relative_header_len + len(name)
    pad = (-name_end) % 4
    parameter_offset = SMB1_HEADER_LEN + name_end + pad
    data_offset = parameter_offset

    params = struct.pack(
        "<HHHHBBHIHHHHHBB",
        0,
        0,
        2,
        0x0400,
        0,
        0,
        0,
        0,
        0,
        0,
        parameter_offset,
        0,
        data_offset,
        setup_count,
        0,
    )
    params += struct.pack("<HH", TRANS_PEEK_NMPIPE, fid)

    body_data = name + (b"\x00" * pad)
    body = params + struct.pack("<H", len(body_data)) + body_data

    return header + body


def peek_named_pipe_probe(transport: SMBTransport, uid: int, tid: int, fid: int = 0) -> int:
    request = _build_peek_named_pipe_request(transport.next_message_id(), uid, tid, fid)
    response = transport.send_and_recv(request)
    header = parse_smb1_header(response)
    return header.status
