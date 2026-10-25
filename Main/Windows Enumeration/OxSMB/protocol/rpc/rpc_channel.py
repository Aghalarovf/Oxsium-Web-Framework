import struct
import uuid as uuidlib

from core.exceptions import RPCBindError, RPCCallError, SMBCreateError, SMBTreeConnectError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_bind import build_bind_request, parse_bind_ack
from protocol.rpc.rpc_constants import (
    MSRPC_PACKET_TYPE_FAULT,
    MSRPC_PACKET_TYPE_RESPONSE,
    MSRPC_PFC_FIRST_FRAG,
    MSRPC_PFC_LAST_FRAG,
    NAMED_PIPE_MAP,
)
from protocol.smb.smb_constants import (
    FILE_NON_DIRECTORY_FILE,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_OPEN,
    GENERIC_READ,
    GENERIC_WRITE,
    SMB2_COM_CLOSE,
    SMB2_COM_CREATE,
    SMB2_COM_READ,
    SMB2_COM_TREE_CONNECT,
    SMB2_COM_TREE_DISCONNECT,
    SMB2_COM_WRITE,
    SMB2_OPLOCK_LEVEL_NONE,
    STATUS_SUCCESS,
)
from protocol.rpc.rpc_bind import build_rpc_header
from protocol.rpc.rpc_constants import MSRPC_PACKET_TYPE_REQUEST
from protocol.smb.smb_packet_parser import build_smb2_header, split_header_and_body


def tree_connect(transport: SMBTransport, share_path: str) -> int:
    encoded_path = share_path.encode("utf-16-le")
    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_TREE_CONNECT, message_id=message_id, session_id=transport.session_id
    )
    path_offset = 64 + 8
    body = struct.pack("<HHHH", 9, 0, path_offset, len(encoded_path))
    request = header + body + encoded_path

    response = transport.send_and_recv(request)
    resp_header, resp_body = split_header_and_body(response)

    if resp_header.status != STATUS_SUCCESS:
        raise SMBTreeConnectError(f"Tree connect failed with status 0x{resp_header.status:08x}")

    transport.tree_id = resp_header.tree_id
    return resp_header.tree_id


def open_named_pipe(transport: SMBTransport, pipe_name: str) -> bytes:
    encoded_name = pipe_name.encode("utf-16-le")
    name_offset = 64 + 56

    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_CREATE,
        message_id=message_id,
        session_id=transport.session_id,
        tree_id=transport.tree_id,
    )

    body = struct.pack("<HBB", 57, 0, SMB2_OPLOCK_LEVEL_NONE)
    body += struct.pack("<I", 0)
    body += struct.pack("<Q", 0)
    body += struct.pack("<Q", 0)
    body += struct.pack("<I", GENERIC_READ | GENERIC_WRITE)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
    body += struct.pack("<I", FILE_OPEN)
    body += struct.pack("<I", FILE_NON_DIRECTORY_FILE)
    body += struct.pack("<HH", name_offset, len(encoded_name))
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)

    request = header + body + encoded_name
    response = transport.send_and_recv(request)
    resp_header, resp_body = split_header_and_body(response)

    if resp_header.status != STATUS_SUCCESS:
        raise SMBCreateError(f"Create on pipe '{pipe_name}' failed with status 0x{resp_header.status:08x}")

    file_id = resp_body[64:80] if len(resp_body) >= 80 else resp_body[-16:]
    return file_id


def close_handle(transport: SMBTransport, file_id: bytes):
    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_CLOSE,
        message_id=message_id,
        session_id=transport.session_id,
        tree_id=transport.tree_id,
    )
    body = struct.pack("<HHI", 24, 0, 0) + file_id
    request = header + body
    transport.send_and_recv(request)


def tree_disconnect(transport: SMBTransport):
    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_TREE_DISCONNECT,
        message_id=message_id,
        session_id=transport.session_id,
        tree_id=transport.tree_id,
    )
    body = struct.pack("<HH", 4, 0)
    request = header + body
    response = transport.send_and_recv(request)
    resp_header, _ = split_header_and_body(response)

    if resp_header.status != STATUS_SUCCESS:
        raise SMBTreeConnectError(f"Tree disconnect failed with status 0x{resp_header.status:08x}")

    transport.tree_id = 0


def pipe_write(transport: SMBTransport, file_id: bytes, data: bytes):
    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_WRITE,
        message_id=message_id,
        session_id=transport.session_id,
        tree_id=transport.tree_id,
    )
    data_offset = 64 + 48
    body = struct.pack("<HH", 49, data_offset)
    body += struct.pack("<I", len(data))
    body += struct.pack("<Q", 0)
    body += file_id
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)

    request = header + body + data
    response = transport.send_and_recv(request)
    resp_header, _ = split_header_and_body(response)
    if resp_header.status != STATUS_SUCCESS:
        raise RPCCallError(f"Pipe write failed with status 0x{resp_header.status:08x}")


def pipe_read(transport: SMBTransport, file_id: bytes, length: int = 0x00010000) -> bytes:
    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_READ,
        message_id=message_id,
        session_id=transport.session_id,
        tree_id=transport.tree_id,
    )
    body = struct.pack("<HB", 49, 0)
    body += struct.pack("<B", 0)
    body += struct.pack("<I", length)
    body += struct.pack("<Q", 0)
    body += file_id
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)
    body += struct.pack("<HH", 0, 0)
    body += b"\x00"

    request = header + body
    response = transport.send_and_recv(request)
    resp_header, resp_body = split_header_and_body(response)

    if resp_header.status != STATUS_SUCCESS:
        raise RPCCallError(f"Pipe read failed with status 0x{resp_header.status:08x}")

    structure_size, data_offset, reserved, data_length = struct.unpack_from("<HBBI", resp_body, 0)
    full_offset = data_offset - 64
    return resp_body[full_offset:full_offset + data_length]


class RPCChannel:
    def __init__(self, transport: SMBTransport, pipe_name: str):
        self.transport = transport
        self.pipe_name = pipe_name
        self.file_id = None
        self.call_id = 1
        self.bound = False
        self.tree_connected = False

    def open(self):
        tree_connect(self.transport, f"\\\\{self.transport.host}\\IPC$")
        self.tree_connected = True
        self.file_id = open_named_pipe(self.transport, self.pipe_name)

    def bind(self):
        if self.pipe_name not in NAMED_PIPE_MAP:
            raise RPCBindError(f"Unknown named pipe '{self.pipe_name}', no interface UUID mapped")

        interface_uuid, version, version_minor = NAMED_PIPE_MAP[self.pipe_name]
        bind_pdu = build_bind_request(interface_uuid, version, version_minor, call_id=self.call_id)

        pipe_write(self.transport, self.file_id, bind_pdu)
        response = pipe_read(self.transport, self.file_id)

        bind_ack = parse_bind_ack(response)
        if not bind_ack.accepted:
            raise RPCBindError(f"RPC bind rejected, reason code {bind_ack.reject_reason}")

        self.bound = True
        self.call_id += 1

    def call(self, opnum: int, stub_data: bytes) -> bytes:
        if not self.bound:
            raise RPCCallError("RPC channel is not bound, call bind() first")

        pfc_flags = MSRPC_PFC_FIRST_FRAG | MSRPC_PFC_LAST_FRAG
        body = struct.pack("<IHH", 0, 0, opnum) + stub_data
        total_length = 24 + len(body)
        header = build_rpc_header(MSRPC_PACKET_TYPE_REQUEST, pfc_flags, total_length, self.call_id)
        request_pdu = header[:16] + struct.pack("<I", len(stub_data)) + body

        self.call_id += 1
        pipe_write(self.transport, self.file_id, request_pdu)

        response = pipe_read(self.transport, self.file_id)
        return self._parse_response(response)

    def _parse_response(self, data: bytes) -> bytes:
        if len(data) < 24:
            raise RPCCallError("RPC response too short")
        packet_type = data[2]
        if packet_type == MSRPC_PACKET_TYPE_FAULT:
            status = struct.unpack_from("<I", data, 20)[0] if len(data) >= 24 else 0
            raise RPCCallError(f"RPC fault received, status 0x{status:08x}")
        if packet_type != MSRPC_PACKET_TYPE_RESPONSE:
            raise RPCCallError(f"Unexpected RPC packet type in response: {packet_type}")
        return data[24:]

    def close(self):
        if self.file_id is not None:
            try:
                close_handle(self.transport, self.file_id)
            except Exception:
                pass
            self.file_id = None

        if self.tree_connected:
            try:
                tree_disconnect(self.transport)
            except Exception:
                pass
            self.tree_connected = False

    def __enter__(self):
        self.open()
        self.bind()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
