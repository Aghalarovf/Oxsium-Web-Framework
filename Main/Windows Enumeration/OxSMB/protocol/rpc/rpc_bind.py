import struct
from dataclasses import dataclass

from core.exceptions import RPCBindError
from protocol.rpc.ndr import uuid_to_bytes
from protocol.rpc.rpc_constants import (
    MSRPC_PACKET_TYPE_BIND,
    MSRPC_PACKET_TYPE_BIND_ACK,
    MSRPC_PACKET_TYPE_BIND_NAK,
    MSRPC_PFC_FIRST_FRAG,
    MSRPC_PFC_LAST_FRAG,
    NDR_TRANSFER_SYNTAX_UUID,
    NDR_TRANSFER_SYNTAX_VERSION,
)

RPC_VERSION_MAJOR = 5
RPC_VERSION_MINOR = 0


@dataclass
class BindAckResult:
    accepted: bool
    max_xmit_frag: int
    max_recv_frag: int
    assoc_group_id: int
    reject_reason: int = 0


def build_rpc_header(packet_type: int, pfc_flags: int, frag_length: int, call_id: int, auth_length: int = 0) -> bytes:
    return struct.pack(
        "<BBBBIHHI",
        RPC_VERSION_MAJOR,
        RPC_VERSION_MINOR,
        packet_type,
        pfc_flags,
        0x00000010,
        frag_length,
        auth_length,
        call_id,
    )


def build_bind_request(interface_uuid: str, interface_version: int, interface_version_minor: int, call_id: int = 1) -> bytes:
    context_id = 0
    num_trans_items = 1

    context_item = struct.pack("<HBB", context_id, num_trans_items, 0)
    context_item += uuid_to_bytes(interface_uuid)
    context_item += struct.pack("<HH", interface_version, interface_version_minor)
    context_item += uuid_to_bytes(NDR_TRANSFER_SYNTAX_UUID)
    context_item += struct.pack("<I", NDR_TRANSFER_SYNTAX_VERSION)

    body = struct.pack("<HHI", 4280, 4280, 0)
    body += struct.pack("<BBH", 1, 0, 0)
    body += context_item

    total_length = 16 + len(body)
    pfc_flags = MSRPC_PFC_FIRST_FRAG | MSRPC_PFC_LAST_FRAG
    header = build_rpc_header(MSRPC_PACKET_TYPE_BIND, pfc_flags, total_length, call_id)

    return header + body


def parse_bind_ack(data: bytes) -> BindAckResult:
    if len(data) < 16:
        raise RPCBindError("RPC bind response too short")

    packet_type = data[2]

    if packet_type == MSRPC_PACKET_TYPE_BIND_NAK:
        reject_reason = struct.unpack_from("<H", data, 16)[0] if len(data) >= 18 else 0
        return BindAckResult(
            accepted=False,
            max_xmit_frag=0,
            max_recv_frag=0,
            assoc_group_id=0,
            reject_reason=reject_reason,
        )

    if packet_type != MSRPC_PACKET_TYPE_BIND_ACK:
        raise RPCBindError(f"Unexpected RPC packet type in bind response: {packet_type}")

    max_xmit_frag, max_recv_frag, assoc_group_id = struct.unpack_from("<HHI", data, 16)

    offset = 24
    sec_addr_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2 + sec_addr_len
    padding = (-offset) % 4
    offset += padding

    num_results = data[offset] if offset < len(data) else 0
    offset += 4

    accepted = True
    reject_reason = 0
    if num_results >= 1 and offset + 4 <= len(data):
        result_code, reject_reason = struct.unpack_from("<HH", data, offset)
        accepted = result_code == 0
    elif num_results >= 1 and offset + 2 <= len(data):
        result_code = struct.unpack_from("<H", data, offset)[0]
        accepted = result_code == 0

    return BindAckResult(
        accepted=accepted,
        max_xmit_frag=max_xmit_frag,
        max_recv_frag=max_recv_frag,
        assoc_group_id=assoc_group_id,
        reject_reason=reject_reason,
    )
