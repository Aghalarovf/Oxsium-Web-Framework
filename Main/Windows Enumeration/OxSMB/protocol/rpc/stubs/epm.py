import struct
from dataclasses import dataclass
from typing import List

from core.exceptions import NDRError, RPCCallError
from protocol.rpc.ndr import NDRReader, NDRWriter
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.rpc_constants import EPT_LOOKUP, EPT_MAX_ANNOTATION_SIZE, RPC_C_EP_ALL_ELTS, RPC_C_VERS_ALL

NULL_ENTRY_HANDLE = b"\x00" * 20


@dataclass
class EptEntry:
    interface_uuid: str
    annotation: str
    tower_raw_hex: str


def _format_uuid(raw16: bytes) -> str:
    data1, data2, data3 = struct.unpack_from("<IHH", raw16, 0)
    data4 = raw16[8:16]
    return (
        f"{data1:08x}-{data2:04x}-{data3:04x}-"
        f"{data4[0]:02x}{data4[1]:02x}-"
        f"{data4[2]:02x}{data4[3]:02x}{data4[4]:02x}{data4[5]:02x}{data4[6]:02x}{data4[7]:02x}"
    )


def _build_ept_lookup_request(entry_handle: bytes, max_ents: int) -> bytes:
    writer = NDRWriter()
    writer.uint32(RPC_C_EP_ALL_ELTS)
    writer.uint32(0)
    writer.uint32(0)
    writer.uint32(RPC_C_VERS_ALL)
    writer.raw(entry_handle)
    writer.uint32(max_ents)
    return writer.getvalue()


def _parse_ept_lookup_response(data: bytes):
    reader = NDRReader(data)
    next_entry_handle = reader.raw(20)
    num_ents = reader.uint32()

    entries: List[EptEntry] = []
    if num_ents:
        reader.uint32()
        reader.uint32()
        actual_count = reader.uint32()

        fixed_parts = []
        for _ in range(actual_count):
            object_uuid = reader.raw(16)
            tower_referent = reader.uint32()
            annotation_raw = reader.raw(EPT_MAX_ANNOTATION_SIZE)
            fixed_parts.append((object_uuid, tower_referent, annotation_raw))

        for object_uuid, tower_referent, annotation_raw in fixed_parts:
            tower_hex = ""
            if tower_referent != 0:
                tower_length = reader.uint32()
                reader.uint32()
                tower_bytes = reader.raw(tower_length)
                reader.align(4)
                tower_hex = tower_bytes.hex()

            annotation = annotation_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            entries.append(
                EptEntry(
                    interface_uuid=_format_uuid(object_uuid),
                    annotation=annotation,
                    tower_raw_hex=tower_hex,
                )
            )

    status = reader.uint32()
    return next_entry_handle, num_ents, entries, status


def ept_lookup_all(channel: RPCChannel, max_ents: int = 500, max_iterations: int = 64, max_total_entries: int = 4096) -> list:
    entry_handle = NULL_ENTRY_HANDLE
    collected: List[EptEntry] = []

    for _ in range(max_iterations):
        request_stub = _build_ept_lookup_request(entry_handle, max_ents)
        response_stub = channel.call(EPT_LOOKUP, request_stub)

        try:
            entry_handle, num_ents, entries, status = _parse_ept_lookup_response(response_stub)
        except NDRError as exc:
            if collected:
                break
            raise RPCCallError(f"Failed to parse ept_lookup response: {exc}") from exc

        if num_ents == 0:
            break

        collected.extend(entries)

        if status != 0 or entry_handle == NULL_ENTRY_HANDLE or len(collected) >= max_total_entries:
            break

    return collected
