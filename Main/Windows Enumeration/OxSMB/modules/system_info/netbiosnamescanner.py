import os
import socket
import struct

MODULE_NAME = "netbiosnamescanner"

NBNS_PORT = 137
NBSTAT_QUERY_TYPE = 0x0021
IN_CLASS = 0x0001
GROUP_FLAG_BIT = 0x8000


def _encode_nbns_name(raw16: bytes) -> bytes:
    encoded = bytearray()
    for byte_value in raw16:
        encoded.append(0x41 + ((byte_value >> 4) & 0x0F))
        encoded.append(0x41 + (byte_value & 0x0F))
    return bytes([32]) + bytes(encoded) + b"\x00"


def _build_node_status_query(transaction_id: int) -> bytes:
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
    raw_name = b"*" + b"\x00" * 15
    question = _encode_nbns_name(raw_name) + struct.pack(">HH", NBSTAT_QUERY_TYPE, IN_CLASS)
    return header + question


def _skip_rr_name(data: bytes, offset: int) -> int:
    if data[offset] & 0xC0 == 0xC0:
        return offset + 2
    name_len = data[offset]
    offset += 1 + name_len
    if offset < len(data) and data[offset] == 0x00:
        offset += 1
    return offset


def _parse_node_status_response(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError("NBNS response too short")

    offset = _skip_rr_name(data, 12)
    offset += 8
    rdlength = struct.unpack_from(">H", data, offset)[0]
    offset += 2

    if rdlength <= 0 or offset >= len(data):
        return {"names": [], "mac_address": ""}

    num_names = data[offset]
    offset += 1

    names = []
    for _ in range(num_names):
        if offset + 18 > len(data):
            break
        raw_name = data[offset:offset + 15]
        suffix = data[offset + 15]
        name_flags = struct.unpack_from(">H", data, offset + 16)[0]
        names.append(
            {
                "name": raw_name.decode("ascii", errors="replace").rstrip(),
                "suffix": suffix,
                "is_group": bool(name_flags & GROUP_FLAG_BIT),
            }
        )
        offset += 18

    mac_address = ""
    if offset + 6 <= len(data):
        mac_bytes = data[offset:offset + 6]
        if any(mac_bytes):
            mac_address = ":".join(f"{b:02x}" for b in mac_bytes)

    return {"names": names, "mac_address": mac_address}


def _classify_names(names: list) -> dict:
    hostname = ""
    workgroup = ""
    for entry in names:
        if entry["suffix"] == 0x00 and not entry["is_group"] and not hostname:
            hostname = entry["name"]
        if entry["suffix"] == 0x00 and entry["is_group"] and not workgroup:
            workgroup = entry["name"]
    return {"hostname": hostname, "workgroup": workgroup}


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transaction_id = struct.unpack(">H", os.urandom(2))[0]
    query = _build_node_status_query(transaction_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(read_timeout)

    try:
        sock.sendto(query, (host, NBNS_PORT))
        response, _ = sock.recvfrom(2048)
    except socket.timeout:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": "Timeout waiting for NBNS response on UDP/137",
        }
    except OSError as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": f"NBNS query failed: {exc}",
        }
    finally:
        sock.close()

    try:
        parsed = _parse_node_status_response(response)
    except (ValueError, struct.error) as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": f"Failed to parse NBNS response: {exc}",
        }

    classified = _classify_names(parsed["names"])

    data = {
        "nbns_responded": True,
        "hostname": classified["hostname"],
        "workgroup_or_domain": classified["workgroup"],
        "mac_address": parsed["mac_address"],
        "registered_names": [
            "{0}<{1:02x}>{2}".format(
                entry["name"], entry["suffix"], " (group)" if entry["is_group"] else ""
            )
            for entry in parsed["names"]
        ],
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
