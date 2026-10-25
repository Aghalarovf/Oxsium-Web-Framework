import struct

from core.exceptions import SMBCreateError, SMBReadWriteError
from core.smb_transport import SMBTransport
from protocol.smb.smb_constants import (
    FILE_DIRECTORY_FILE,
    FILE_NAMES_INFORMATION_CLASS,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_OPEN,
    GENERIC_READ,
    SMB2_COM_CREATE,
    SMB2_COM_QUERY_DIRECTORY,
    SMB2_OPLOCK_LEVEL_NONE,
    SMB2_RESTART_SCANS,
    STATUS_NO_MORE_FILES,
    STATUS_SUCCESS,
)
from protocol.smb.smb_packet_parser import build_smb2_header, split_header_and_body


def open_directory(transport: SMBTransport, path: str = "") -> bytes:
    encoded_name = path.encode("utf-16-le")
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
    body += struct.pack("<I", GENERIC_READ)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
    body += struct.pack("<I", FILE_OPEN)
    body += struct.pack("<I", FILE_DIRECTORY_FILE)
    body += struct.pack("<HH", name_offset, len(encoded_name))
    body += struct.pack("<I", 0)
    body += struct.pack("<Q", 0)

    request = header + body + encoded_name
    response = transport.send_and_recv(request)
    resp_header, resp_body = split_header_and_body(response)

    if resp_header.status != STATUS_SUCCESS:
        raise SMBCreateError(f"Directory open on '{path or chr(92) + chr(92)}' failed with status 0x{resp_header.status:08x}")

    file_id = resp_body[64:80] if len(resp_body) >= 80 else resp_body[-16:]
    return file_id


def _query_directory_once(transport: SMBTransport, file_id: bytes, restart: bool, pattern: str = "*"):
    encoded_pattern = pattern.encode("utf-16-le")
    name_offset = 64 + 32

    message_id = transport.next_message_id()
    header = build_smb2_header(
        command=SMB2_COM_QUERY_DIRECTORY,
        message_id=message_id,
        session_id=transport.session_id,
        tree_id=transport.tree_id,
    )

    flags = SMB2_RESTART_SCANS if restart else 0
    body = struct.pack("<HBB", 33, FILE_NAMES_INFORMATION_CLASS, flags)
    body += struct.pack("<I", 0)
    body += file_id
    body += struct.pack("<HH", name_offset, len(encoded_pattern))
    body += struct.pack("<I", 65536)

    request = header + body + encoded_pattern
    response = transport.send_and_recv(request)
    resp_header, resp_body = split_header_and_body(response)

    if resp_header.status == STATUS_NO_MORE_FILES:
        return [], True

    if resp_header.status != STATUS_SUCCESS:
        raise SMBReadWriteError(f"Query directory failed with status 0x{resp_header.status:08x}")

    output_offset, output_length = struct.unpack_from("<HI", resp_body, 2)
    full_offset = output_offset - 64
    entries_bytes = resp_body[full_offset:full_offset + output_length]

    names = []
    offset = 0
    while offset + 12 <= len(entries_bytes):
        next_entry_offset, file_index, filename_length = struct.unpack_from("<III", entries_bytes, offset)
        name_start = offset + 12
        raw_name = entries_bytes[name_start:name_start + filename_length]
        names.append(raw_name.decode("utf-16-le", errors="replace"))
        if next_entry_offset == 0:
            break
        offset += next_entry_offset

    return names, False


def list_directory_names(transport: SMBTransport, file_id: bytes, max_pages: int = 64) -> list:
    all_names = []
    restart = True

    for _ in range(max_pages):
        names, done = _query_directory_once(transport, file_id, restart=restart)
        restart = False
        all_names.extend(names)
        if done or not names:
            break

    return [name for name in all_names if name not in (".", "..")]
