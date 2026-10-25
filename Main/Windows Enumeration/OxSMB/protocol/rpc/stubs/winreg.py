from dataclasses import dataclass
from typing import Optional

from core.exceptions import NDRError, RPCCallError
from protocol.rpc.ndr import NDRReader, NDRWriter
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.rpc_constants import (
    WINREG_BASE_REG_ENUM_KEY,
    WINREG_BASE_REG_OPEN_KEY,
    WINREG_BASE_REG_QUERY_VALUE,
    WINREG_CLOSE_KEY,
    WINREG_OPEN_HKLM,
    WINREG_OPEN_HKU,
)

CONTEXT_HANDLE_LEN = 20

STANDARD_RIGHTS_READ = 0x00020000
KEY_QUERY_VALUE = 0x0001
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_NOTIFY = 0x0010
KEY_READ = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY

ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_NO_MORE_ITEMS = 259

REG_TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


@dataclass
class RegistryValue:
    reg_type: int
    data: bytes

    @property
    def type_name(self) -> str:
        return REG_TYPE_NAMES.get(self.reg_type, f"UNKNOWN(0x{self.reg_type:08x})")

    @property
    def as_dword(self) -> Optional[int]:
        if self.reg_type == 4 and len(self.data) >= 4:
            return int.from_bytes(self.data[:4], "little")
        return None

    @property
    def as_string(self) -> Optional[str]:
        if self.reg_type not in (1, 2):
            return None
        return self.data.decode("utf-16-le", errors="replace").rstrip("\x00")

    @property
    def as_multi_string(self) -> Optional[list]:
        if self.reg_type != 7:
            return None
        text = self.data.decode("utf-16-le", errors="replace")
        return [part for part in text.split("\x00") if part]


class RegistryKeyNotFound(RPCCallError):
    pass


def _open_root_key(channel: RPCChannel, opnum: int, sam_desired: int) -> bytes:
    writer = NDRWriter()
    writer.uint32(0)
    writer.uint32(sam_desired)

    response_stub = channel.call(opnum, writer.getvalue())
    try:
        reader = NDRReader(response_stub)
        reader.align(4)
        handle = reader.raw(CONTEXT_HANDLE_LEN)
        return_code = reader.uint32()
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse registry root-key open response: {exc}") from exc

    if return_code != ERROR_SUCCESS:
        raise RPCCallError(f"Registry root-key open returned Win32 error code {return_code}")

    return handle


def open_hklm(channel: RPCChannel, sam_desired: int = KEY_READ) -> bytes:
    return _open_root_key(channel, WINREG_OPEN_HKLM, sam_desired)


def open_hku(channel: RPCChannel, sam_desired: int = KEY_READ) -> bytes:
    return _open_root_key(channel, WINREG_OPEN_HKU, sam_desired)


def open_key(channel: RPCChannel, parent_handle: bytes, subkey: str, sam_desired: int = KEY_READ) -> bytes:
    writer = NDRWriter()
    writer.align(4)
    writer.raw(parent_handle)
    writer.rrp_unicode_string(subkey)
    writer.uint32(0)
    writer.uint32(sam_desired)

    response_stub = channel.call(WINREG_BASE_REG_OPEN_KEY, writer.getvalue())
    try:
        reader = NDRReader(response_stub)
        reader.align(4)
        handle = reader.raw(CONTEXT_HANDLE_LEN)
        return_code = reader.uint32()
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse BaseRegOpenKey response: {exc}") from exc

    if return_code == ERROR_FILE_NOT_FOUND:
        raise RegistryKeyNotFound(f"Registry key '{subkey}' does not exist")
    if return_code != ERROR_SUCCESS:
        raise RPCCallError(f"BaseRegOpenKey returned Win32 error code {return_code}")

    return handle


def close_key(channel: RPCChannel, handle: bytes):
    writer = NDRWriter()
    writer.align(4)
    writer.raw(handle)
    try:
        channel.call(WINREG_CLOSE_KEY, writer.getvalue())
    except RPCCallError:
        pass


def query_value(channel: RPCChannel, handle: bytes, value_name: str, buffer_size: int = 4096) -> RegistryValue:
    writer = NDRWriter()
    writer.align(4)
    writer.raw(handle)
    writer.rrp_unicode_string(value_name)
    writer.referent_id()
    writer.uint32(0)
    writer.referent_id()
    writer.conformant_byte_array(b"\x00" * buffer_size)
    writer.referent_id()
    writer.uint32(buffer_size)
    writer.uint32(0)

    response_stub = channel.call(WINREG_BASE_REG_QUERY_VALUE, writer.getvalue())
    try:
        reader = NDRReader(response_stub)

        reg_type = 0
        if reader.pointer_present():
            reg_type = reader.uint32()

        data = b""
        if reader.pointer_present():
            data = reader.read_conformant_byte_array()

        if reader.pointer_present():
            reader.uint32()

        if reader.pointer_present():
            reader.uint32()

        return_code = reader.uint32()
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse BaseRegQueryValue response: {exc}") from exc

    if return_code == ERROR_FILE_NOT_FOUND:
        raise RegistryKeyNotFound(f"Registry value '{value_name}' does not exist")
    if return_code != ERROR_SUCCESS:
        raise RPCCallError(f"BaseRegQueryValue returned Win32 error code {return_code}")

    return RegistryValue(reg_type=reg_type, data=data)


def enum_key(channel: RPCChannel, handle: bytes, index: int, max_name_chars: int = 512) -> Optional[str]:
    writer = NDRWriter()
    writer.align(4)
    writer.raw(handle)
    writer.uint32(index)
    writer.rrp_unicode_string_buffer(max_name_chars)
    writer.uint32(0)
    writer.uint32(0)

    response_stub = channel.call(WINREG_BASE_REG_ENUM_KEY, writer.getvalue())
    try:
        reader = NDRReader(response_stub)
        name = reader.read_rrp_unicode_string()

        if reader.pointer_present():
            pass

        if reader.pointer_present():
            pass

        return_code = reader.uint32()
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse BaseRegEnumKey response: {exc}") from exc

    if return_code == ERROR_NO_MORE_ITEMS:
        return None
    if return_code != ERROR_SUCCESS:
        raise RPCCallError(f"BaseRegEnumKey returned Win32 error code {return_code}")

    return name


def enum_all_subkeys(channel: RPCChannel, handle: bytes, max_name_chars: int = 512) -> list:
    names = []
    index = 0
    while True:
        name = enum_key(channel, handle, index, max_name_chars=max_name_chars)
        if name is None:
            break
        names.append(name)
        index += 1
    return names
