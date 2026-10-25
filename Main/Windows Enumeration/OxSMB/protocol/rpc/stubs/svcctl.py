import struct
from dataclasses import dataclass
from typing import List, Optional

from core.exceptions import NDRError, RPCCallError
from protocol.rpc.ndr import NDRReader, NDRWriter
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.rpc_constants import (
    SVCCTL_CLOSE_SERVICE_HANDLE,
    SVCCTL_ENUM_SERVICES_STATUS_EX_W,
    SVCCTL_OPEN_SC_MANAGER_W,
)

CONTEXT_HANDLE_LEN = 20

SC_MANAGER_CONNECT = 0x00000001
SC_MANAGER_CREATE_SERVICE = 0x00000002
SC_MANAGER_ENUMERATE_SERVICE = 0x00000004
SC_MANAGER_ALL_ACCESS = 0x000F003F

SC_ENUM_PROCESS_INFO = 0

SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_WIN32_SHARE_PROCESS = 0x00000020
# The four type bits REnumServicesStatusExW actually accepts (MS-SCMR 3.1.4.40).
SERVICE_TYPE_ALL = (
    SERVICE_KERNEL_DRIVER
    | SERVICE_FILE_SYSTEM_DRIVER
    | SERVICE_WIN32_OWN_PROCESS
    | SERVICE_WIN32_SHARE_PROCESS
)

SERVICE_ACTIVE = 0x00000001
SERVICE_INACTIVE = 0x00000002
SERVICE_STATE_ALL = 0x00000003

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTINUE_PENDING = 5
SERVICE_PAUSE_PENDING = 6
SERVICE_PAUSED = 7

SERVICE_STATE_NAMES = {
    SERVICE_STOPPED: "STOPPED",
    SERVICE_START_PENDING: "START_PENDING",
    SERVICE_STOP_PENDING: "STOP_PENDING",
    SERVICE_RUNNING: "RUNNING",
    SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
    SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
    SERVICE_PAUSED: "PAUSED",
}

ERROR_MORE_DATA = 234

# SERVICE_STATUS_PROCESS is 9 fixed DWORDs; each ENUM_SERVICE_STATUS_PROCESSW
# record is 2 pointer-sized offsets (lpServiceName, lpDisplayName) plus that
# struct, all fixed-size with no inline alignment padding.
_SERVICE_STATUS_PROCESS_LEN = 36
_ENTRY_FIXED_LEN = 4 + 4 + _SERVICE_STATUS_PROCESS_LEN


@dataclass
class ServiceEntry:
    service_name: str
    display_name: str
    service_type: int
    current_state: int
    controls_accepted: int
    win32_exit_code: int
    service_specific_exit_code: int
    check_point: int
    wait_hint: int
    process_id: int
    service_flags: int

    @property
    def state_name(self) -> str:
        return SERVICE_STATE_NAMES.get(self.current_state, f"UNKNOWN(0x{self.current_state:08x})")


def _build_open_scm_request(
    machine_name: Optional[str], database_name: Optional[str], desired_access: int
) -> bytes:
    writer = NDRWriter()

    # [in, string, unique] SVCCTL_HANDLEW lpMachineName
    if machine_name:
        writer.referent_id(0x00020000)
        writer.unicode_string_ptr(machine_name)
    else:
        writer.uint32(0)

    # [in, string, unique] wchar_t* lpDatabaseName (NULL -> "ServicesActive")
    if database_name:
        writer.referent_id(0x00020004)
        writer.unicode_string_ptr(database_name)
    else:
        writer.uint32(0)

    # [in] DWORD dwDesiredAccess
    writer.uint32(desired_access)

    return writer.getvalue()


def _parse_open_scm_response(data: bytes) -> bytes:
    reader = NDRReader(data)
    reader.align(4)
    handle = reader.raw(CONTEXT_HANDLE_LEN)
    return_code = reader.uint32()
    if return_code != 0:
        raise RPCCallError(f"ROpenSCManagerW returned Win32 error code {return_code}")
    return handle


def open_scm(
    channel: RPCChannel,
    machine_name: Optional[str] = None,
    database_name: Optional[str] = None,
    desired_access: int = SC_MANAGER_ALL_ACCESS,
) -> bytes:
    request_stub = _build_open_scm_request(machine_name, database_name, desired_access)
    response_stub = channel.call(SVCCTL_OPEN_SC_MANAGER_W, request_stub)
    try:
        return _parse_open_scm_response(response_stub)
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse ROpenSCManagerW response: {exc}") from exc


def _build_close_handle_request(handle: bytes) -> bytes:
    writer = NDRWriter()
    writer.align(4)
    writer.raw(handle)
    return writer.getvalue()


def close_service_handle(channel: RPCChannel, handle: bytes):
    request_stub = _build_close_handle_request(handle)
    try:
        channel.call(SVCCTL_CLOSE_SERVICE_HANDLE, request_stub)
    except RPCCallError:
        # Best-effort cleanup only; the pipe itself is torn down by the
        # enclosing RPCChannel context manager regardless.
        pass


def _build_enum_request(handle: bytes, cb_buf_size: int, service_type: int, service_state: int) -> bytes:
    writer = NDRWriter()

    # [in] SC_RPC_HANDLE hSCManager
    writer.align(4)
    writer.raw(handle)

    # [in] SC_ENUM_TYPE InfoLevel
    writer.uint32(SC_ENUM_PROCESS_INFO)
    # [in] DWORD dwServiceType
    writer.uint32(service_type)
    # [in] DWORD dwServiceState
    writer.uint32(service_state)
    # [in] DWORD cbBufSize
    writer.uint32(cb_buf_size)
    # [in, out, unique] LPBOUNDED_DWORD_256K lpResumeIndex (NULL: start from the top)
    writer.uint32(0)
    # [in, string, unique] LPCWSTR pszGroupName (NULL: all groups)
    writer.uint32(0)

    return writer.getvalue()


def _parse_enum_response(data: bytes):
    reader = NDRReader(data)

    # [out, size_is(cbBufSize)] LPBYTE lpBuffer - non-unique ("ref") pointer to
    # a conformant byte array: wire form is just max_count + raw bytes, no
    # separate referent id.
    buf_len = reader.uint32()
    buffer = reader.raw(buf_len)

    # [out] LPBOUNDED_DWORD_256K pcbBytesNeeded - ref pointer, value inline
    pcb_bytes_needed = reader.uint32()
    # [out] LPBOUNDED_DWORD_256K lpServicesReturned - ref pointer, value inline
    services_returned = reader.uint32()

    # [in, out, unique] LPBOUNDED_DWORD_256K lpResumeIndex
    resume_referent = reader.uint32()
    if resume_referent != 0:
        reader.uint32()

    return_code = reader.uint32()
    return buffer, services_returned, pcb_bytes_needed, return_code


def _read_offset_string(buffer: bytes, offset: int) -> str:
    # lpServiceName / lpDisplayName are not NDR pointers here: the server
    # mirrors its native in-process memory layout, so these DWORDs are raw
    # byte offsets into this same lpBuffer blob, pointing at a UTF-16LE,
    # NUL-terminated string.
    if offset <= 0 or offset >= len(buffer):
        return ""
    end = offset
    while end + 1 < len(buffer) and not (buffer[end] == 0 and buffer[end + 1] == 0):
        end += 2
    return buffer[offset:end].decode("utf-16-le", errors="replace")


def _parse_service_array(buffer: bytes, count: int) -> List[ServiceEntry]:
    entries = []
    for index in range(count):
        base = index * _ENTRY_FIXED_LEN
        if base + _ENTRY_FIXED_LEN > len(buffer):
            break

        name_offset, display_offset = struct.unpack_from("<II", buffer, base)
        (
            service_type,
            current_state,
            controls_accepted,
            win32_exit_code,
            service_specific_exit_code,
            check_point,
            wait_hint,
            process_id,
            service_flags,
        ) = struct.unpack_from("<9I", buffer, base + 8)

        entries.append(
            ServiceEntry(
                service_name=_read_offset_string(buffer, name_offset),
                display_name=_read_offset_string(buffer, display_offset),
                service_type=service_type,
                current_state=current_state,
                controls_accepted=controls_accepted,
                win32_exit_code=win32_exit_code,
                service_specific_exit_code=service_specific_exit_code,
                check_point=check_point,
                wait_hint=wait_hint,
                process_id=process_id,
                service_flags=service_flags,
            )
        )
    return entries


def enum_services_status_ex(
    channel: RPCChannel,
    handle: bytes,
    service_type: int = SERVICE_TYPE_ALL,
    service_state: int = SERVICE_STATE_ALL,
    initial_buffer_size: int = 0x10000,
) -> List[ServiceEntry]:
    buf_size = initial_buffer_size

    request_stub = _build_enum_request(handle, buf_size, service_type, service_state)
    response_stub = channel.call(SVCCTL_ENUM_SERVICES_STATUS_EX_W, request_stub)
    try:
        buffer, count, needed, return_code = _parse_enum_response(response_stub)
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse REnumServicesStatusExW response: {exc}") from exc

    if return_code == ERROR_MORE_DATA and needed > buf_size:
        buf_size = needed
        request_stub = _build_enum_request(handle, buf_size, service_type, service_state)
        response_stub = channel.call(SVCCTL_ENUM_SERVICES_STATUS_EX_W, request_stub)
        try:
            buffer, count, needed, return_code = _parse_enum_response(response_stub)
        except NDRError as exc:
            raise RPCCallError(f"Failed to parse REnumServicesStatusExW response: {exc}") from exc

    if return_code not in (0, ERROR_MORE_DATA):
        raise RPCCallError(f"REnumServicesStatusExW returned Win32 error code {return_code}")

    try:
        return _parse_service_array(buffer, count)
    except (struct.error, IndexError) as exc:
        raise RPCCallError(f"Failed to parse ENUM_SERVICE_STATUS_PROCESSW array: {exc}") from exc
