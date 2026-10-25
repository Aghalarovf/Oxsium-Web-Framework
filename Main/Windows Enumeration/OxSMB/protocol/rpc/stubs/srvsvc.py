from dataclasses import dataclass
from typing import List

from core.exceptions import NDRError, RPCCallError
from protocol.rpc.ndr import NDRReader, NDRWriter
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.rpc_constants import (
    SRVSVC_NET_REMOTE_TOD,
    SRVSVC_NET_SERVER_GET_INFO,
    SRVSVC_NET_SHARE_ENUM,
)

SERVER_INFO_LEVEL_101 = 101

SV_TYPE_WORKSTATION = 0x00000001
SV_TYPE_SERVER = 0x00000002
SV_TYPE_SQLSERVER = 0x00000004
SV_TYPE_DOMAIN_CTRL = 0x00000008
SV_TYPE_DOMAIN_BAKCTRL = 0x00000010
SV_TYPE_TIME_SOURCE = 0x00000020
SV_TYPE_AFP = 0x00000040
SV_TYPE_NOVELL = 0x00000080
SV_TYPE_DOMAIN_MEMBER = 0x00000100
SV_TYPE_PRINTQ_SERVER = 0x00000200
SV_TYPE_DIALIN_SERVER = 0x00000400
SV_TYPE_XENIX_SERVER = 0x00000800
SV_TYPE_NT = 0x00001000
SV_TYPE_WFW = 0x00002000
SV_TYPE_SERVER_NT = 0x00008000
SV_TYPE_POTENTIAL_BROWSER = 0x00010000
SV_TYPE_BACKUP_BROWSER = 0x00020000
SV_TYPE_MASTER_BROWSER = 0x00040000
SV_TYPE_DOMAIN_MASTER = 0x00080000
SV_TYPE_TERMINAL_SERVER = 0x20000000

SV_TYPE_NAMES = {
    SV_TYPE_WORKSTATION: "WORKSTATION",
    SV_TYPE_SERVER: "SERVER",
    SV_TYPE_SQLSERVER: "SQLSERVER",
    SV_TYPE_DOMAIN_CTRL: "DOMAIN_CTRL",
    SV_TYPE_DOMAIN_BAKCTRL: "DOMAIN_BAKCTRL",
    SV_TYPE_TIME_SOURCE: "TIME_SOURCE",
    SV_TYPE_AFP: "AFP",
    SV_TYPE_NOVELL: "NOVELL",
    SV_TYPE_DOMAIN_MEMBER: "DOMAIN_MEMBER",
    SV_TYPE_PRINTQ_SERVER: "PRINTQ_SERVER",
    SV_TYPE_DIALIN_SERVER: "DIALIN_SERVER",
    SV_TYPE_XENIX_SERVER: "XENIX_SERVER",
    SV_TYPE_NT: "NT",
    SV_TYPE_WFW: "WFW",
    SV_TYPE_SERVER_NT: "SERVER_NT",
    SV_TYPE_POTENTIAL_BROWSER: "POTENTIAL_BROWSER",
    SV_TYPE_BACKUP_BROWSER: "BACKUP_BROWSER",
    SV_TYPE_MASTER_BROWSER: "MASTER_BROWSER",
    SV_TYPE_DOMAIN_MASTER: "DOMAIN_MASTER",
    SV_TYPE_TERMINAL_SERVER: "TERMINAL_SERVER",
}

SHARE_TYPE_DISK = 0x00000000
SHARE_TYPE_PRINT = 0x00000001
SHARE_TYPE_DEVICE = 0x00000002
SHARE_TYPE_IPC = 0x00000003
SHARE_TYPE_SPECIAL = 0x80000000
SHARE_TYPE_TEMPORARY = 0x40000000

SHARE_TYPE_NAMES = {
    SHARE_TYPE_DISK: "DISK",
    SHARE_TYPE_PRINT: "PRINTER",
    SHARE_TYPE_DEVICE: "DEVICE",
    SHARE_TYPE_IPC: "IPC",
}


@dataclass
class ShareInfo:
    name: str
    share_type: int
    remark: str

    @property
    def type_name(self) -> str:
        base_type = self.share_type & 0x0FFFFFFF
        name = SHARE_TYPE_NAMES.get(base_type, f"UNKNOWN(0x{base_type:08x})")
        if self.share_type & SHARE_TYPE_SPECIAL:
            name += "$"
        return name


def _build_net_share_enum_request(server_name: str, level: int = 1) -> bytes:
    writer = NDRWriter()

    writer.referent_id(0x00020000)
    writer.unicode_string_ptr(server_name)

    writer.uint32(level)

    writer.referent_id(0x00020004)
    writer.uint32(0)
    writer.uint32(0)

    writer.uint32(0xFFFFFFFF)

    writer.referent_id(0x00020008)
    writer.uint32(0)

    return writer.getvalue()


def _parse_net_share_enum_response(data: bytes) -> List[ShareInfo]:
    reader = NDRReader(data)

    level = reader.uint32()
    reader.uint32()

    container_referent = reader.uint32()
    entries_read = reader.uint32()
    buffer_referent = reader.uint32()

    shares: List[ShareInfo] = []

    if buffer_referent != 0 and entries_read > 0:
        array_count = reader.uint32()

        raw_entries = []
        for _ in range(array_count):
            name_referent = reader.uint32()
            share_type = reader.uint32()
            remark_referent = reader.uint32()
            raw_entries.append((name_referent, share_type, remark_referent))

        for name_referent, share_type, remark_referent in raw_entries:
            name = ""
            remark = ""
            if name_referent != 0:
                name = reader.read_unicode_conformant_string()
            if remark_referent != 0:
                remark = reader.read_unicode_conformant_string()
            shares.append(ShareInfo(name=name, share_type=share_type, remark=remark))

    total_entries = reader.uint32()
    resume_referent = reader.uint32()
    if resume_referent != 0:
        reader.uint32()

    return_code = reader.uint32()
    if return_code not in (0, 0xEA):
        raise RPCCallError(f"NetrShareEnum returned Win32 error code {return_code}")

    return shares


def net_share_enum(channel: RPCChannel, server_name: str = "") -> List[ShareInfo]:
    request_stub = _build_net_share_enum_request(server_name)
    response_stub = channel.call(SRVSVC_NET_SHARE_ENUM, request_stub)
    try:
        return _parse_net_share_enum_response(response_stub)
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse NetrShareEnum response: {exc}") from exc


@dataclass
class TimeOfDayInfo:
    elapsed_seconds: int
    msecs: int
    hours: int
    mins: int
    secs: int
    hunds: int
    timezone_minutes: int
    tick_interval: int
    day: int
    month: int
    year: int
    weekday: int

    @property
    def timezone_offset(self) -> str:
        if self.timezone_minutes == -1:
            return "unknown"
        sign = "-" if self.timezone_minutes >= 0 else "+"
        magnitude = abs(self.timezone_minutes)
        return f"UTC{sign}{magnitude // 60:02d}:{magnitude % 60:02d}"

    @property
    def remote_datetime(self) -> str:
        return (
            f"{self.year:04d}-{self.month:02d}-{self.day:02d} "
            f"{self.hours:02d}:{self.mins:02d}:{self.secs:02d}"
        )


def _build_net_remote_tod_request(server_name: str) -> bytes:
    writer = NDRWriter()

    # [in, string, unique] SRVSVC_HANDLE ServerName
    writer.referent_id(0x00020000)
    writer.unicode_string_ptr(server_name)

    return writer.getvalue()


def _parse_net_remote_tod_response(data: bytes) -> TimeOfDayInfo:
    reader = NDRReader(data)

    # [out] LPTIME_OF_DAY_INFO* BufferPtr
    info_referent = reader.uint32()
    if info_referent == 0:
        raise RPCCallError("NetrRemoteTOD returned a NULL TIME_OF_DAY_INFO pointer")

    elapsed_seconds = reader.uint32()
    msecs = reader.uint32()
    hours = reader.uint32()
    mins = reader.uint32()
    secs = reader.uint32()
    hunds = reader.uint32()
    raw_timezone = reader.uint32()
    tick_interval = reader.uint32()
    day = reader.uint32()
    month = reader.uint32()
    year = reader.uint32()
    weekday = reader.uint32()

    # tod_timezone is a signed LONG (minutes west of UTC, -1 if unknown)
    timezone_minutes = raw_timezone - 0x100000000 if raw_timezone >= 0x80000000 else raw_timezone

    return_code = reader.uint32()
    if return_code != 0:
        raise RPCCallError(f"NetrRemoteTOD returned Win32 error code {return_code}")

    return TimeOfDayInfo(
        elapsed_seconds=elapsed_seconds,
        msecs=msecs,
        hours=hours,
        mins=mins,
        secs=secs,
        hunds=hunds,
        timezone_minutes=timezone_minutes,
        tick_interval=tick_interval,
        day=day,
        month=month,
        year=year,
        weekday=weekday,
    )


def net_remote_tod(channel: RPCChannel, server_name: str = "") -> TimeOfDayInfo:
    request_stub = _build_net_remote_tod_request(server_name)
    response_stub = channel.call(SRVSVC_NET_REMOTE_TOD, request_stub)
    try:
        return _parse_net_remote_tod_response(response_stub)
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse NetrRemoteTOD response: {exc}") from exc


@dataclass
class ServerInfo101:
    platform_id: int
    name: str
    version_major: int
    version_minor: int
    server_type: int
    comment: str

    @property
    def os_version(self) -> str:
        return f"{self.version_major}.{self.version_minor}"

    @property
    def server_type_flags(self) -> List[str]:
        return [label for bit, label in SV_TYPE_NAMES.items() if self.server_type & bit]


def _build_net_server_get_info_request(server_name: str, level: int = SERVER_INFO_LEVEL_101) -> bytes:
    writer = NDRWriter()

    # [in, string, unique] SRVSVC_HANDLE ServerName
    writer.referent_id(0x00020000)
    writer.unicode_string_ptr(server_name)

    # [in] DWORD Level
    writer.uint32(level)

    return writer.getvalue()


def _parse_net_server_get_info_101_response(data: bytes) -> ServerInfo101:
    reader = NDRReader(data)

    # [out, switch_is(Level)] LPSERVER_INFO ServerInfo
    # Non-encapsulated union: discriminant is echoed ahead of the selected arm.
    reader.uint32()  # echoed Level / union discriminant

    info_referent = reader.uint32()  # referent for the SERVER_INFO_101 arm pointer
    if info_referent == 0:
        raise RPCCallError("NetrServerGetInfo returned a NULL ServerInfo pointer")

    # SERVER_INFO_101 fixed part
    platform_id = reader.uint32()
    name_referent = reader.uint32()
    version_major = reader.uint32()
    version_minor = reader.uint32()
    server_type = reader.uint32()
    comment_referent = reader.uint32()

    # Deferred conformant-varying strings, in declaration order
    name = ""
    comment = ""
    if name_referent != 0:
        name = reader.read_unicode_conformant_string()
    if comment_referent != 0:
        comment = reader.read_unicode_conformant_string()

    return_code = reader.uint32()
    if return_code != 0:
        raise RPCCallError(f"NetrServerGetInfo returned Win32 error code {return_code}")

    return ServerInfo101(
        platform_id=platform_id,
        name=name,
        version_major=version_major,
        version_minor=version_minor,
        server_type=server_type,
        comment=comment,
    )


def net_server_get_info_101(channel: RPCChannel, server_name: str = "") -> ServerInfo101:
    request_stub = _build_net_server_get_info_request(server_name, SERVER_INFO_LEVEL_101)
    response_stub = channel.call(SRVSVC_NET_SERVER_GET_INFO, request_stub)
    try:
        return _parse_net_server_get_info_101_response(response_stub)
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse NetrServerGetInfo response: {exc}") from exc
