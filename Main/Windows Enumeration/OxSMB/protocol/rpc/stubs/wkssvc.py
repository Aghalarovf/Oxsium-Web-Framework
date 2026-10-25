from dataclasses import dataclass

from core.exceptions import NDRError, RPCCallError
from protocol.rpc.ndr import NDRReader, NDRWriter
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.rpc_constants import WKSSVC_NET_WKSTA_GET_INFO

WKSTA_INFO_LEVEL_100 = 100
WKSTA_INFO_LEVEL_101 = 101
WKSTA_INFO_LEVEL_102 = 102
WKSTA_INFO_LEVEL_502 = 502

PLATFORM_ID_DOS = 300
PLATFORM_ID_OS2 = 400
PLATFORM_ID_NT = 500
PLATFORM_ID_OSF = 600
PLATFORM_ID_VMS = 700

PLATFORM_ID_NAMES = {
    PLATFORM_ID_DOS: "DOS",
    PLATFORM_ID_OS2: "OS/2",
    PLATFORM_ID_NT: "Windows NT",
    PLATFORM_ID_OSF: "OSF",
    PLATFORM_ID_VMS: "VMS",
}


@dataclass
class WkstaInfo102:
    platform_id: int
    computer_name: str
    domain_name: str
    version_major: int
    version_minor: int
    logged_on_users: int

    @property
    def platform_name(self) -> str:
        return PLATFORM_ID_NAMES.get(self.platform_id, f"UNKNOWN(0x{self.platform_id:08x})")

    @property
    def os_version(self) -> str:
        return f"{self.version_major}.{self.version_minor}"


def _build_net_wksta_get_info_request(server_name: str, level: int = WKSTA_INFO_LEVEL_102) -> bytes:
    writer = NDRWriter()

    # [in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName
    writer.referent_id(0x00020000)
    writer.unicode_string_ptr(server_name)

    # [in] unsigned long Level
    writer.uint32(level)

    return writer.getvalue()


def _parse_net_wksta_get_info_102_response(data: bytes) -> WkstaInfo102:
    reader = NDRReader(data)

    # [out, switch_is(Level)] LPWKSTA_INFO WkstaInfo
    # WkstaInfo is a non-encapsulated union: its own discriminant is echoed
    # on the wire ahead of the selected arm.
    reader.uint32()  # echoed Level / union discriminant

    info_referent = reader.uint32()  # referent for the LPWKSTA_INFO_102 arm pointer
    if info_referent == 0:
        raise RPCCallError("NetrWkstaGetInfo returned a NULL WkstaInfo pointer")

    # WKSTA_INFO_102 fixed part
    platform_id = reader.uint32()
    computername_referent = reader.uint32()
    langroup_referent = reader.uint32()
    version_major = reader.uint32()
    version_minor = reader.uint32()
    reader.uint32()  # wki102_lanroot referent - MUST be NULL per [MS-WKST] 2.2.5.3
    logged_on_users = reader.uint32()

    # Deferred conformant-varying strings, in declaration order
    computer_name = ""
    domain_name = ""
    if computername_referent != 0:
        computer_name = reader.read_unicode_conformant_string()
    if langroup_referent != 0:
        domain_name = reader.read_unicode_conformant_string()

    return_code = reader.uint32()
    if return_code != 0:
        raise RPCCallError(f"NetrWkstaGetInfo returned Win32 error code {return_code}")

    return WkstaInfo102(
        platform_id=platform_id,
        computer_name=computer_name,
        domain_name=domain_name,
        version_major=version_major,
        version_minor=version_minor,
        logged_on_users=logged_on_users,
    )


def net_wksta_get_info_102(channel: RPCChannel, server_name: str = "") -> WkstaInfo102:
    request_stub = _build_net_wksta_get_info_request(server_name, WKSTA_INFO_LEVEL_102)
    response_stub = channel.call(WKSSVC_NET_WKSTA_GET_INFO, request_stub)
    try:
        return _parse_net_wksta_get_info_102_response(response_stub)
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse NetrWkstaGetInfo response: {exc}") from exc
