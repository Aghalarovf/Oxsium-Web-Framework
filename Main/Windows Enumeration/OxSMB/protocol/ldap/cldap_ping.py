import socket
import struct
from dataclasses import dataclass
from typing import Optional

from core.exceptions import OxSMBError

NETLOGON_NT_VERSION_5EX = 0x00000006
NETLOGON_SAM_LOGON_RESPONSE_EX = 23

DS_PDC_FLAG = 0x00000001
DS_GC_FLAG = 0x00000004
DS_LDAP_FLAG = 0x00000008
DS_DS_FLAG = 0x00000010
DS_KDC_FLAG = 0x00000020
DS_TIMESERV_FLAG = 0x00000040
DS_CLOSEST_FLAG = 0x00000080
DS_WRITABLE_FLAG = 0x00000100
DS_GOOD_TIMESERV_FLAG = 0x00000200
DS_DNS_CONTROLLER_FLAG = 0x20000000
DS_DNS_DOMAIN_FLAG = 0x40000000
DS_DNS_FOREST_FLAG = 0x80000000

DS_FLAG_NAMES = {
    DS_PDC_FLAG: "PDC",
    DS_GC_FLAG: "GC",
    DS_LDAP_FLAG: "LDAP",
    DS_DS_FLAG: "DS",
    DS_KDC_FLAG: "KDC",
    DS_TIMESERV_FLAG: "TIMESERV",
    DS_CLOSEST_FLAG: "CLOSEST",
    DS_WRITABLE_FLAG: "WRITABLE",
    DS_GOOD_TIMESERV_FLAG: "GOOD_TIMESERV",
    DS_DNS_CONTROLLER_FLAG: "DNS_CONTROLLER",
    DS_DNS_DOMAIN_FLAG: "DNS_DOMAIN",
    DS_DNS_FOREST_FLAG: "DNS_FOREST",
}


class CLDAPPingError(OxSMBError):
    pass


@dataclass
class CLDAPPingResult:
    opcode: int
    flags: int
    domain_guid: str
    dns_forest_name: str
    dns_domain_name: str
    dns_host_name: str
    netbios_domain_name: str
    netbios_computer_name: str
    dc_site_name: str
    client_site_name: str

    @property
    def is_domain_controller(self) -> bool:
        return bool(self.flags & DS_DS_FLAG)

    @property
    def flag_names(self):
        return [name for bit, name in DS_FLAG_NAMES.items() if self.flags & bit]


def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _ber_integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=False)
        if body[0] & 0x80:
            body = b"\x00" + body
    return _ber_tlv(0x02, body)


def _ber_enumerated(value: int) -> bytes:
    return _ber_tlv(0x0A, bytes([value]))


def _ber_boolean(value: bool) -> bytes:
    return _ber_tlv(0x01, b"\xff" if value else b"\x00")


def _ber_octet_string(value) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _ber_tlv(0x04, value)


def _build_netlogon_search_request(message_id: int = 1) -> bytes:
    base_object = _ber_octet_string("")
    scope = _ber_enumerated(0)
    deref_aliases = _ber_enumerated(0)
    size_limit = _ber_integer(0)
    time_limit = _ber_integer(0)
    types_only = _ber_boolean(False)

    ntver_bytes = struct.pack("<I", NETLOGON_NT_VERSION_5EX)
    equality_match = _ber_octet_string("NtVer") + _ber_octet_string(ntver_bytes)
    filter_expr = _ber_tlv(0xA3, equality_match)

    attributes = _ber_tlv(0x30, _ber_octet_string("Netlogon"))

    search_request_body = (
        base_object + scope + deref_aliases + size_limit + time_limit + types_only + filter_expr + attributes
    )
    search_request = _ber_tlv(0x63, search_request_body)

    ldap_message_body = _ber_integer(message_id) + search_request
    return _ber_tlv(0x30, ldap_message_body)


def _read_ber_tlv(data: bytes, offset: int):
    tag = data[offset]
    offset += 1
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num_bytes = length_byte & 0x7F
        length = int.from_bytes(data[offset:offset + num_bytes], "big")
        offset += num_bytes
    else:
        length = length_byte
    value = data[offset:offset + length]
    return tag, value, offset + length


def _extract_netlogon_attribute(packet: bytes) -> bytes:
    offset = packet.find(b"\x04\x08Netlogon")
    if offset == -1:
        offset = packet.find(b"Netlogon")
        if offset == -1:
            raise CLDAPPingError("Netlogon attribute not found in LDAP ping response")
        offset += len(b"Netlogon")
    else:
        offset += len(b"\x04\x08Netlogon")

    tag, value, _ = _read_ber_tlv(packet, offset)
    if tag != 0x31:
        raise CLDAPPingError("Unexpected ASN.1 tag for Netlogon attribute value set")

    inner_tag, inner_value, _ = _read_ber_tlv(value, 0)
    if inner_tag != 0x04:
        raise CLDAPPingError("Unexpected ASN.1 tag for Netlogon attribute value")

    return inner_value


def _read_dns_compressed_name(packet: bytes, offset: int):
    labels = []
    jumped = False
    jump_count = 0
    original_next = None

    while True:
        if offset >= len(packet):
            raise CLDAPPingError("DNS-compressed name read past end of buffer")

        length = packet[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise CLDAPPingError("Truncated DNS name compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_next = offset + 2
            jumped = True
            jump_count += 1
            if jump_count > 64:
                raise CLDAPPingError("DNS name compression pointer loop detected")
            offset = pointer
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    next_offset = original_next if jumped else offset
    return ".".join(labels), next_offset


def _parse_netlogon_sam_logon_response_ex(packet: bytes, blob: bytes) -> CLDAPPingResult:
    base = packet.find(blob)
    if base == -1:
        base = 0
        packet = blob

    opcode, sbz = struct.unpack_from("<HH", blob, 0)
    if opcode != NETLOGON_SAM_LOGON_RESPONSE_EX:
        raise CLDAPPingError(f"Unexpected Netlogon opcode {opcode}, expected NETLOGON_SAM_LOGON_RESPONSE_EX")

    flags = struct.unpack_from("<I", blob, 4)[0]
    domain_guid_bytes = blob[8:24]
    domain_guid = str(_bytes_to_guid(domain_guid_bytes))

    cursor = base + 24
    dns_forest_name, cursor = _read_dns_compressed_name(packet, cursor)
    dns_domain_name, cursor = _read_dns_compressed_name(packet, cursor)
    dns_host_name, cursor = _read_dns_compressed_name(packet, cursor)
    netbios_domain_name, cursor = _read_dns_compressed_name(packet, cursor)
    netbios_computer_name, cursor = _read_dns_compressed_name(packet, cursor)
    _user_name, cursor = _read_dns_compressed_name(packet, cursor)
    dc_site_name, cursor = _read_dns_compressed_name(packet, cursor)
    client_site_name, cursor = _read_dns_compressed_name(packet, cursor)

    return CLDAPPingResult(
        opcode=opcode,
        flags=flags,
        domain_guid=domain_guid,
        dns_forest_name=dns_forest_name,
        dns_domain_name=dns_domain_name,
        dns_host_name=dns_host_name,
        netbios_domain_name=netbios_domain_name,
        netbios_computer_name=netbios_computer_name,
        dc_site_name=dc_site_name,
        client_site_name=client_site_name,
    )


def _bytes_to_guid(data: bytes) -> str:
    part1, part2, part3 = struct.unpack_from("<IHH", data, 0)
    part4 = data[8:10].hex()
    part5 = data[10:16].hex()
    return f"{part1:08x}-{part2:04x}-{part3:04x}-{part4}-{part5}"


def send_ldap_ping(host: str, port: int = 389, timeout: float = 5.0) -> Optional[CLDAPPingResult]:
    request = _build_netlogon_search_request()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request, (host, port))
        packet, _ = sock.recvfrom(65535)
    except socket.timeout:
        return None
    except OSError as exc:
        raise CLDAPPingError(f"UDP LDAP ping failed: {exc}") from exc
    finally:
        sock.close()

    blob = _extract_netlogon_attribute(packet)
    return _parse_netlogon_sam_logon_response_ex(packet, blob)
