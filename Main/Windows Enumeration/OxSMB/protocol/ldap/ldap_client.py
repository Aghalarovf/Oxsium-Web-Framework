import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.exceptions import OxSMBError

LDAP_SCOPE_BASE = 0
LDAP_SCOPE_ONELEVEL = 1
LDAP_SCOPE_SUBTREE = 2

LDAP_MSG_BIND_REQUEST = 0x60
LDAP_MSG_BIND_RESPONSE = 0x61
LDAP_MSG_SEARCH_REQUEST = 0x63
LDAP_MSG_SEARCH_RESULT_ENTRY = 0x64
LDAP_MSG_SEARCH_RESULT_DONE = 0x65
LDAP_MSG_UNBIND_REQUEST = 0x42

LDAP_SUCCESS = 0


class LDAPError(OxSMBError):
    pass


class LDAPBindError(LDAPError):
    pass


@dataclass
class LDAPResult:
    result_code: int
    matched_dn: str
    error_message: str


@dataclass
class LDAPEntry:
    dn: str
    attributes: Dict[str, List[bytes]] = field(default_factory=dict)

    def first(self, name: str) -> Optional[bytes]:
        values = self.attributes.get(name)
        return values[0] if values else None

    def first_str(self, name: str) -> Optional[str]:
        value = self.first(name)
        return value.decode("utf-8", errors="replace") if value is not None else None

    def first_int(self, name: str) -> Optional[int]:
        value = self.first_str(name)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None


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


def filter_present(attribute: str) -> bytes:
    return _ber_tlv(0x87, attribute.encode("utf-8"))


def filter_equality(attribute: str, value) -> bytes:
    return _ber_tlv(0xA3, _ber_octet_string(attribute) + _ber_octet_string(value))


def filter_and(*filters: bytes) -> bytes:
    return _ber_tlv(0xA0, b"".join(filters))


def _read_ber_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
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


def _peek_tlv_total_length(buffer: bytes) -> Optional[int]:
    if len(buffer) < 2:
        return None
    length_byte = buffer[1]
    if length_byte & 0x80:
        num_bytes = length_byte & 0x7F
        if len(buffer) < 2 + num_bytes:
            return None
        length = int.from_bytes(buffer[2:2 + num_bytes], "big")
        header_len = 2 + num_bytes
    else:
        length = length_byte
        header_len = 2
    return header_len + length


def _parse_ldap_result(data: bytes) -> LDAPResult:
    offset = 0
    _, code_bytes, offset = _read_ber_tlv(data, offset)
    result_code = code_bytes[0] if code_bytes else 0
    _, matched_dn_bytes, offset = _read_ber_tlv(data, offset)
    _, error_message_bytes, offset = _read_ber_tlv(data, offset)
    return LDAPResult(
        result_code=result_code,
        matched_dn=matched_dn_bytes.decode("utf-8", errors="replace"),
        error_message=error_message_bytes.decode("utf-8", errors="replace"),
    )


def _parse_search_result_entry(data: bytes) -> LDAPEntry:
    offset = 0
    _, object_name, offset = _read_ber_tlv(data, offset)
    _, attrs_seq, offset = _read_ber_tlv(data, offset)

    attributes: Dict[str, List[bytes]] = {}
    inner_offset = 0
    while inner_offset < len(attrs_seq):
        _, attr_seq, inner_offset = _read_ber_tlv(attrs_seq, inner_offset)
        a_offset = 0
        _, type_bytes, a_offset = _read_ber_tlv(attr_seq, a_offset)
        attr_name = type_bytes.decode("utf-8", errors="replace")
        _, vals_set, a_offset = _read_ber_tlv(attr_seq, a_offset)

        values = []
        v_offset = 0
        while v_offset < len(vals_set):
            _, value, v_offset = _read_ber_tlv(vals_set, v_offset)
            values.append(value)

        attributes[attr_name] = values

    return LDAPEntry(dn=object_name.decode("utf-8", errors="replace"), attributes=attributes)


def _split_ldap_message(data: bytes) -> Tuple[int, int, bytes]:
    _, seq, _ = _read_ber_tlv(data, 0)
    inner_offset = 0
    _, msgid_bytes, inner_offset = _read_ber_tlv(seq, 0)
    msgid = int.from_bytes(msgid_bytes, "big") if msgid_bytes else 0
    op_tag, op_value, inner_offset = _read_ber_tlv(seq, inner_offset)
    return msgid, op_tag, op_value


class LDAPClient:
    def __init__(self, host: str, port: int = 389, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.message_id = 0

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _next_message_id(self) -> int:
        self.message_id += 1
        return self.message_id

    def _recv_message(self) -> bytes:
        buffer = bytearray()
        while True:
            total_length = _peek_tlv_total_length(bytes(buffer))
            if total_length is not None and len(buffer) >= total_length:
                return bytes(buffer[:total_length])
            chunk = self.sock.recv(65536)
            if not chunk:
                raise LDAPError("Connection closed while waiting for an LDAP response")
            buffer += chunk

    def bind(self, bind_dn: str = "", password: str = "") -> LDAPResult:
        message_id = self._next_message_id()
        name = _ber_octet_string(bind_dn)
        auth = _ber_tlv(0x80, password.encode("utf-8"))
        bind_request = _ber_tlv(LDAP_MSG_BIND_REQUEST, _ber_integer(3) + name + auth)
        packet = _ber_tlv(0x30, _ber_integer(message_id) + bind_request)

        self.sock.sendall(packet)
        response = self._recv_message()
        _, op_tag, op_value = _split_ldap_message(response)

        if op_tag != LDAP_MSG_BIND_RESPONSE:
            raise LDAPBindError("Unexpected response to BindRequest")

        result = _parse_ldap_result(op_value)
        if result.result_code != LDAP_SUCCESS:
            raise LDAPBindError(
                f"LDAP bind failed with result code {result.result_code}: {result.error_message}"
            )
        return result

    def search(
        self,
        base_dn: str,
        scope: int,
        search_filter: bytes,
        attributes: List[str],
        size_limit: int = 0,
    ) -> List[LDAPEntry]:
        message_id = self._next_message_id()

        attribute_list = _ber_tlv(0x30, b"".join(_ber_octet_string(name) for name in attributes))
        body = (
            _ber_octet_string(base_dn)
            + _ber_enumerated(scope)
            + _ber_enumerated(0)
            + _ber_integer(size_limit)
            + _ber_integer(0)
            + _ber_boolean(False)
            + search_filter
            + attribute_list
        )
        search_request = _ber_tlv(LDAP_MSG_SEARCH_REQUEST, body)
        packet = _ber_tlv(0x30, _ber_integer(message_id) + search_request)

        self.sock.sendall(packet)

        entries: List[LDAPEntry] = []
        while True:
            response = self._recv_message()
            _, op_tag, op_value = _split_ldap_message(response)

            if op_tag == LDAP_MSG_SEARCH_RESULT_ENTRY:
                entries.append(_parse_search_result_entry(op_value))
            elif op_tag == LDAP_MSG_SEARCH_RESULT_DONE:
                result = _parse_ldap_result(op_value)
                if result.result_code not in (0, 4):
                    raise LDAPError(
                        f"LDAP search failed with result code {result.result_code}: {result.error_message}"
                    )
                break
            else:
                break

        return entries

    def unbind(self):
        if self.sock is None:
            return
        try:
            message_id = self._next_message_id()
            packet = _ber_tlv(0x30, _ber_integer(message_id) + _ber_tlv(LDAP_MSG_UNBIND_REQUEST, b""))
            self.sock.sendall(packet)
        except OSError:
            pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.unbind()
        self.close()
        return False
