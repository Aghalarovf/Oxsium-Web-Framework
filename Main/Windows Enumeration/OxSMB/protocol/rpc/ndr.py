import struct
from core.exceptions import NDRError


class NDRWriter:
    def __init__(self):
        self.buffer = bytearray()

    def align(self, size: int):
        padding = (-len(self.buffer)) % size
        if padding:
            self.buffer += b"\x00" * padding

    def uint8(self, value: int):
        self.buffer += struct.pack("<B", value & 0xFF)

    def uint16(self, value: int):
        self.align(2)
        self.buffer += struct.pack("<H", value & 0xFFFF)

    def uint32(self, value: int):
        self.align(4)
        self.buffer += struct.pack("<I", value & 0xFFFFFFFF)

    def uint64(self, value: int):
        self.align(8)
        self.buffer += struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)

    def referent_id(self, value: int = 0x00020000):
        self.uint32(value)

    def unicode_string_ptr(self, value: str):
        encoded = (value + "\x00").encode("utf-16-le")
        char_count = len(encoded) // 2
        self.uint32(char_count)
        self.uint32(0)
        self.uint32(char_count)
        self.buffer += encoded
        self.align(4)

    def rrp_unicode_string(self, value: str):
        encoded = (value + "\x00").encode("utf-16-le")
        char_count = len(encoded) // 2
        byte_len = char_count * 2
        self.uint16(byte_len)
        self.uint16(byte_len)
        self.referent_id()
        self.uint32(char_count)
        self.uint32(0)
        self.uint32(char_count)
        self.buffer += encoded
        self.align(4)

    def rrp_unicode_string_buffer(self, max_chars: int):
        self.uint16(0)
        self.uint16(max_chars * 2)
        self.referent_id()
        self.uint32(max_chars)
        self.uint32(0)
        self.uint32(0)
        self.align(4)

    def conformant_byte_array(self, data: bytes):
        self.uint32(len(data))
        self.uint32(0)
        self.uint32(len(data))
        self.buffer += data
        self.align(4)

    def raw(self, data: bytes):
        self.buffer += data

    def getvalue(self) -> bytes:
        return bytes(self.buffer)


class NDRReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def align(self, size: int):
        padding = (-self.offset) % size
        self.offset += padding

    def uint8(self) -> int:
        self._check(1)
        value = struct.unpack_from("<B", self.data, self.offset)[0]
        self.offset += 1
        return value

    def uint16(self) -> int:
        self.align(2)
        self._check(2)
        value = struct.unpack_from("<H", self.data, self.offset)[0]
        self.offset += 2
        return value

    def uint32(self) -> int:
        self.align(4)
        self._check(4)
        value = struct.unpack_from("<I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def uint64(self) -> int:
        self.align(8)
        self._check(8)
        value = struct.unpack_from("<Q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def raw(self, length: int) -> bytes:
        self._check(length)
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def remaining(self) -> bytes:
        return self.data[self.offset:]

    def read_unicode_conformant_string(self) -> str:
        max_count = self.uint32()
        offset = self.uint32()
        actual_count = self.uint32()
        byte_len = actual_count * 2
        self._check(byte_len)
        raw = self.data[self.offset:self.offset + byte_len]
        self.offset += byte_len
        self.align(4)
        text = raw.decode("utf-16-le", errors="replace")
        return text.rstrip("\x00")

    def read_rrp_unicode_string(self) -> str:
        length = self.uint16()
        max_length = self.uint16()
        referent = self.uint32()
        if referent == 0:
            return ""
        max_count = self.uint32()
        offset = self.uint32()
        actual_count = self.uint32()
        byte_len = actual_count * 2
        self._check(byte_len)
        raw = self.data[self.offset:self.offset + byte_len]
        self.offset += byte_len
        self.align(4)
        text = raw.decode("utf-16-le", errors="replace")
        return text.rstrip("\x00")

    def pointer_present(self) -> bool:
        return self.uint32() != 0

    def read_conformant_byte_array(self) -> bytes:
        max_count = self.uint32()
        offset = self.uint32()
        actual_count = self.uint32()
        data = self.raw(actual_count)
        self.align(4)
        return data

    def _check(self, length: int):
        if self.offset + length > len(self.data):
            raise NDRError(
                f"NDR read out of bounds: need {length} bytes at offset {self.offset}, "
                f"buffer length {len(self.data)}"
            )


def uuid_to_bytes(uuid_str: str) -> bytes:
    hex_str = uuid_str.replace("-", "")
    time_low = hex_str[0:8]
    time_mid = hex_str[8:12]
    time_hi = hex_str[12:16]
    clock_seq = hex_str[16:20]
    node = hex_str[20:32]
    data = struct.pack("<I", int(time_low, 16))
    data += struct.pack("<H", int(time_mid, 16))
    data += struct.pack("<H", int(time_hi, 16))
    data += bytes.fromhex(clock_seq)
    data += bytes.fromhex(node)
    return data
