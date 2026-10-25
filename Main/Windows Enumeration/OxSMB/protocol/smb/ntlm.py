import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

from core.auth import Credentials
from core.exceptions import NTLMError

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

NTLMSSP_NEGOTIATE = 1
NTLMSSP_CHALLENGE = 2
NTLMSSP_AUTHENTICATE = 3

NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_OEM = 0x00000002
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_NEGOTIATE_56 = 0x80000000
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_VERSION = 0x02000000

AV_PAIR_EOL = 0x0000
AV_PAIR_NB_COMPUTER_NAME = 0x0001
AV_PAIR_NB_DOMAIN_NAME = 0x0002
AV_PAIR_DNS_COMPUTER_NAME = 0x0003
AV_PAIR_DNS_DOMAIN_NAME = 0x0004
AV_PAIR_TIMESTAMP = 0x0007


def build_negotiate_message() -> bytes:
    flags = (
        NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
    )
    message = NTLMSSP_SIGNATURE
    message += struct.pack("<I", NTLMSSP_NEGOTIATE)
    message += struct.pack("<I", flags)
    message += struct.pack("<HHI", 0, 0, 0)
    message += struct.pack("<HHI", 0, 0, 0)
    return message


@dataclass
class ChallengeMessage:
    server_challenge: bytes
    target_name: bytes
    target_info: bytes
    flags: int
    raw: bytes


def parse_challenge_message(data: bytes) -> ChallengeMessage:
    if data[0:8] != NTLMSSP_SIGNATURE:
        raise NTLMError("Invalid NTLMSSP signature in challenge message")
    message_type = struct.unpack("<I", data[8:12])[0]
    if message_type != NTLMSSP_CHALLENGE:
        raise NTLMError(f"Expected NTLM challenge message, got type {message_type}")

    target_name_len, target_name_max, target_name_off = struct.unpack("<HHI", data[12:20])
    flags = struct.unpack("<I", data[20:24])[0]
    server_challenge = data[24:32]

    target_info = b""
    if flags & NTLMSSP_NEGOTIATE_TARGET_INFO and len(data) >= 48:
        ti_len, ti_max, ti_off = struct.unpack("<HHI", data[40:48])
        if ti_len and ti_off + ti_len <= len(data):
            target_info = data[ti_off:ti_off + ti_len]

    target_name = b""
    if target_name_len and target_name_off + target_name_len <= len(data):
        target_name = data[target_name_off:target_name_off + target_name_len]

    return ChallengeMessage(
        server_challenge=server_challenge,
        target_name=target_name,
        target_info=target_info,
        flags=flags,
        raw=data,
    )


def _md4_fallback(data: bytes) -> bytes:
    def leftrotate(x, c):
        x &= 0xFFFFFFFF
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    orig_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack("<Q", orig_len_bits)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    s1 = [3, 7, 11, 19]
    s2 = [3, 5, 9, 13]
    s3 = [3, 9, 11, 15]
    order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

    for offset in range(0, len(padded), 64):
        x = list(struct.unpack("<16I", padded[offset:offset + 64]))
        a, b, c, d = a0, b0, c0, d0

        for i in range(16):
            a, b, c, d = d, leftrotate((a + f(b, c, d) + x[i]) & 0xFFFFFFFF, s1[i % 4]), b, c

        for i in range(16):
            k = order2[i]
            a, b, c, d = d, leftrotate((a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s2[i % 4]), b, c

        for i in range(16):
            k = order3[i]
            a, b, c, d = d, leftrotate((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[i % 4]), b, c

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def _md4_digest(data: bytes) -> bytes:
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError):
        return _md4_fallback(data)


def ntowfv1(password: str) -> bytes:
    return _md4_digest(password.encode("utf-16-le"))


def ntowfv2(nt_hash: bytes, username: str, domain: str) -> bytes:
    identity = (username.upper() + domain).encode("utf-16-le")
    return hmac.new(nt_hash, identity, hashlib.md5).digest()


def resolve_nt_hash(credentials: Credentials) -> bytes:
    if credentials.nt_hash:
        return bytes.fromhex(credentials.nt_hash)
    return ntowfv1(credentials.password)


def build_ntlmv2_response(nt_hash: bytes, username: str, domain: str, server_challenge: bytes, target_info: bytes):
    response_key = ntowfv2(nt_hash, username, domain)

    timestamp = struct.pack("<Q", int((time.time() + 11644473600) * 10000000))
    client_challenge = __import__("os").urandom(8)

    if not target_info:
        target_info = struct.pack("<HH", AV_PAIR_EOL, 0)

    temp = struct.pack("<I", 0x00000101)
    temp += struct.pack("<I", 0)
    temp += timestamp
    temp += client_challenge
    temp += struct.pack("<I", 0)
    temp += target_info
    temp += struct.pack("<I", 0)

    nt_proof = hmac.new(response_key, server_challenge + temp, hashlib.md5).digest()
    ntlmv2_response = nt_proof + temp

    session_base_key = hmac.new(response_key, nt_proof, hashlib.md5).digest()

    return ntlmv2_response, session_base_key


def build_authenticate_message(
    credentials: Credentials,
    challenge: ChallengeMessage,
    workstation: str = "OXSMB",
) -> bytes:
    nt_hash = resolve_nt_hash(credentials)
    ntlmv2_response, session_key = build_ntlmv2_response(
        nt_hash, credentials.username, credentials.domain, challenge.server_challenge, challenge.target_info
    )

    lm_response = b"\x00" * 24

    domain_bytes = credentials.domain.encode("utf-16-le")
    user_bytes = credentials.username.encode("utf-16-le")
    workstation_bytes = workstation.encode("utf-16-le")

    flags = (
        NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
        | NTLMSSP_REQUEST_TARGET
    )

    fixed_part_len = 8 + 4 + (8 * 6) + 4
    offset = fixed_part_len

    def field_entry(blob):
        nonlocal offset
        entry = struct.pack("<HHI", len(blob), len(blob), offset)
        offset += len(blob)
        return entry

    lm_field = field_entry(lm_response)
    nt_field = field_entry(ntlmv2_response)
    domain_field = field_entry(domain_bytes)
    user_field = field_entry(user_bytes)
    workstation_field = field_entry(workstation_bytes)
    session_key_field = field_entry(b"")

    message = NTLMSSP_SIGNATURE
    message += struct.pack("<I", NTLMSSP_AUTHENTICATE)
    message += lm_field
    message += nt_field
    message += domain_field
    message += user_field
    message += workstation_field
    message += session_key_field
    message += struct.pack("<I", flags)

    payload = lm_response + ntlmv2_response + domain_bytes + user_bytes + workstation_bytes

    return message + payload, session_key
