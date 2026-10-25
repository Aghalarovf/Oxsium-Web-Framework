"""
SMB2/3 message signing support.

Implements, with no third-party dependencies, the primitives [MS-SMB2]
requires for signing: AES-128 (single block, encrypt-only), AES-CMAC
(NIST SP800-38B), the SP800-108 counter-mode KDF used to derive the
per-dialect SigningKey, and HMAC-SHA256 signing for the 2.x dialects.
"""

import hashlib
import hmac
import struct

from core.exceptions import OxSMBError
from protocol.smb.smb_constants import (
    SMB2_DIALECT_2_0_2,
    SMB2_DIALECT_2_1,
    SMB2_DIALECT_3_0,
    SMB2_DIALECT_3_0_2,
    SMB2_DIALECT_3_1_1,
)

# ---------------------------------------------------------------------------
# AES-128 (ECB, single block, encryption only) - pure Python.
# ---------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76af5768ca7918f06b038413e55bda922c6e8b85"
    "f4a9f49e95a97e243def22bd5d40234f941cc004236b24b36a04d7cc8f5a5f9d9276fcd"
    "3b7cca9ba1a9e21ce390d9fecaa59a38edd0744bdee2bfe13594cb30eb63c96b0e1554d"
    "a11fda06351cfabcbe19f82f3ac67e8f52c2db4b8c33f8d5f80e4e0a0c6151142a1c0a9"
    "08a1d8a05fdf02cf7adc9c56f6e44a24bbbdc63951b2a7ffe5f68e2f4e59ec9c0a8c030"
    "c9789ff39a9f43d8f4a4e1dc0a6c74ede4f7f61a8ad604a24c8ccda857f7cc8d41d83f7"
    "7a9b03e1cb63adb3817f25e8b1a1c0d7e18d1958d3c9c9f9f3c1b65f4bfab1038"
)
# Guard: regenerate the canonical AES S-box programmatically to avoid any
# transcription error in the hard-coded table above.


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _build_aes_sbox():
    # Multiplicative inverse in GF(2^8) (0 maps to 0), then the AES affine
    # transform. Built at import time so there is no risk of a typo'd table.
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gf_mul(x, y) == 1:
                inv[x] = y
                break
    sbox = [0] * 256
    for x in range(256):
        b = inv[x]
        s = b
        for shift in (1, 2, 3, 4):
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        s ^= 0x63
        sbox[x] = s & 0xFF
    return bytes(sbox)


_SBOX = _build_aes_sbox()

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _key_expansion(key: bytes):
    nk = 4
    nr = 10
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w


def _add_round_key(state, w, round_idx):
    for c in range(4):
        word = w[round_idx * 4 + c]
        for r in range(4):
            state[r][c] ^= word[r]


def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _mix_single_column(col):
    a = col
    return [
        _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3],
        a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3],
        a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3),
        _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2),
    ]


def _mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = _mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(key) != 16:
        raise OxSMBError("AES-128 requires a 16-byte key")
    if len(block) != 16:
        raise OxSMBError("AES-128 operates on 16-byte blocks")

    w = _key_expansion(key)
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    _add_round_key(state, w, 0)
    for round_idx in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, w, round_idx)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, w, 10)

    return bytes(state[r][c] for c in range(4) for r in range(4))


# ---------------------------------------------------------------------------
# AES-CMAC (NIST SP800-38B)
# ---------------------------------------------------------------------------

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _shift_left_1(data: bytes) -> bytes:
    value = int.from_bytes(data, "big") << 1
    value &= (1 << (8 * len(data))) - 1
    return value.to_bytes(len(data), "big")


def _cmac_subkeys(key: bytes):
    const_rb = 0x87
    zero_block = b"\x00" * 16
    l_val = aes128_encrypt_block(key, zero_block)

    msb_l = l_val[0] & 0x80
    k1 = _shift_left_1(l_val)
    if msb_l:
        k1 = bytes(k1[:-1]) + bytes([k1[-1] ^ const_rb])

    msb_k1 = k1[0] & 0x80
    k2 = _shift_left_1(k1)
    if msb_k1:
        k2 = bytes(k2[:-1]) + bytes([k2[-1] ^ const_rb])

    return k1, k2


def aes128_cmac(key: bytes, message: bytes) -> bytes:
    k1, k2 = _cmac_subkeys(key)
    block_size = 16

    if len(message) == 0:
        n = 1
        flag = False
    else:
        n = (len(message) + block_size - 1) // block_size
        flag = (len(message) % block_size) == 0

    if n == 0:
        n = 1

    if flag:
        last_block_index = (n - 1) * block_size
        last_block = _xor_bytes(message[last_block_index:], k1)
    else:
        last_block_index = (n - 1) * block_size
        remainder = message[last_block_index:]
        padded = remainder + b"\x80" + b"\x00" * (block_size - len(remainder) - 1)
        last_block = _xor_bytes(padded, k2)

    x = b"\x00" * block_size
    for i in range(n - 1):
        block = message[i * block_size:(i + 1) * block_size]
        x = aes128_encrypt_block(key, _xor_bytes(x, block))

    return aes128_encrypt_block(key, _xor_bytes(x, last_block))


# ---------------------------------------------------------------------------
# NIST SP800-108 counter-mode KDF with HMAC-SHA256 as the PRF.
# ---------------------------------------------------------------------------

def sp800_108_counter_kdf(key: bytes, label: bytes, context: bytes, length_bits: int = 128) -> bytes:
    output = b""
    counter = 1
    length_bytes = struct.pack(">I", length_bits)
    while len(output) * 8 < length_bits:
        input_data = struct.pack(">I", counter) + label + b"\x00" + context + length_bytes
        output += hmac.new(key, input_data, hashlib.sha256).digest()
        counter += 1
    return output[: length_bits // 8]


# ---------------------------------------------------------------------------
# Dialect-specific signing key derivation and packet signature computation.
# ---------------------------------------------------------------------------

_LABEL_SMB2AESCMAC = b"SMB2AESCMAC\x00"
_CONTEXT_SMBSIGN = b"SmbSign\x00"
_LABEL_SMBSIGNINGKEY = b"SMBSigningKey\x00"

HMAC_SHA256_DIALECTS = (SMB2_DIALECT_2_0_2, SMB2_DIALECT_2_1)
AES_CMAC_DIALECTS = (SMB2_DIALECT_3_0, SMB2_DIALECT_3_0_2, SMB2_DIALECT_3_1_1)


def derive_signing_key(dialect: int, session_key: bytes, preauth_integrity_hash: bytes) -> bytes:
    if dialect in HMAC_SHA256_DIALECTS:
        # [MS-SMB2] 3.1.4.1: for 2.0.2/2.1 the signing key IS the session key.
        return session_key
    if dialect in (SMB2_DIALECT_3_0, SMB2_DIALECT_3_0_2):
        return sp800_108_counter_kdf(session_key, _LABEL_SMB2AESCMAC, _CONTEXT_SMBSIGN, 128)
    if dialect == SMB2_DIALECT_3_1_1:
        return sp800_108_counter_kdf(session_key, _LABEL_SMBSIGNINGKEY, preauth_integrity_hash, 128)
    raise OxSMBError(f"No signing key derivation defined for dialect 0x{dialect:04x}")


def compute_signature(dialect: int, signing_key: bytes, packet_with_zeroed_signature: bytes) -> bytes:
    if dialect in HMAC_SHA256_DIALECTS:
        return hmac.new(signing_key, packet_with_zeroed_signature, hashlib.sha256).digest()[:16]
    if dialect in AES_CMAC_DIALECTS:
        return aes128_cmac(signing_key, packet_with_zeroed_signature)
    raise OxSMBError(f"No signing algorithm defined for dialect 0x{dialect:04x}")
