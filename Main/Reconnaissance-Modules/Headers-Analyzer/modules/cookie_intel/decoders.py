"""Classifies and (safely, read-only) decodes cookie values.

Never deserializes anything (no pickle.loads / Marshal.load) - only inspects
magic bytes and structure to report what the value *is*, which is enough to
flag object-injection risk without executing untrusted payloads.
"""

import base64
import binascii
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

PREVIEW_LIMIT = 500

HEX_HASH_LENGTHS = {
    32: ["MD5", "MD4", "NTLM"],
    40: ["SHA-1"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b"],
}
HEX_ALGO_FUNCS = {
    "MD5": hashlib.md5, "MD4": None, "NTLM": None, "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224, "SHA3-224": hashlib.sha3_224,
    "SHA-256": hashlib.sha256, "SHA3-256": hashlib.sha3_256,
    "SHA-384": hashlib.sha384, "SHA3-384": hashlib.sha3_384,
    "SHA-512": hashlib.sha512, "SHA3-512": hashlib.sha3_512,
    "BLAKE2s": hashlib.blake2s, "BLAKE2b": hashlib.blake2b,
}
# Candidates we'll actually try hashing (BLAKE2 variants are listed as
# possible digest-size matches, but we don't brute-force preimages against
# them since they're rarely used for session identifiers).
HEX_PREIMAGE_ALGOS = frozenset({
    "MD5", "SHA-1", "SHA-224", "SHA3-224", "SHA-256", "SHA3-256",
    "SHA-384", "SHA3-384", "SHA-512", "SHA3-512",
})

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_NUMERIC_RE = re.compile(r"^-?[0-9]+$")

PRIVILEGE_FIELD_HINTS = (
    "role", "admin", "is_admin", "isadmin", "permissions", "permission",
    "is_staff", "is_superuser", "superuser", "privilege", "scope", "entitlement",
)

PREIMAGE_CANDIDATES_BASE = [
    "", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
    "admin", "administrator", "root", "test", "guest", "user", "username",
    "null", "undefined", "none", "password", "123456", "true", "false",
]

PROVIDER_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    ("Stripe secret key", "CRITICAL", re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{10,}\b")),
    ("AWS access key ID", "CRITICAL", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", "CRITICAL", re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b")),
    ("Google OAuth access token", "HIGH", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b")),
    ("Slack token", "CRITICAL", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("npm access token", "CRITICAL", re.compile(r"\bnpm_[0-9A-Za-z]{30,}\b")),
    ("Private key material", "CRITICAL", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


def printable_text(data: bytes) -> Optional[str]:
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return ""
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if printable / len(text) < 0.85:
        return None
    return text


def _b64_variants(value: str):
    for pad_mode in ("urlsafe", "std"):
        for padding in ("", "=", "==", "==="):
            candidate = value + padding
            try:
                if pad_mode == "urlsafe":
                    yield base64.urlsafe_b64decode(candidate)
                else:
                    yield base64.b64decode(candidate)
            except (binascii.Error, ValueError):
                continue


def _b64_decode_first(value: str) -> Optional[bytes]:
    for data in _b64_variants(value):
        return data
    return None


def _preview(text: str, limit: int = PREVIEW_LIMIT) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _token_preview(token: str) -> str:
    return f"{token[:4]}...[{len(token)} chars]"


def scan_provider_tokens(text: str) -> List[Tuple[str, str, str]]:
    """Return (provider, severity, preview) for any leaked provider-credential patterns in text."""
    hits: List[Tuple[str, str, str]] = []
    if not text:
        return hits
    for provider, severity, pattern in PROVIDER_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append((provider, severity, _token_preview(match.group(0))))
    return hits


def _format_epoch(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return "unknown"


def _privilege_fields(obj: Any) -> List[str]:
    from .structure import flatten

    found = []
    if isinstance(obj, dict):
        leaves, _ = flatten(obj)
        for path, _value in leaves:
            key = path.split(".")[-1].split("[")[0].lower()
            if key in PRIVILEGE_FIELD_HINTS and key not in found:
                found.append(key)
    return found


def _new_profile() -> Dict[str, Any]:
    return {
        "type": "opaque",
        "decoded": None,
        "layers": [],
        "assessment": None,
        "hash_candidates": [],
        "preimage": None,
        "provider_tokens": [],
        "signals": [],
        "time_hint": None,
        "signed": False,
        "encrypted": False,
    }


# Decoded types that imply the cookie carries meaningful, security-relevant
# state (and should therefore be treated as sensitive regardless of its name).
_SIGNED_TYPES = frozenset({"jwt", "flask-itsdangerous", "rails-marshal", "django-signed"})
_ENCRYPTED_OR_RISKY_TYPES = frozenset({
    "laravel-envelope", "java-serialized", "python-pickle", "php-serialized",
})


def _finalize_signed_encrypted(profile: Dict[str, Any]) -> None:
    kind = profile["type"]
    if kind in _SIGNED_TYPES:
        profile["signed"] = True
    if kind in _ENCRYPTED_OR_RISKY_TYPES:
        profile["encrypted"] = True


# ---------------------------------------------------------------------------
# Structured-format detectors. Each returns True and mutates `profile` if it
# recognized and handled the value.
# ---------------------------------------------------------------------------

def _try_jwt(value: str, profile: Dict[str, Any], reference_epoch: float) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header_bytes = _b64_decode_first(parts[0])
    if header_bytes is None:
        return False
    header_text = printable_text(header_bytes)
    if header_text is None:
        return False
    try:
        header = json.loads(header_text)
    except ValueError:
        return False
    if not isinstance(header, dict) or "alg" not in header:
        return False

    payload_bytes = _b64_decode_first(parts[1])
    payload_text = printable_text(payload_bytes) if payload_bytes is not None else None
    try:
        payload = json.loads(payload_text) if payload_text else None
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        payload = {}

    profile["type"] = "jwt"
    profile["layers"] = ["base64url", "json"]
    profile["_decoded_obj"] = {"header": header, "payload": payload}
    combined = json.dumps({"header": header, "payload": payload}, separators=(",", ":"))
    profile["decoded"] = _preview(combined)
    signals = profile["signals"]
    signals.append(("INFO", f"Decoded contents: {_preview(combined, 2000)}", "JWT"))

    alg = str(header.get("alg", "")).upper()
    signals.append(("INFO", f"Signing algorithm: {alg or 'unspecified'}", "JWT"))
    if alg.startswith("HS"):
        signals.append(("INFO", "Symmetric HMAC signature: verification uses a shared secret, so security depends entirely on that secret being long and random", "JWT"))
    elif alg in ("NONE", ""):
        signals.append(("HIGH", "Algorithm is 'none' or unspecified; if the server accepts unsigned tokens, authentication can be bypassed entirely", "JWT"))
    elif alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES"):
        signals.append(("INFO", "Asymmetric signature: verification uses a public key, so algorithm-confusion attacks (e.g. RS256->HS256) are worth testing", "JWT"))

    kid = header.get("kid")
    if isinstance(kid, str) and re.search(r"\.\./|[;|`$]|\x00", kid):
        signals.append(("HIGH", f"Header 'kid' contains path or injection-prone characters ({kid}); test the key lookup for traversal and injection", "JWT"))

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        remaining_days = (exp - reference_epoch) / 86400
        if remaining_days < 0:
            signals.append(("MEDIUM", f"Token is expired (exp={_format_epoch(exp)}); confirm the server actually rejects expired tokens", "JWT"))
        elif remaining_days > 7:
            signals.append(("LOW", f"Long-lived token, about {remaining_days:.1f} days remaining at capture time (exp={_format_epoch(exp)})", "JWT"))
    else:
        signals.append(("MEDIUM", "No 'exp' claim; the token never expires unless revoked out-of-band", "JWT"))

    if "iss" not in payload and "aud" not in payload:
        signals.append(("LOW", "Neither 'iss' nor 'aud' claim is present; token issuer and audience cannot be validated by a relying party", "JWT"))
    if "jti" not in payload:
        signals.append(("INFO", "No 'jti' claim; individual tokens cannot be tracked or revoked by identifier", "JWT"))

    privilege_fields = [f for f in _privilege_fields(payload) if f not in ("exp", "iat", "nbf")]
    if privilege_fields:
        signals.append(("INFO", f"Payload exposes claim(s) worth testing for tampering: {', '.join(sorted(set(privilege_fields)))}", "JWT"))

    if re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", json.dumps(payload)):
        signals.append(("LOW", "Structure exposes personal data (email address) readable by whoever holds the cookie", "JWT"))

    return True


def _try_rails_marshal(value: str, profile: Dict[str, Any]) -> bool:
    if "--" not in value:
        return False
    payload_part, _, sig = value.rpartition("--")
    if not payload_part or not re.match(r"^[0-9a-f]{32,64}$", sig):
        return False
    data = _b64_decode_first(payload_part)
    if data is None or not data.startswith(b"\x04\x08"):
        return False
    profile["type"] = "rails-marshal"
    profile["layers"] = ["base64", "marshal"]
    profile["decoded"] = "<Ruby Marshal binary payload, not deserialized>"
    algo = "HMAC-SHA1" if len(sig) == 40 else "HMAC-SHA256"
    profile["signals"].append((
        "MEDIUM",
        f"Rails signed cookie ({algo}) carrying a Ruby Marshal payload; integrity relies on secret_key_base, and its exposure would turn this into an object-injection vector",
        "Value",
    ))
    return True


def _try_flask_itsdangerous(value: str, profile: Dict[str, Any], reference_epoch: float) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    payload_bytes = _b64_decode_first(parts[0])
    payload_text = printable_text(payload_bytes) if payload_bytes is not None else None
    if payload_text is None:
        return False
    try:
        payload = json.loads(payload_text)
    except ValueError:
        return False
    ts_bytes = _b64_decode_first(parts[1])
    sig_bytes = _b64_decode_first(parts[2])
    if ts_bytes is None or sig_bytes is None or len(ts_bytes) > 8 or not (len(sig_bytes) in (20, 32, 28, 48, 64)):
        return False

    profile["type"] = "flask-itsdangerous"
    profile["layers"] = ["base64url", "json"]
    profile["_decoded_obj"] = payload
    profile["decoded"] = _preview(json.dumps(payload, separators=(",", ":")))
    signals = profile["signals"]

    issued = int.from_bytes(ts_bytes, "big") if ts_bytes else None
    issued_str = f", issued {_format_epoch(issued)}" if issued else ""
    algo = {20: "HMAC-SHA1", 32: "HMAC-SHA256", 28: "HMAC-SHA224", 48: "HMAC-SHA384", 64: "HMAC-SHA512"}.get(len(sig_bytes), "HMAC")
    signals.append(("INFO", f"itsdangerous / Flask signed cookie ({algo}){issued_str}, payload: {json.dumps(payload, separators=(',', ':'))}", "Value"))
    signals.append(("LOW", "Signed but not encrypted: the payload is readable by the client, and integrity depends entirely on the strength of the server secret key", "Value"))

    privilege_fields = _privilege_fields(payload) if isinstance(payload, dict) else []
    if privilege_fields:
        signals.append(("INFO", f"Payload exposes claim(s) worth testing for tampering: {', '.join(sorted(set(privilege_fields)))}", "Value"))
    return True


def _try_django_signed(value: str, profile: Dict[str, Any]) -> bool:
    parts = value.split(":")
    if len(parts) != 3:
        return False
    data_part, ts_part, sig_part = parts
    if not re.match(r"^[0-9a-zA-Z_-]+$", data_part) or not re.match(r"^[0-9a-zA-Z_-]{20,}$", sig_part):
        return False
    if not re.match(r"^[0-9a-zA-Z_-]+$", ts_part):
        return False
    data = _b64_decode_first(data_part)
    text = printable_text(data) if data is not None else None
    if text is None:
        return False
    profile["type"] = "django-signed"
    profile["layers"] = ["base64url", "colon-split"]
    profile["decoded"] = _preview(text)
    profile["signals"].append((
        "INFO",
        "Django signed cookie value (value:timestamp:signature); integrity depends on SECRET_KEY, and the payload itself is unencrypted",
        "Value",
    ))
    return True


def _try_laravel(value: str, profile: Dict[str, Any]) -> bool:
    candidate = unquote(value)
    data = _b64_decode_first(candidate)
    if data is None:
        return False
    text = printable_text(data)
    if text is None:
        return False
    try:
        obj = json.loads(text)
    except ValueError:
        return False
    if not (isinstance(obj, dict) and {"iv", "value", "mac"} <= set(obj)):
        return False
    profile["type"] = "laravel-envelope"
    profile["layers"] = ["urldecode", "base64", "json"]
    profile["decoded"] = _preview(text)
    profile["signals"].append((
        "INFO",
        "Laravel encrypted cookie envelope (iv/value/mac); confidentiality and integrity depend on APP_KEY secrecy",
        "Value",
    ))
    return True


def _try_java_serialized(value: str, profile: Dict[str, Any]) -> bool:
    data = _b64_decode_first(value)
    if data is None or not data.startswith(b"\xac\xed\x00\x05"):
        return False
    profile["type"] = "java-serialized"
    profile["layers"] = ["base64", "java-serialization"]
    profile["decoded"] = "<Java serialized object stream, not deserialized>"
    profile["signals"].append((
        "HIGH",
        "Java serialized object stream held in a client-controlled cookie; deserializing untrusted data is a critical risk unless the server authenticates it first",
        "Value",
    ))
    return True


def _try_python_pickle(value: str, profile: Dict[str, Any]) -> bool:
    data = _b64_decode_first(value)
    if data is None or len(data) < 2:
        return False
    if not (data[0] == 0x80 and data[1] in (0, 1, 2, 3, 4, 5)):
        return False
    profile["type"] = "python-pickle"
    profile["layers"] = ["base64", "pickle"]
    profile["decoded"] = "<Python pickle byte stream, not deserialized>"
    profile["signals"].append((
        "HIGH",
        f"Python pickle byte stream (protocol {data[1]}) held in a client-controlled cookie; unpickling untrusted data allows arbitrary code execution",
        "Value",
    ))
    return True


def _try_php_serialized(value: str, profile: Dict[str, Any]) -> bool:
    text = unquote(value)
    if not re.match(r"^(a:\d+:\{|O:\d+:\"|s:\d+:\"|i:\d+;)", text):
        return False
    profile["type"] = "php-serialized"
    profile["layers"] = ["urldecode"]
    profile["decoded"] = _preview(text)
    profile["signals"].append((
        "HIGH",
        "PHP serialized data held in a client-controlled cookie; unserialize() on untrusted input can trigger PHP object injection",
        "Value",
    ))
    return True


def _try_urlencoded_structured(value: str, profile: Dict[str, Any]) -> bool:
    if "%" not in value and "+" not in value:
        return False
    text = unquote(value)
    if "=" not in text or "&" not in text:
        return False
    pairs = [p for p in text.split("&") if "=" in p]
    if len(pairs) < 2:
        return False
    parsed = {}
    for pair in pairs:
        key, _, val = pair.partition("=")
        parsed[key] = val
    profile["type"] = "urlencoded-structured"
    profile["layers"] = ["urldecode"]
    profile["_decoded_obj"] = parsed
    profile["decoded"] = _preview(text)
    signals = profile["signals"]
    signals.append(("INFO", f"URL-decoded structured value: {_preview(text)}", "Value"))
    privilege_fields = [k for k in parsed if k.lower() in PRIVILEGE_FIELD_HINTS]
    if privilege_fields:
        signals.append((
            "HIGH",
            f"Client-side structure contains privilege-looking field(s): {', '.join(privilege_fields)}; test for tampering (e.g. changing role/admin fields)",
            "Value",
        ))
    signals.append((
        "LOW",
        "Cookie carries structured data that is readable, and likely editable, by the client; confirm the server validates it rather than trusting it as-is",
        "Value",
    ))
    return True


def _try_base64_json(value: str, profile: Dict[str, Any]) -> bool:
    data = _b64_decode_first(value)
    if data is None:
        return False
    text = printable_text(data)
    if text is None:
        return False
    try:
        obj = json.loads(text)
    except ValueError:
        return False
    if not isinstance(obj, (dict, list)):
        return False
    profile["type"] = "base64-json"
    profile["layers"] = ["base64", "json"]
    profile["_decoded_obj"] = obj
    compact = json.dumps(obj, separators=(",", ":"))
    profile["decoded"] = _preview(compact)
    profile["signals"].append(("INFO", f"Base64-decoded JSON content: {_preview(compact, 2000)}", "Value"))
    privilege_fields = _privilege_fields(obj) if isinstance(obj, dict) else []
    if privilege_fields:
        profile["signals"].append((
            "INFO",
            f"Decoded structure exposes claim(s) worth testing for tampering: {', '.join(sorted(set(privilege_fields)))}",
            "Value",
        ))
    return True


def _try_base64_text(value: str, profile: Dict[str, Any]) -> bool:
    data = _b64_decode_first(value)
    if data is None or len(data) == 0:
        return False
    text = printable_text(data)
    if text is None:
        return False
    if len(value) < 8:
        return False
    # Only claim this as a meaningful decode if it looks structured or leaks
    # something worth flagging - otherwise leave it classified as opaque so we
    # don't manufacture noise from incidentally-base64-shaped random tokens.
    looks_structured = ("=" in text or ":" in text or "{" in text or "&" in text)
    if not (looks_structured or scan_provider_tokens(text)):
        return False
    profile["type"] = "base64-text"
    profile["layers"] = ["base64"]
    profile["decoded"] = _preview(text)
    profile["signals"].append(("INFO", f"Base64-decoded content: {_preview(text)}", "Value"))
    return True


def _try_uuid(value: str, profile: Dict[str, Any]) -> bool:
    if not _UUID_RE.match(value):
        return False
    profile["type"] = "uuid"
    profile["layers"] = []
    return True


def _try_hex_token(value: str, profile: Dict[str, Any], extras: List[str]) -> bool:
    if not _HEX_RE.match(value) or len(value) % 2 != 0:
        return False
    candidates = HEX_HASH_LENGTHS.get(len(value))
    if not candidates:
        return False
    profile["type"] = "hex-token"
    profile["layers"] = []
    profile["hash_candidates"] = list(candidates)

    lowered = value.lower()
    preimage_pool = list(PREIMAGE_CANDIDATES_BASE) + list(extras or [])
    for algo in candidates:
        if algo not in HEX_PREIMAGE_ALGOS:
            continue
        func = HEX_ALGO_FUNCS.get(algo)
        if func is None:
            continue
        for candidate in preimage_pool:
            try:
                digest = func(str(candidate).encode("utf-8", "ignore")).hexdigest()
            except Exception:
                continue
            if digest == lowered:
                profile["preimage"] = {"algorithm": algo, "preimage": str(candidate)}
                return True
    return True


def _try_numeric(value: str, profile: Dict[str, Any], reference_epoch: float) -> bool:
    if not _NUMERIC_RE.match(value):
        return False
    profile["type"] = "numeric"
    profile["layers"] = []
    if len(value) in (10, 13) and value.isdigit():
        try:
            ts = int(value) / (1000 if len(value) == 13 else 1)
            if 946684800 <= ts <= reference_epoch + 86400 * 365 * 5:
                profile["time_hint"] = _format_epoch(ts)
        except (ValueError, OverflowError):
            pass
    return True


# ---------------------------------------------------------------------------

def inspect_value(value: str, reference_epoch: float, extras: Optional[List[str]] = None, deep: bool = True) -> Dict[str, Any]:
    profile = _new_profile()
    if value == "":
        profile["type"] = "empty"
        profile["assessment"] = {
            "length": 0, "charset": "none", "shannon_bits_per_char": 0.0,
            "uniformity": 0.0, "estimated_bits": 0.0, "patterns": [],
        }
        return profile

    extras = extras or []
    decoded_texts: List[str] = []

    matched = False
    for detector in (
        lambda: _try_jwt(value, profile, reference_epoch),
        lambda: _try_rails_marshal(value, profile),
        lambda: _try_flask_itsdangerous(value, profile, reference_epoch),
        lambda: _try_laravel(value, profile),
        lambda: _try_django_signed(value, profile),
        lambda: _try_java_serialized(value, profile),
        lambda: _try_python_pickle(value, profile),
        lambda: _try_php_serialized(value, profile),
        lambda: _try_urlencoded_structured(value, profile),
        lambda: _try_uuid(value, profile),
        lambda: _try_hex_token(value, profile, extras),
        lambda: _try_numeric(value, profile, reference_epoch),
        lambda: _try_base64_json(value, profile),
        lambda: _try_base64_text(value, profile),
    ):
        try:
            if detector():
                matched = True
                break
        except Exception:
            continue

    if not matched:
        profile["type"] = "opaque-token" if _ALNUM_SAFE(value) else "opaque"

    _finalize_signed_encrypted(profile)

    if profile.get("decoded"):
        decoded_texts.append(str(profile["decoded"]))

    # Provider-token scanning: scan both the raw value and anything decoded from it.
    seen_providers = set()
    for text in [value] + decoded_texts:
        for provider, severity, preview in scan_provider_tokens(text):
            if provider in seen_providers:
                continue
            seen_providers.add(provider)
            profile["provider_tokens"].append(provider)
            profile["signals"].append((
                severity,
                f"{provider} pattern detected inside the decoded cookie value ({preview}); credentials must never be stored in client-side cookies",
                "Secret",
            ))

    profile["assessment"] = assess_wrapper(value)
    return profile


def _ALNUM_SAFE(value: str) -> bool:
    return bool(re.match(r"^[0-9a-zA-Z_\-]+$", value))


def assess_wrapper(value: str) -> Dict[str, Any]:
    from .entropy import assess
    return assess(value)
