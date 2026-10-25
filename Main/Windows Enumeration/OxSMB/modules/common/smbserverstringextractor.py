import struct

from core.exceptions import OxSMBError, SMBSessionSetupError
from core.smb_transport import SMBTransport
from protocol.smb.ntlm import (
    AV_PAIR_DNS_COMPUTER_NAME,
    AV_PAIR_DNS_DOMAIN_NAME,
    AV_PAIR_EOL,
    AV_PAIR_NB_COMPUTER_NAME,
    AV_PAIR_NB_DOMAIN_NAME,
    NTLMSSP_NEGOTIATE_VERSION,
)
from protocol.smb.smb_constants import DIALECT_NAMES
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import probe_ntlm_challenge

MODULE_NAME = "smbserverstringextractor"

NTLM_REVISION_NAMES = {
    0x0F: "NTLMSSP_REVISION_W2K3",
}


def _parse_av_pairs(target_info: bytes) -> dict:
    fields = {}
    offset = 0
    while offset + 4 <= len(target_info):
        av_id, av_len = struct.unpack_from("<HH", target_info, offset)
        offset += 4
        if av_id == AV_PAIR_EOL:
            break
        value = target_info[offset:offset + av_len]
        offset += av_len
        if av_id == AV_PAIR_NB_COMPUTER_NAME:
            fields["netbios_computer_name"] = value.decode("utf-16-le", errors="replace")
        elif av_id == AV_PAIR_NB_DOMAIN_NAME:
            fields["netbios_domain_name"] = value.decode("utf-16-le", errors="replace")
        elif av_id == AV_PAIR_DNS_COMPUTER_NAME:
            fields["dns_computer_name"] = value.decode("utf-16-le", errors="replace")
        elif av_id == AV_PAIR_DNS_DOMAIN_NAME:
            fields["dns_domain_name"] = value.decode("utf-16-le", errors="replace")
    return fields


def _parse_version(raw_challenge: bytes) -> dict:
    flags = struct.unpack_from("<I", raw_challenge, 20)[0]
    if not (flags & NTLMSSP_NEGOTIATE_VERSION) or len(raw_challenge) < 56:
        return {}

    major, minor, build, _reserved1, _reserved2, _reserved3, revision = struct.unpack_from(
        "<BBHBBBB", raw_challenge, 48
    )
    return {
        "product_major_version": major,
        "product_minor_version": minor,
        "product_build": build,
        "ntlm_revision": NTLM_REVISION_NAMES.get(revision, revision),
    }


def _classify_consistency(negotiated_dialect: int, version_info: dict) -> str:
    if not version_info:
        return "unknown"

    major = version_info.get("product_major_version", 0)
    build = version_info.get("product_build", 0)

    dialect_implies_modern = negotiated_dialect >= 0x0300
    version_implies_legacy = major <= 5 or (major == 6 and build and build < 9200)

    if dialect_implies_modern and version_implies_legacy:
        return "inconsistent_possible_honeypot"
    return "consistent"


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    try:
        transport.connect()
        negotiate_result = negotiate(transport)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    raw_challenge = b""
    challenge_status = "obtained"
    try:
        raw_challenge = probe_ntlm_challenge(transport)
    except SMBSessionSetupError as exc:
        challenge_status = str(exc)
    except OSError as exc:
        challenge_status = str(exc)
    finally:
        transport.close()

    name_fields = {}
    version_info = {}
    if len(raw_challenge) >= 32:
        flags = struct.unpack_from("<I", raw_challenge, 20)[0]
        target_info_len, _, target_info_off = struct.unpack_from("<HHI", raw_challenge, 40) if len(
            raw_challenge
        ) >= 48 else (0, 0, 0)
        if target_info_len and target_info_off + target_info_len <= len(raw_challenge):
            target_info = raw_challenge[target_info_off:target_info_off + target_info_len]
            name_fields = _parse_av_pairs(target_info)
        version_info = _parse_version(raw_challenge)

    negotiated_dialect = DIALECT_NAMES.get(
        negotiate_result.dialect_revision, hex(negotiate_result.dialect_revision)
    )
    consistency_state = _classify_consistency(negotiate_result.dialect_revision, version_info)

    data = {
        "negotiated_dialect": negotiated_dialect,
        "challenge_status": challenge_status,
        "netbios_computer_name": name_fields.get("netbios_computer_name", ""),
        "netbios_domain_name": name_fields.get("netbios_domain_name", ""),
        "dns_computer_name": name_fields.get("dns_computer_name", ""),
        "dns_domain_name": name_fields.get("dns_domain_name", ""),
        "os_version_disclosed": bool(version_info),
        "product_major_version": version_info.get("product_major_version"),
        "product_minor_version": version_info.get("product_minor_version"),
        "product_build": version_info.get("product_build"),
        "version_dialect_consistency": consistency_state,
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
