import struct

from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.ntlm import (
    AV_PAIR_DNS_COMPUTER_NAME,
    AV_PAIR_DNS_DOMAIN_NAME,
    AV_PAIR_EOL,
    AV_PAIR_NB_COMPUTER_NAME,
    AV_PAIR_NB_DOMAIN_NAME,
    NTLMSSP_NEGOTIATE_VERSION,
)
from protocol.smb.smb_constants import DIALECT_NAMES, STATUS_SUCCESS
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import probe_authentication_status, probe_ntlm_challenge

MODULE_NAME = "smbfingerprintmapper"

ANONYMOUS_CREDENTIALS = Credentials(username="", password="", domain="")

OS_FAMILY_HINTS = {
    (10, 0): "Windows 10 / 11 / Server 2016+",
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 0): "Windows Vista / Server 2008",
    (5, 2): "Windows XP x64 / Server 2003",
    (5, 1): "Windows XP",
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
    if len(raw_challenge) < 24:
        return {}
    flags = struct.unpack_from("<I", raw_challenge, 20)[0]
    if not (flags & NTLMSSP_NEGOTIATE_VERSION) or len(raw_challenge) < 56:
        return {}
    major, minor, build, _r1, _r2, _r3, _revision = struct.unpack_from("<BBHBBBB", raw_challenge, 48)
    return {"major": major, "minor": minor, "build": build}


def _os_family(major: int, minor: int) -> str:
    return OS_FAMILY_HINTS.get((major, minor), "unknown")


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
    challenge_error = ""
    try:
        raw_challenge = probe_ntlm_challenge(transport)
    except (OxSMBError, OSError) as exc:
        challenge_error = str(exc)
    finally:
        transport.close()

    name_fields = {}
    version_info = {}
    if len(raw_challenge) >= 32:
        target_info_len, _, target_info_off = (
            struct.unpack_from("<HHI", raw_challenge, 40) if len(raw_challenge) >= 48 else (0, 0, 0)
        )
        if target_info_len and target_info_off + target_info_len <= len(raw_challenge):
            name_fields = _parse_av_pairs(raw_challenge[target_info_off:target_info_off + target_info_len])
        version_info = _parse_version(raw_challenge)

    anon_transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    anonymous_logon_status = ""
    anonymous_logon_allowed = False
    try:
        anon_transport.connect()
        negotiate(anon_transport)
        raw_status = probe_authentication_status(anon_transport, ANONYMOUS_CREDENTIALS)
        anonymous_logon_status = f"0x{raw_status:08x}"
        anonymous_logon_allowed = raw_status == STATUS_SUCCESS
    except (OxSMBError, OSError) as exc:
        anonymous_logon_status = str(exc)
    finally:
        anon_transport.close()

    os_family = ""
    if version_info:
        os_family = _os_family(version_info.get("major", 0), version_info.get("minor", 0))

    data = {
        "negotiated_dialect": DIALECT_NAMES.get(
            negotiate_result.dialect_revision, hex(negotiate_result.dialect_revision)
        ),
        "signing_required": negotiate_result.signing_required,
        "server_guid": negotiate_result.server_guid.hex(),
        "challenge_obtained": bool(raw_challenge),
        "challenge_error": challenge_error,
        "netbios_computer_name": name_fields.get("netbios_computer_name", ""),
        "netbios_domain_name": name_fields.get("netbios_domain_name", ""),
        "dns_computer_name": name_fields.get("dns_computer_name", ""),
        "dns_domain_name": name_fields.get("dns_domain_name", ""),
        "os_version_disclosed": bool(version_info),
        "os_major_version": version_info.get("major"),
        "os_minor_version": version_info.get("minor"),
        "os_build": version_info.get("build"),
        "os_family_guess": os_family,
        "anonymous_logon_status": anonymous_logon_status,
        "anonymous_logon_allowed": anonymous_logon_allowed,
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
