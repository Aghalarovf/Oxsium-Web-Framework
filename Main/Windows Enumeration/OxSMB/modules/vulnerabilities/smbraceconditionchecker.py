import struct

from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.winreg import close_key, enum_all_subkeys, open_hklm, open_key
from protocol.smb.ntlm import NTLMSSP_NEGOTIATE_VERSION
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import probe_ntlm_challenge

MODULE_NAME = "smbraceconditionchecker"

CVE_ID = "CVE-2025-50169"
MS_TITLE = "Windows SMB Remote Code Execution Vulnerability"

AFFECTED_MAJOR = 10
AFFECTED_MINOR = 0
AFFECTED_BASE_BUILD = 26100

FIX_KB_NUMBERS = {"5063878", "5064010"}

PIPE_NAME = "winreg"
PACKAGES_SUBKEY = "Component Based Servicing\\Packages"

VERDICT_NOT_APPLICABLE = "not_applicable"
VERDICT_PATCHED = "patched"
VERDICT_LIKELY_VULNERABLE = "likely_vulnerable"
VERDICT_NEEDS_VERIFICATION = "needs_patch_level_verification"


def _parse_version(raw_challenge: bytes) -> dict:
    if len(raw_challenge) < 24:
        return {}
    flags = struct.unpack_from("<I", raw_challenge, 20)[0]
    if not (flags & NTLMSSP_NEGOTIATE_VERSION) or len(raw_challenge) < 56:
        return {}
    major, minor, build, _r1, _r2, _r3, _revision = struct.unpack_from("<BBHBBBB", raw_challenge, 48)
    return {"major": major, "minor": minor, "build": build}


def _fingerprint_build(host: str, port: int, connect_timeout: float, read_timeout: float) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)
    try:
        transport.connect()
        negotiate(transport)
        raw_challenge = probe_ntlm_challenge(transport)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {"error": str(exc)}
    transport.close()
    return _parse_version(raw_challenge)


def _enumerate_installed_kbs(transport) -> set:
    with RPCChannel(transport, PIPE_NAME) as channel:
        hklm = open_hklm(channel)
        try:
            packages_key = open_key(channel, hklm, PACKAGES_SUBKEY)
            try:
                package_names = enum_all_subkeys(channel, packages_key)
            finally:
                close_key(channel, packages_key)
        finally:
            close_key(channel, hklm)

    found = set()
    for name in package_names:
        for kb in FIX_KB_NUMBERS:
            if kb in name:
                found.add(kb)
    return found


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    version_info = _fingerprint_build(host, port, connect_timeout, read_timeout)
    fingerprint_error = version_info.pop("error", "")

    build = version_info.get("build")
    product_family_affected = (
        version_info.get("major") == AFFECTED_MAJOR
        and version_info.get("minor") == AFFECTED_MINOR
        and build == AFFECTED_BASE_BUILD
    )

    matched_kbs = set()
    hotfix_checked = False
    hotfix_error = ""

    if product_family_affected and credentials is not None and auth_session is not None and auth_session.authenticated:
        try:
            matched_kbs = _enumerate_installed_kbs(auth_session.transport)
            hotfix_checked = True
        except (OxSMBError, OSError) as exc:
            hotfix_error = str(exc)

    if not product_family_affected:
        verdict = VERDICT_NOT_APPLICABLE
        note = (
            "Reported OS build does not match the affected family (Windows 11 24H2 / "
            "Windows Server 2025, base build 10.0.26100) for CVE-2025-50169."
            if build is not None
            else "OS build could not be read from the NTLM challenge"
            + (f" ({fingerprint_error})" if fingerprint_error else "")
            + ", so the affected-family precondition could not be confirmed."
        )
    elif hotfix_checked and matched_kbs:
        verdict = VERDICT_PATCHED
        note = f"Installed package list contains fix KB(s): {', '.join(sorted(matched_kbs))}."
    elif hotfix_checked:
        verdict = VERDICT_LIKELY_VULNERABLE
        note = (
            "Host is on the affected base build (10.0.26100) and none of the known fix KBs "
            f"({', '.join(sorted(FIX_KB_NUMBERS))}) were found in the installed package list. "
            "This is a heuristic KB-name match, not an authoritative patch-level source; "
            "confirm with Get-HotFix, wmic qfe, or current MSRC/WSUS data before acting on it."
        )
    else:
        verdict = VERDICT_NEEDS_VERIFICATION
        note = (
            "Host is on the affected base build (10.0.26100), but the exact Update Build "
            "Revision (the '.4851' part that separates patched from unpatched) is not visible "
            "in the NTLM Version field, and no authenticated session was available to check "
            "installed hotfixes. Re-run with credentials to enable the registry-based KB check"
            + (f", or address this error: {hotfix_error}" if hotfix_error else "")
            + "."
        )

    data = {
        "cve_id": CVE_ID,
        "advisory_title": MS_TITLE,
        "os_major_version": version_info.get("major"),
        "os_minor_version": version_info.get("minor"),
        "os_build": build,
        "affected_product_family": product_family_affected,
        "fix_kb_candidates": sorted(FIX_KB_NUMBERS),
        "hotfix_check_performed": hotfix_checked,
        "matched_fix_kbs": sorted(matched_kbs),
        "verdict": verdict,
        "note": (
            "Detection only: this check never attempts to win the SMB request race or trigger "
            "the double-free, which is the only way to actually confirm exploitability for a "
            "race-condition bug and risks crashing the target. It relies on OS build "
            "fingerprinting and, when credentials are supplied, an authenticated registry read "
            "of installed hotfix package names. "
        )
        + note,
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }