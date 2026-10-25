import struct

from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.winreg import close_key, enum_all_subkeys, open_hklm, open_key
from protocol.smb.ntlm import NTLMSSP_NEGOTIATE_VERSION
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import probe_ntlm_challenge

MODULE_NAME = "smbclientuafchecker"

CVE_ID = "CVE-2025-54101"
MS_TITLE = "Windows SMB Client Remote Code Execution Vulnerability"

PIPE_NAME = "winreg"
PACKAGES_SUBKEY = "Component Based Servicing\\Packages"

KNOWN_AFFECTED_BASE_BUILDS = {
    10240: {"branch": "Windows 10 1507", "fix_kb_candidates": {"5065430"}},
    14393: {"branch": "Windows 10 1607 / Server 2016", "fix_kb_candidates": {"5065427"}},
    17763: {"branch": "Windows 10 1809 / Server 2019", "fix_kb_candidates": set()},
    19044: {"branch": "Windows 10 21H2", "fix_kb_candidates": set()},
    19045: {"branch": "Windows 10 22H2", "fix_kb_candidates": set()},
    20348: {"branch": "Windows Server 2022", "fix_kb_candidates": set()},
    22621: {"branch": "Windows 11 22H2", "fix_kb_candidates": set()},
    22631: {"branch": "Windows 11 23H2", "fix_kb_candidates": set()},
    25398: {"branch": "Windows Server 2022 23H2", "fix_kb_candidates": set()},
}

VERDICT_NOT_APPLICABLE = "not_applicable"
VERDICT_PATCHED = "patched"
VERDICT_LIKELY_VULNERABLE = "likely_vulnerable"
VERDICT_NEEDS_VERIFICATION = "needs_patch_level_verification"
VERDICT_UNKNOWN = "unknown"


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


def _enumerate_installed_kbs(transport, candidate_kbs: set) -> set:
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
        for kb in candidate_kbs:
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
    branch_info = KNOWN_AFFECTED_BASE_BUILDS.get(build) if build else None

    matched_kbs = set()
    hotfix_checked = False
    hotfix_error = ""
    candidate_kbs = branch_info["fix_kb_candidates"] if branch_info else set()

    if branch_info is not None and candidate_kbs and credentials is not None and auth_session is not None and auth_session.authenticated:
        try:
            matched_kbs = _enumerate_installed_kbs(auth_session.transport, candidate_kbs)
            hotfix_checked = True
        except (OxSMBError, OSError) as exc:
            hotfix_error = str(exc)

    if branch_info is None and build is not None:
        verdict = VERDICT_NOT_APPLICABLE
        note = f"Reported base build {build} is outside this module's reference table of branches affected by CVE-2025-54101."
    elif branch_info is None:
        verdict = VERDICT_UNKNOWN
        note = (
            "OS build could not be read from the NTLM challenge"
            + (f" ({fingerprint_error})" if fingerprint_error else "")
            + ", so the affected-branch precondition could not be confirmed."
        )
    elif hotfix_checked and matched_kbs:
        verdict = VERDICT_PATCHED
        note = (
            f"Host is on {branch_info['branch']} (base build {build}); installed package list "
            f"contains fix KB(s): {', '.join(sorted(matched_kbs))}."
        )
    elif hotfix_checked:
        verdict = VERDICT_LIKELY_VULNERABLE
        note = (
            f"Host is on {branch_info['branch']} (base build {build}); none of the known fix "
            f"KBs ({', '.join(sorted(candidate_kbs))}) were found in the installed package list. "
            "This is a heuristic KB-name match, not an authoritative patch-level source; confirm "
            "with Get-HotFix, wmic qfe, or current MSRC/WSUS data before acting on it."
        )
    else:
        verdict = VERDICT_NEEDS_VERIFICATION
        note = (
            f"Host is on {branch_info['branch']} (base build {build}), a branch documented as "
            "affected by CVE-2025-54101. The NTLM Version field does not expose the Update Build "
            "Revision, so the base build alone cannot confirm whether the patch is installed. "
            + (
                "Re-run with credentials to enable the registry-based KB check"
                + (f", or address this error: {hotfix_error}" if hotfix_error else "")
                + "."
                if candidate_kbs
                else "This branch has no known fix KB in this module's table yet; confirm the exact "
                "patch level with Get-HotFix, wmic qfe, or current MSRC/WSUS data."
            )
        )

    data = {
        "cve_id": CVE_ID,
        "advisory_title": MS_TITLE,
        "os_major_version": version_info.get("major"),
        "os_minor_version": version_info.get("minor"),
        "os_build": build,
        "matched_reference_branch": branch_info["branch"] if branch_info else None,
        "fix_kb_candidates": sorted(candidate_kbs),
        "hotfix_check_performed": hotfix_checked,
        "matched_fix_kbs": sorted(matched_kbs),
        "verdict": verdict,
        "note": (
            "Detection only: this check never attempts to win the client-side race condition "
            "that the use-after-free requires, since doing so would mean acting as a malicious "
            "SMB server against a real client and risking a crash. It relies on OS build "
            "fingerprinting from the NTLM challenge and, when credentials are supplied, an "
            "authenticated registry read of installed hotfix package names. "
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