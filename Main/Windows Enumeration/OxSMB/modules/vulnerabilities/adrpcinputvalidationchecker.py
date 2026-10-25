import struct

from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.ldap.cldap_ping import CLDAPPingError, send_ldap_ping
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.winreg import close_key, enum_all_subkeys, open_hklm, open_key
from protocol.smb.ntlm import NTLMSSP_NEGOTIATE_VERSION
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import probe_ntlm_challenge

MODULE_NAME = "adrpcinputvalidationchecker"

CVE_ID = "CVE-2026-33826"
MS_TITLE = "Windows Active Directory Remote Code Execution Vulnerability"

LDAP_PING_PORT = 389

PIPE_NAME = "winreg"
PACKAGES_SUBKEY = "Component Based Servicing\\Packages"

KNOWN_AFFECTED_BASE_BUILDS = {
    9200: {"branch": "Windows Server 2012", "fix_kb_candidates": set()},
    9600: {"branch": "Windows Server 2012 R2", "fix_kb_candidates": set()},
    14393: {"branch": "Windows Server 2016", "fix_kb_candidates": set()},
    17763: {"branch": "Windows Server 2019", "fix_kb_candidates": set()},
    20348: {"branch": "Windows Server 2022", "fix_kb_candidates": {"5082060"}},
    25398: {"branch": "Windows Server 2022 23H2", "fix_kb_candidates": set()},
    26100: {"branch": "Windows Server 2025", "fix_kb_candidates": set()},
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


def _check_domain_controller_role(host: str, timeout: float) -> dict:
    try:
        ping_result = send_ldap_ping(host, port=LDAP_PING_PORT, timeout=timeout)
    except (CLDAPPingError, OSError) as exc:
        return {"responded": False, "is_domain_controller": False, "error": str(exc)}
    return {
        "responded": True,
        "is_domain_controller": bool(ping_result.is_domain_controller),
        "dns_host_name": ping_result.dns_host_name,
        "dns_domain_name": ping_result.dns_domain_name,
        "error": None,
    }


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
    dc_role = _check_domain_controller_role(host, max(connect_timeout, read_timeout))
    version_info = _fingerprint_build(host, port, connect_timeout, read_timeout)
    fingerprint_error = version_info.pop("error", "")

    build = version_info.get("build")
    branch_info = KNOWN_AFFECTED_BASE_BUILDS.get(build) if build else None
    candidate_kbs = branch_info["fix_kb_candidates"] if branch_info else set()

    matched_kbs = set()
    hotfix_checked = False
    hotfix_error = ""

    if candidate_kbs and credentials is not None and auth_session is not None and auth_session.authenticated:
        try:
            matched_kbs = _enumerate_installed_kbs(auth_session.transport, candidate_kbs)
            hotfix_checked = True
        except (OxSMBError, OSError) as exc:
            hotfix_error = str(exc)

    if not dc_role["is_domain_controller"]:
        verdict = VERDICT_NOT_APPLICABLE
        if dc_role["responded"]:
            note = (
                "Target did not respond to an AD NETLOGON ping as a domain controller, so the "
                "CVE-2026-33826 precondition (an Active Directory Domain Services role) is not met."
            )
        else:
            note = (
                "CLDAP ping failed"
                + (f" ({dc_role['error']})" if dc_role["error"] else "")
                + ", so the domain controller precondition could not be confirmed."
            )
    elif branch_info is None and build is not None:
        verdict = VERDICT_NOT_APPLICABLE
        note = f"Reported base build {build} is outside this module's reference table of Windows Server branches affected by CVE-2026-33826."
    elif branch_info is None:
        verdict = VERDICT_UNKNOWN
        note = (
            "Target responded as a domain controller, but the OS build could not be read from "
            "the NTLM challenge"
            + (f" ({fingerprint_error})" if fingerprint_error else "")
            + "."
        )
    elif hotfix_checked and matched_kbs:
        verdict = VERDICT_PATCHED
        note = (
            f"Target is a domain controller on {branch_info['branch']} (base build {build}); "
            f"installed package list contains fix KB(s): {', '.join(sorted(matched_kbs))}."
        )
    elif hotfix_checked:
        verdict = VERDICT_LIKELY_VULNERABLE
        note = (
            f"Target is a domain controller on {branch_info['branch']} (base build {build}); "
            f"none of the known fix KBs ({', '.join(sorted(candidate_kbs))}) were found in the "
            "installed package list. This is a heuristic KB-name match, not an authoritative "
            "patch-level source; confirm with Get-HotFix, wmic qfe, or current MSRC/WSUS data "
            "before acting on it."
        )
    else:
        verdict = VERDICT_NEEDS_VERIFICATION
        note = (
            f"Target is a domain controller on {branch_info['branch']} (base build {build}), a "
            "branch documented as affected by CVE-2026-33826. The NTLM Version field does not "
            "expose the Update Build Revision, so the base build alone cannot confirm whether "
            "the patch is installed. "
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
        "is_domain_controller": dc_role["is_domain_controller"],
        "cldap_ping_responded": dc_role["responded"],
        "dns_host_name": dc_role.get("dns_host_name"),
        "dns_domain_name": dc_role.get("dns_domain_name"),
        "os_major_version": version_info.get("major"),
        "os_minor_version": version_info.get("minor"),
        "os_build": build,
        "matched_reference_branch": branch_info["branch"] if branch_info else None,
        "fix_kb_candidates": sorted(candidate_kbs),
        "hotfix_check_performed": hotfix_checked,
        "matched_fix_kbs": sorted(matched_kbs),
        "verdict": verdict,
        "note": (
            "Detection only: Microsoft has not published the exact RPC interface or request "
            "structure involved, so this check never sends crafted RPC calls against Active "
            "Directory's RPC handling. It only confirms the domain controller role via an "
            "unauthenticated CLDAP NETLOGON ping, fingerprints the OS build from the NTLM "
            "challenge, and, when credentials are supplied, performs an authenticated registry "
            "read of installed hotfix package names. "
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