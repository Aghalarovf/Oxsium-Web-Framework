import struct

from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.ntlm import NTLMSSP_NEGOTIATE_VERSION
from protocol.smb.smb2_constants import SMB2_NEGOTIATE_CONTEXT_COMPRESSION
from protocol.smb.smb_constants import SMB2_DIALECT_3_1_1
from protocol.smb.smb_negotiate import negotiate, parse_negotiate_contexts
from protocol.smb.smb_session_setup import probe_ntlm_challenge

MODULE_NAME = "smbleedchecker"

CVE_ID = "CVE-2020-1206"

VERDICT_NOT_VULNERABLE = "not_vulnerable"
VERDICT_NEEDS_VERIFICATION = "needs_patch_level_verification"
VERDICT_UNKNOWN = "unknown"

KNOWN_AFFECTED_BASE_BUILDS = {
    18362: {"branch": "Windows 10 1903 / Server, version 1903", "fix_kb_reference": "KB4560960 and later"},
    18363: {"branch": "Windows 10 1909 / Server, version 1909", "fix_kb_reference": "KB4560960 and later"},
    19041: {"branch": "Windows 10 2004 / Server, version 2004", "fix_kb_reference": "KB4557957 and later"},
}


def _parse_version(raw_challenge: bytes) -> dict:
    if len(raw_challenge) < 24:
        return {}
    flags = struct.unpack_from("<I", raw_challenge, 20)[0]
    if not (flags & NTLMSSP_NEGOTIATE_VERSION) or len(raw_challenge) < 56:
        return {}
    major, minor, build, _r1, _r2, _r3, _revision = struct.unpack_from("<BBHBBBB", raw_challenge, 48)
    return {"major": major, "minor": minor, "build": build}


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()
        negotiate_result = negotiate(
            transport,
            dialects=[SMB2_DIALECT_3_1_1],
            include_compression_context=True,
        )
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    negotiated_311 = negotiate_result.dialect_revision == SMB2_DIALECT_3_1_1
    compression_negotiated = False

    if negotiated_311 and negotiate_result.negotiate_context_count > 0:
        contexts = parse_negotiate_contexts(
            negotiate_result.raw_body,
            negotiate_result.negotiate_context_offset,
            negotiate_result.negotiate_context_count,
        )
        compression_negotiated = any(
            context_type == SMB2_NEGOTIATE_CONTEXT_COMPRESSION for context_type, _ in contexts
        )

    precondition_met = negotiated_311 and compression_negotiated

    raw_challenge = b""
    challenge_error = ""
    if precondition_met:
        try:
            raw_challenge = probe_ntlm_challenge(transport)
        except (OxSMBError, OSError) as exc:
            challenge_error = str(exc)

    transport.close()

    version_info = _parse_version(raw_challenge) if raw_challenge else {}
    build = version_info.get("build")
    branch_info = KNOWN_AFFECTED_BASE_BUILDS.get(build) if build else None

    if not precondition_met:
        verdict = VERDICT_NOT_VULNERABLE
        note = (
            "Server did not negotiate SMB 3.1.1 with compression, so the SMBleed "
            "decompression-handler precondition is not met."
        )
    elif branch_info is not None:
        verdict = VERDICT_NEEDS_VERIFICATION
        note = (
            f"Server negotiated SMB 3.1.1 compression and reports base build {build} "
            f"({branch_info['branch']}), a branch that shipped an affected decompression "
            f"routine at some point (fixed from {branch_info['fix_kb_reference']}). The NTLM "
            "Version field does not expose the Update Build Revision, so this cannot confirm "
            "whether the specific patch is installed. Confirm with an authenticated hotfix "
            "check before treating this as exploitable."
        )
    elif build is not None:
        verdict = VERDICT_NEEDS_VERIFICATION
        note = (
            f"Server negotiated SMB 3.1.1 compression and reports base build {build}, which is "
            "outside this module's reference table of historically affected branches. Compression "
            "support alone still meets the documented precondition for CVE-2020-1206; verify the "
            "exact patch level with an authenticated check rather than relying on this result alone."
        )
    else:
        verdict = VERDICT_UNKNOWN
        note = (
            "Server negotiated SMB 3.1.1 compression (the documented CVE-2020-1206 precondition) "
            "but the OS build could not be read from the NTLM challenge"
            + (f" ({challenge_error})" if challenge_error else "")
            + ". Patch status could not be estimated."
        )

    data = {
        "cve_id": CVE_ID,
        "aka": "SMBleed",
        "dialect_negotiated": hex(negotiate_result.dialect_revision),
        "smb_3_1_1_supported": negotiated_311,
        "compression_capability_negotiated": compression_negotiated,
        "os_major_version": version_info.get("major"),
        "os_minor_version": version_info.get("minor"),
        "os_build": build,
        "matched_reference_branch": branch_info["branch"] if branch_info else None,
        "verdict": verdict,
        "note": (
            "Detection only: this check inspects SMB 3.1.1 negotiation and the OS build reported "
            "in the NTLM challenge. No SMB2 WRITE/decompression request is sent and no kernel "
            "memory is read, so a 'needs_patch_level_verification' result means the precondition "
            "is present, not that exploitation was confirmed. "
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