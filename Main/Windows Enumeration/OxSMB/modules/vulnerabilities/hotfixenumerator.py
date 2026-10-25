import re
from datetime import datetime, timedelta, timezone

from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.winreg import (
    RegistryKeyNotFound,
    close_key,
    enum_all_subkeys,
    open_hklm,
    open_key,
    query_value,
)
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "hotfixenumerator"

PIPE_NAME = "winreg"

CBS_PACKAGES_SUBKEY = "Component Based Servicing\\Packages"
CURRENT_VERSION_SUBKEY = "Microsoft\\Windows NT\\CurrentVersion"
LEGACY_HOTFIX_SUBKEY = "Microsoft\\Windows NT\\CurrentVersion\\Hotfix"

KB_PATTERN = re.compile(r"KB(\d{6,7})", re.IGNORECASE)

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

CVE_WATCHLIST = {
    "EternalBlue / MS17-010 (CVE-2017-0144)": {
        "4012212", "4012213", "4012214", "4012215", "4012216", "4012217", "4013198", "4013429",
    },
    "BlueKeep (CVE-2019-0708)": {"4499164", "4499165", "4499175", "4500331"},
    "SMBGhost (CVE-2020-0796)": {"4551762"},
    "ZeroLogon (CVE-2020-1472)": {"4571694", "4571702", "4565351", "4566782", "4601345", "4601347"},
    "PrintNightmare (CVE-2021-34527)": {"5004945", "5004946", "5004947", "5004950", "5004953"},
    "PetitPotam (CVE-2021-36942)": {"5005413", "5005406", "5005394", "5005398", "5005409"},
    "HiveNightmare (CVE-2021-36934)": {"5003637", "5003646", "5003690", "5004237", "5004245"},
    "Follina (CVE-2022-30190)": {"5014692", "5014697", "5014699", "5014702", "5014710"},
}

WATCHLIST_NOTE = (
    "Heuristic match against a small, non-exhaustive sample of known fix KB numbers per CVE. "
    "A miss here does not confirm the host is patched or unpatched; verify the exact OS build "
    "and UBR against Microsoft's update catalog, or confirm with wmic qfe, Get-HotFix, or an "
    "authoritative vulnerability scanner against current MSRC data."
)


def _filetime_to_iso(high, low):
    if high is None or low is None:
        return None
    ticks = (high << 32) | low
    if ticks <= 0:
        return None
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=ticks / 10)).isoformat()
    except OverflowError:
        return None


def _read_dword(channel, handle, value_name):
    try:
        reg_value = query_value(channel, handle, value_name)
    except RegistryKeyNotFound:
        return None
    return reg_value.as_dword


def _read_string(channel, handle, value_name):
    try:
        reg_value = query_value(channel, handle, value_name)
    except RegistryKeyNotFound:
        return None
    return reg_value.as_string


def _extract_kb_numbers(names) -> set:
    found = set()
    for name in names:
        match = KB_PATTERN.search(name)
        if match:
            found.add(match.group(1))
    return found


def _match_watchlist_entries(names, watchlist_kbs) -> dict:
    matches = {}
    for name in names:
        match = KB_PATTERN.search(name)
        if not match:
            continue
        kb = match.group(1)
        if kb in watchlist_kbs and kb not in matches:
            matches[kb] = name
    return matches


def _read_os_version(channel, hklm) -> dict:
    version_key = open_key(channel, hklm, CURRENT_VERSION_SUBKEY)
    try:
        current_build_number = _read_string(channel, version_key, "CurrentBuildNumber")
        ubr = _read_dword(channel, version_key, "UBR")
        display_version = _read_string(channel, version_key, "DisplayVersion")
        release_id = _read_string(channel, version_key, "ReleaseId")
        product_name = _read_string(channel, version_key, "ProductName")
    finally:
        close_key(channel, version_key)

    if current_build_number and ubr is not None:
        full_build = f"{current_build_number}.{ubr}"
    else:
        full_build = current_build_number

    return {
        "product_name": product_name,
        "current_build_number": current_build_number,
        "ubr": ubr,
        "full_build": full_build,
        "display_version": display_version,
        "release_id": release_id,
    }


def _read_cbs_package_detail(channel, packages_key, package_name):
    try:
        package_key = open_key(channel, packages_key, package_name)
    except RegistryKeyNotFound:
        return None
    try:
        current_state = _read_dword(channel, package_key, "CurrentState")
        install_time_high = _read_dword(channel, package_key, "InstallTimeHigh")
        install_time_low = _read_dword(channel, package_key, "InstallTimeLow")
    finally:
        close_key(channel, package_key)

    return {
        "source": "cbs_package",
        "package_name": package_name,
        "current_state": current_state,
        "install_time": _filetime_to_iso(install_time_high, install_time_low),
    }


def _read_legacy_hotfix_detail(channel, hotfix_key, subkey_name):
    try:
        entry_key = open_key(channel, hotfix_key, subkey_name)
    except RegistryKeyNotFound:
        return None
    try:
        description = _read_string(channel, entry_key, "Description")
        installed_by = _read_string(channel, entry_key, "InstalledBy")
        install_time_high = _read_dword(channel, entry_key, "InstallTimeHigh")
        install_time_low = _read_dword(channel, entry_key, "InstallTimeLow")
    finally:
        close_key(channel, entry_key)

    return {
        "source": "legacy_hotfix",
        "package_name": subkey_name,
        "description": description,
        "installed_by": installed_by,
        "install_time": _filetime_to_iso(install_time_high, install_time_low),
    }


def _enumerate_hotfixes(transport):
    watchlist_kbs = set()
    for kb_set in CVE_WATCHLIST.values():
        watchlist_kbs |= kb_set

    with RPCChannel(transport, PIPE_NAME) as channel:
        hklm = open_hklm(channel)
        try:
            os_version = _read_os_version(channel, hklm)

            packages_key = open_key(channel, hklm, CBS_PACKAGES_SUBKEY)
            try:
                package_names = enum_all_subkeys(channel, packages_key)
                package_matches = _match_watchlist_entries(package_names, watchlist_kbs)
                watchlist_details = {}
                for kb, package_name in package_matches.items():
                    detail = _read_cbs_package_detail(channel, packages_key, package_name)
                    if detail is not None:
                        watchlist_details[kb] = detail
            finally:
                close_key(channel, packages_key)

            legacy_names = []
            try:
                hotfix_key = open_key(channel, hklm, LEGACY_HOTFIX_SUBKEY)
                try:
                    legacy_names = enum_all_subkeys(channel, hotfix_key)
                    legacy_matches = _match_watchlist_entries(legacy_names, watchlist_kbs)
                    for kb, subkey_name in legacy_matches.items():
                        if kb in watchlist_details:
                            continue
                        detail = _read_legacy_hotfix_detail(channel, hotfix_key, subkey_name)
                        if detail is not None:
                            watchlist_details[kb] = detail
                finally:
                    close_key(channel, hotfix_key)
            except RegistryKeyNotFound:
                pass
        finally:
            close_key(channel, hklm)

    return package_names, legacy_names, watchlist_details, os_version


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    if credentials is not None and auth_session is not None and auth_session.authenticated:
        try:
            package_names, legacy_names, watchlist_details, os_version = _enumerate_hotfixes(
                auth_session.transport
            )
        except (OxSMBError, OSError) as exc:
            return {
                "module": MODULE_NAME,
                "target": host,
                "status": "error",
                "data": None,
                "error": str(exc),
            }

        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "ok",
            "data": _build_data(package_names, legacy_names, watchlist_details, os_version),
            "error": None,
        }

    transport = SMBTransport(host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout)

    try:
        transport.connect()
        negotiate(transport)

        if credentials is not None and not credentials.is_null_session:
            session_setup(transport, credentials)
        else:
            null_session_setup(transport)

        package_names, legacy_names, watchlist_details, os_version = _enumerate_hotfixes(transport)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }

    transport.close()

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": _build_data(package_names, legacy_names, watchlist_details, os_version),
        "error": None,
    }


def _build_data(package_names, legacy_names, watchlist_details, os_version) -> dict:
    kb_numbers = _extract_kb_numbers(package_names) | _extract_kb_numbers(legacy_names)

    watchlist_results = {}
    for cve_label, kb_set in CVE_WATCHLIST.items():
        matched = sorted(kb_numbers & kb_set)
        watchlist_results[cve_label] = {
            "patch_kb_found": bool(matched),
            "matched_kb_numbers": matched,
            "matched_kb_details": {kb: watchlist_details[kb] for kb in matched if kb in watchlist_details},
        }

    return {
        "os_version": os_version,
        "installed_package_count": len(package_names),
        "legacy_hotfix_count": len(legacy_names),
        "installed_kb_numbers": sorted(kb_numbers, key=int),
        "cve_watchlist": watchlist_results,
        "cve_watchlist_note": WATCHLIST_NOTE,
    }