from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.winreg import RegistryKeyNotFound, close_key, open_hklm, open_key, query_value
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "uacconfigreader"

PIPE_NAME = "winreg"

POLICY_SUBKEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"


def _read_dword_value(channel, key_handle, value_name):
    try:
        reg_value = query_value(channel, key_handle, value_name)
    except RegistryKeyNotFound:
        return None
    return reg_value.as_dword


def _read_uac_config(transport):
    with RPCChannel(transport, PIPE_NAME) as channel:
        hklm = open_hklm(channel)
        try:
            policy_key = open_key(channel, hklm, POLICY_SUBKEY)
            try:
                enable_lua = _read_dword_value(channel, policy_key, "EnableLUA")
                token_filter_policy = _read_dword_value(
                    channel, policy_key, "LocalAccountTokenFilterPolicy"
                )
            finally:
                close_key(channel, policy_key)
        finally:
            close_key(channel, hklm)

    return enable_lua, token_filter_policy


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
            enable_lua, token_filter_policy = _read_uac_config(auth_session.transport)
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
            "data": _build_data(enable_lua, token_filter_policy),
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

        enable_lua, token_filter_policy = _read_uac_config(transport)
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
        "data": _build_data(enable_lua, token_filter_policy),
        "error": None,
    }


def _build_data(enable_lua, token_filter_policy) -> dict:
    uac_enabled = None if enable_lua is None else bool(enable_lua)
    remote_uac_filtering_enforced = None if token_filter_policy is None else not bool(token_filter_policy)

    return {
        "enable_lua": enable_lua,
        "uac_enabled": uac_enabled,
        "local_account_token_filter_policy": token_filter_policy,
        "remote_uac_filtering_enforced": remote_uac_filtering_enforced,
    }
