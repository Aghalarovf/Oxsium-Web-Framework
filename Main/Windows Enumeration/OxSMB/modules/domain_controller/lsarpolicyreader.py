from core.auth import Credentials
from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.stubs.lsarpc import (
    close_policy_handle,
    open_policy2,
    query_audit_log_information,
    query_primary_domain_information,
)
from protocol.rpc.stubs.winreg import (
    RegistryKeyNotFound,
    close_key,
    enum_all_subkeys,
    open_hklm,
    open_key,
)
from protocol.smb.smb_negotiate import negotiate
from protocol.smb.smb_session_setup import null_session_setup, session_setup

MODULE_NAME = "lsarpolicyreader"

SECRETS_KEY_PATH = "SECURITY\\Policy\\Secrets"


def _read_lsa_policy(transport, host: str) -> dict:
    audit_log = None
    audit_log_error = None
    primary_domain = None
    primary_domain_error = None

    with RPCChannel(transport, "lsarpc") as channel:
        handle = open_policy2(channel, system_name=host)
        try:
            try:
                audit_log = query_audit_log_information(channel, handle)
            except (OxSMBError, OSError) as exc:
                audit_log_error = str(exc)

            try:
                primary_domain = query_primary_domain_information(channel, handle)
            except (OxSMBError, OSError) as exc:
                primary_domain_error = str(exc)
        finally:
            close_policy_handle(channel, handle)

    secret_names, secrets_error = _enumerate_lsa_secret_names(transport)

    return {
        "audit_policy": None
        if audit_log is None
        else {
            "audit_log_percent_full": audit_log.audit_log_percent_full,
            "maximum_log_size": audit_log.maximum_log_size,
            "audit_retention_period_low": audit_log.audit_retention_period_low,
            "audit_retention_period_high": audit_log.audit_retention_period_high,
            "audit_log_full_shutdown_in_progress": audit_log.audit_log_full_shutdown_in_progress,
            "next_audit_record_id": audit_log.next_audit_record_id,
        },
        "audit_policy_error": audit_log_error,
        "domain_name": None if primary_domain is None else primary_domain.domain_name,
        "domain_sid": None if primary_domain is None else primary_domain.domain_sid,
        "primary_domain_error": primary_domain_error,
        "lsa_secret_names": secret_names,
        "lsa_secret_names_error": secrets_error,
    }


def _enumerate_lsa_secret_names(transport):
    try:
        with RPCChannel(transport, "winreg") as channel:
            hklm_handle = open_hklm(channel)
            try:
                secrets_handle = open_key(channel, hklm_handle, SECRETS_KEY_PATH)
                try:
                    names = enum_all_subkeys(channel, secrets_handle)
                    return names, None
                finally:
                    close_key(channel, secrets_handle)
            finally:
                close_key(channel, hklm_handle)
    except RegistryKeyNotFound:
        return [], "SECURITY\\Policy\\Secrets key not found"
    except (OxSMBError, OSError) as exc:
        return [], str(exc)


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
            data = _read_lsa_policy(auth_session.transport, host)
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
            "data": data,
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

        data = _read_lsa_policy(transport, host)
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
        "data": data,
        "error": None,
    }
