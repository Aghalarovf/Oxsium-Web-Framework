from core.auth import Credentials
from core.exceptions import OxSMBError
from modules.domain_controller._ldap_common import read_root_dse, resolve_bind_dn, resolve_target_identity
from protocol.ldap.ldap_client import (
    LDAP_SCOPE_BASE,
    LDAP_SCOPE_SUBTREE,
    LDAPClient,
    filter_and,
    filter_equality,
    filter_present,
)

MODULE_NAME = "dcrolechecker"

LDAP_PORT = 389

UF_SERVER_TRUST_ACCOUNT = 0x00002000
UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000
NTDS_OPTIONS_IS_GC = 0x00000001


def _find_server_object(client: LDAPClient, config_nc: str, target: str):
    entries = client.search(
        base_dn=config_nc,
        scope=LDAP_SCOPE_SUBTREE,
        search_filter=filter_and(
            filter_equality("objectClass", "server"),
            filter_equality("dNSHostName", target),
        ),
        attributes=["dNSHostName"],
    )
    return entries[0] if entries else None


def _find_computer_account(client: LDAPClient, default_nc: str, target: str):
    entries = client.search(
        base_dn=default_nc,
        scope=LDAP_SCOPE_SUBTREE,
        search_filter=filter_and(
            filter_equality("objectClass", "computer"),
            filter_equality("dNSHostName", target),
        ),
        attributes=["userAccountControl", "sAMAccountName"],
    )
    return entries[0] if entries else None


def _read_ntds_options(client: LDAPClient, server_dn: str):
    entries = client.search(
        base_dn=f"CN=NTDS Settings,{server_dn}",
        scope=LDAP_SCOPE_BASE,
        search_filter=filter_present("objectClass"),
        attributes=["options"],
    )
    if not entries:
        return None
    return entries[0].first_int("options")


def _check_dc_role(host: str, port: int, connect_timeout: float, credentials) -> dict:
    target = resolve_target_identity(host, connect_timeout)
    bind_dn, bind_password = resolve_bind_dn(credentials)

    with LDAPClient(target, port=port, timeout=connect_timeout) as client:
        client.bind(bind_dn=bind_dn, password=bind_password)
        root_dse = read_root_dse(client)

        default_nc = root_dse.first_str("defaultNamingContext")
        config_nc = root_dse.first_str("configurationNamingContext")

        if not default_nc or not config_nc:
            raise OxSMBError("RootDSE did not return the required naming contexts")

        server_entry = _find_server_object(client, config_nc, target)
        computer_entry = _find_computer_account(client, default_nc, target)

        options = _read_ntds_options(client, server_entry.dn) if server_entry is not None else None
        user_account_control = computer_entry.first_int("userAccountControl") if computer_entry is not None else None

        is_global_catalog = bool(options is not None and options & NTDS_OPTIONS_IS_GC)
        is_rodc = bool(
            user_account_control is not None and user_account_control & UF_PARTIAL_SECRETS_ACCOUNT
        )
        is_domain_controller = bool(
            user_account_control is not None and user_account_control & UF_SERVER_TRUST_ACCOUNT
        )

        if is_rodc:
            role_label = "Read-Only Domain Controller (RODC)"
        elif is_domain_controller:
            role_label = "Writable Domain Controller"
        else:
            role_label = "Unknown"

        if is_global_catalog:
            role_label = f"{role_label} + Global Catalog"

        return {
            "target_dns_host_name": target,
            "default_naming_context": default_nc,
            "configuration_naming_context": config_nc,
            "server_object_dn": server_entry.dn if server_entry is not None else None,
            "computer_object_dn": computer_entry.dn if computer_entry is not None else None,
            "ntds_options": options,
            "user_account_control": user_account_control,
            "is_domain_controller": is_domain_controller,
            "is_global_catalog": is_global_catalog,
            "is_rodc": is_rodc,
            "role_label": role_label,
        }


def run(
    host: str,
    port: int = 445,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
    credentials: Credentials = None,
    auth_session=None,
) -> dict:
    try:
        data = _check_dc_role(host, LDAP_PORT, connect_timeout, credentials)
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
