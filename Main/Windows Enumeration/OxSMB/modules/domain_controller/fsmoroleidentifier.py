from core.auth import Credentials
from core.exceptions import OxSMBError
from modules.domain_controller._ldap_common import read_root_dse, resolve_bind_dn, resolve_target_identity
from protocol.ldap.ldap_client import LDAP_SCOPE_BASE, LDAPClient, filter_present

MODULE_NAME = "fsmoroleidentifier"

LDAP_PORT = 389

NTDS_SETTINGS_PREFIX = "CN=NTDS Settings,"


def _owner_dc_name(ntds_settings_dn: str):
    if not ntds_settings_dn or not ntds_settings_dn.upper().startswith(NTDS_SETTINGS_PREFIX.upper()):
        return None, ntds_settings_dn
    remainder = ntds_settings_dn[len(NTDS_SETTINGS_PREFIX):]
    server_component = remainder.split(",", 1)[0]
    if server_component.upper().startswith("CN="):
        return server_component[3:], ntds_settings_dn
    return server_component, ntds_settings_dn


def _query_role_owner(client: LDAPClient, role_dn: str):
    entries = client.search(
        base_dn=role_dn,
        scope=LDAP_SCOPE_BASE,
        search_filter=filter_present("objectClass"),
        attributes=["fSMORoleOwner"],
    )
    if not entries:
        return None, None
    owner_dn = entries[0].first_str("fSMORoleOwner")
    if owner_dn is None:
        return None, None
    dc_name, ntds_dn = _owner_dc_name(owner_dn)
    return dc_name, ntds_dn


def _identify_fsmo_roles(host: str, port: int, connect_timeout: float, credentials) -> dict:
    target = resolve_target_identity(host, connect_timeout)
    bind_dn, bind_password = resolve_bind_dn(credentials)

    with LDAPClient(target, port=port, timeout=connect_timeout) as client:
        client.bind(bind_dn=bind_dn, password=bind_password)
        root_dse = read_root_dse(client)

        default_nc = root_dse.first_str("defaultNamingContext")
        config_nc = root_dse.first_str("configurationNamingContext")

        if not default_nc or not config_nc:
            raise OxSMBError("RootDSE did not return the required naming contexts")

        role_dns = {
            "pdc_emulator": default_nc,
            "rid_master": f"CN=RID Manager$,CN=System,{default_nc}",
            "infrastructure_master": f"CN=Infrastructure,{default_nc}",
            "schema_master": f"CN=Schema,{config_nc}",
            "domain_naming_master": f"CN=Partitions,{config_nc}",
        }

        roles = {}
        for role_name, role_dn in role_dns.items():
            dc_name, ntds_dn = _query_role_owner(client, role_dn)
            roles[role_name] = {
                "owner_dc_name": dc_name,
                "owner_ntds_settings_dn": ntds_dn,
                "role_object_dn": role_dn,
            }

        return {
            "default_naming_context": default_nc,
            "configuration_naming_context": config_nc,
            "fsmo_roles": roles,
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
        data = _identify_fsmo_roles(host, LDAP_PORT, connect_timeout, credentials)
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
