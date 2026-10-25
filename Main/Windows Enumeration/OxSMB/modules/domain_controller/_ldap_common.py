from typing import List, Optional

from core.auth import Credentials
from protocol.ldap.cldap_ping import CLDAPPingError, send_ldap_ping
from protocol.ldap.ldap_client import (
    LDAP_SCOPE_BASE,
    LDAPClient,
    LDAPEntry,
    LDAPError,
    filter_present,
)

ROOT_DSE_ATTRIBUTES = [
    "defaultNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "rootDomainNamingContext",
]


def resolve_bind_dn(credentials: Optional[Credentials]):
    if credentials is None or credentials.is_anonymous:
        return "", ""
    if credentials.domain:
        return f"{credentials.username}@{credentials.domain}", credentials.password
    return credentials.username, credentials.password


def resolve_target_identity(host: str, connect_timeout: float) -> str:
    try:
        ping_result = send_ldap_ping(host, timeout=connect_timeout)
    except (CLDAPPingError, OSError):
        return host
    if ping_result is None or not ping_result.dns_host_name:
        return host
    return ping_result.dns_host_name


def read_root_dse(client: LDAPClient) -> LDAPEntry:
    entries = client.search(
        base_dn="",
        scope=LDAP_SCOPE_BASE,
        search_filter=filter_present("objectClass"),
        attributes=ROOT_DSE_ATTRIBUTES,
    )
    if not entries:
        raise LDAPError("RootDSE search returned no entries")
    return entries[0]
