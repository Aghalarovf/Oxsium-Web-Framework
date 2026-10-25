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

MODULE_NAME = "networkinterfaceenumerator"

PIPE_NAME = "winreg"

INTERFACES_SUBKEY = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"

EMPTY_ADDRESSES = {"", "0.0.0.0"}


def _read_string(channel, key_handle, value_name):
    try:
        reg_value = query_value(channel, key_handle, value_name, buffer_size=2048)
    except RegistryKeyNotFound:
        return None
    return reg_value.as_string


def _read_multi_string(channel, key_handle, value_name):
    try:
        reg_value = query_value(channel, key_handle, value_name, buffer_size=4096)
    except RegistryKeyNotFound:
        return None
    return reg_value.as_multi_string


def _read_dword(channel, key_handle, value_name):
    try:
        reg_value = query_value(channel, key_handle, value_name)
    except RegistryKeyNotFound:
        return None
    return reg_value.as_dword


def _first_valid(addresses):
    if not addresses:
        return None
    for address in addresses:
        if address not in EMPTY_ADDRESSES:
            return address
    return None


def _read_interface(channel, interfaces_key, interface_id):
    interface_key = open_key(channel, interfaces_key, interface_id)
    try:
        dhcp_enabled = bool(_read_dword(channel, interface_key, "EnableDHCP"))

        static_ip = _first_valid(_read_multi_string(channel, interface_key, "IPAddress"))
        static_subnet = _first_valid(_read_multi_string(channel, interface_key, "SubnetMask"))
        static_gateway = _first_valid(_read_multi_string(channel, interface_key, "DefaultGateway"))
        static_dns = _read_string(channel, interface_key, "NameServer")
        static_domain = _read_string(channel, interface_key, "Domain")

        dhcp_ip = _read_string(channel, interface_key, "DhcpIPAddress")
        dhcp_subnet = _read_string(channel, interface_key, "DhcpSubnetMask")
        dhcp_gateway = _first_valid(_read_multi_string(channel, interface_key, "DhcpDefaultGateway"))
        dhcp_dns = _read_string(channel, interface_key, "DhcpNameServer")
        dhcp_domain = _read_string(channel, interface_key, "DhcpDomain")
    finally:
        close_key(channel, interface_key)

    if dhcp_enabled and dhcp_ip not in (None, "0.0.0.0"):
        effective_ip = dhcp_ip
        effective_subnet = dhcp_subnet
        effective_gateway = dhcp_gateway
        effective_dns = dhcp_dns or static_dns
        effective_domain = dhcp_domain or static_domain
    else:
        effective_ip = static_ip
        effective_subnet = static_subnet
        effective_gateway = static_gateway
        effective_dns = static_dns
        effective_domain = static_domain

    return {
        "interface_id": interface_id,
        "dhcp_enabled": dhcp_enabled,
        "ip_address": effective_ip,
        "subnet_mask": effective_subnet,
        "default_gateway": effective_gateway,
        "dns_servers": effective_dns,
        "domain": effective_domain,
        "static_ip_address": static_ip,
        "dhcp_ip_address": dhcp_ip if dhcp_ip not in (None, "0.0.0.0") else None,
    }


def _enumerate_interfaces(transport):
    with RPCChannel(transport, PIPE_NAME) as channel:
        hklm = open_hklm(channel)
        try:
            interfaces_key = open_key(channel, hklm, INTERFACES_SUBKEY)
            try:
                interface_ids = enum_all_subkeys(channel, interfaces_key)
                interfaces = []
                for interface_id in interface_ids:
                    try:
                        interfaces.append(_read_interface(channel, interfaces_key, interface_id))
                    except RegistryKeyNotFound:
                        continue
            finally:
                close_key(channel, interfaces_key)
        finally:
            close_key(channel, hklm)

    return interfaces


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
            interfaces = _enumerate_interfaces(auth_session.transport)
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
            "data": _build_data(interfaces),
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

        interfaces = _enumerate_interfaces(transport)
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
        "data": _build_data(interfaces),
        "error": None,
    }


def _build_data(interfaces) -> dict:
    active_ips = {iface["ip_address"] for iface in interfaces if iface["ip_address"]}

    return {
        "interface_count": len(interfaces),
        "interfaces": interfaces,
        "active_ip_count": len(active_ips),
        "dual_homed": len(active_ips) > 1,
    }
