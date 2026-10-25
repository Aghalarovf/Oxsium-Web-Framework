import socket

from protocol.ldap.cldap_ping import CLDAPPingError, send_ldap_ping

MODULE_NAME = "dclocatorsmb"

LDAP_PING_PORT = 389
DIRECT_SMB_PORT = 445


def _probe_smb_port(host: str, port: int, connect_timeout: float) -> dict:
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock.close()
        return {"port": port, "state": "open", "error": None}
    except socket.timeout:
        return {"port": port, "state": "filtered", "error": "Connection attempt timed out"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "error": None}
    except OSError as exc:
        return {"port": port, "state": "error", "error": str(exc)}


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    smb_probe = _probe_smb_port(host, port if port else DIRECT_SMB_PORT, connect_timeout)

    ldap_ping_error = None
    ping_result = None
    try:
        ping_result = send_ldap_ping(host, port=LDAP_PING_PORT, timeout=max(connect_timeout, read_timeout))
    except CLDAPPingError as exc:
        ldap_ping_error = str(exc)
    except OSError as exc:
        ldap_ping_error = str(exc)

    ldap_ping_data = None
    if ping_result is not None:
        ldap_ping_data = {
            "flags": ping_result.flags,
            "flag_names": ping_result.flag_names,
            "domain_guid": ping_result.domain_guid,
            "dns_forest_name": ping_result.dns_forest_name,
            "dns_domain_name": ping_result.dns_domain_name,
            "dns_host_name": ping_result.dns_host_name,
            "netbios_domain_name": ping_result.netbios_domain_name,
            "netbios_computer_name": ping_result.netbios_computer_name,
            "dc_site_name": ping_result.dc_site_name,
            "client_site_name": ping_result.client_site_name,
        }

    is_domain_controller = bool(ping_result is not None and ping_result.is_domain_controller)
    smb_reachable = smb_probe["state"] == "open"

    data = {
        "is_domain_controller": is_domain_controller,
        "smb_reachable": smb_reachable,
        "smb_port_probe": smb_probe,
        "ldap_ping_responded": ping_result is not None,
        "ldap_ping": ldap_ping_data,
        "ldap_ping_error": ldap_ping_error,
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
