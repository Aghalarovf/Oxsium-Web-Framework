import socket

MODULE_NAME = "smbportmapper"

NETBIOS_SESSION_PORT = 139
DIRECT_SMB_PORT = 445

PORT_LABELS = {
    NETBIOS_SESSION_PORT: "NetBIOS Session Service (NBSS over TCP/IP)",
    DIRECT_SMB_PORT: "Direct hosted SMB (no NetBIOS wrapper)",
}


def _probe_port(host: str, port: int, connect_timeout: float) -> dict:
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock.close()
        return {"port": port, "state": "open", "service": PORT_LABELS.get(port, ""), "error": None}
    except socket.timeout:
        return {
            "port": port,
            "state": "filtered",
            "service": PORT_LABELS.get(port, ""),
            "error": "Connection attempt timed out",
        }
    except ConnectionRefusedError:
        return {
            "port": port,
            "state": "closed",
            "service": PORT_LABELS.get(port, ""),
            "error": None,
        }
    except OSError as exc:
        return {
            "port": port,
            "state": "error",
            "service": PORT_LABELS.get(port, ""),
            "error": str(exc),
        }


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    ports_to_probe = sorted({NETBIOS_SESSION_PORT, DIRECT_SMB_PORT, port})
    results = [_probe_port(host, target_port, connect_timeout) for target_port in ports_to_probe]
    by_port = {entry["port"]: entry for entry in results}

    netbios_entry = by_port.get(NETBIOS_SESSION_PORT)
    direct_entry = by_port.get(DIRECT_SMB_PORT)

    netbios_open = bool(netbios_entry and netbios_entry["state"] == "open")
    direct_open = bool(direct_entry and direct_entry["state"] == "open")

    data = {
        "netbios_session_139": netbios_entry,
        "direct_smb_445": direct_entry,
        "all_probed_ports": results,
        "dual_stack": netbios_open and direct_open,
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
