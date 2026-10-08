from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from core import HostInfo, SourceResult
from sources import ALL_SOURCES


def list_sources() -> None:
    print(f"{'SOURCE':<15} {'KEYS':<24} {'STATUS':<9} DESCRIPTION")
    print("-" * 90)
    for cls in ALL_SOURCES:
        keys_col = ",".join(cls.required_keys) if cls.required_keys else (
            "yes" if cls.requires_api_key else "-"
        )
        status = "enabled" if cls.enabled else "disabled"
        print(f"{cls.name:<15} {keys_col:<24} {status:<9} {cls.description}")


# ---------------------------------------------------------------------------
# Tree helpers
# ---------------------------------------------------------------------------

def _build_tree(domain: str, subdomains: list[str]) -> dict:
    root: dict = {}
    suffix = "." + domain
    for sub in subdomains:
        if not sub.endswith(suffix):
            continue
        labels = sub[: -len(suffix)].split(".")
        labels.reverse()
        node = root
        for label in labels:
            node = node.setdefault(label, {})
    return root


def _host_suffix(
    fqdn: str,
    hosts: Optional[dict[str, HostInfo]],
    did_status: bool,
) -> str:
    """Build the inline annotation appended after the hostname in tree output."""
    if hosts is None or fqdn not in hosts:
        return ""

    info = hosts[fqdn]
    parts: list[str] = []

    # IP / DNS error
    parts.append(info.ip_label())

    # CNAME chain
    if info.cname_chain:
        parts.append("-> " + " -> ".join(info.cname_chain))

    # HTTP status
    if did_status and info.checks:
        status_parts = []
        for c in info.checks:
            if c.status is not None:
                status_parts.append(f"{c.scheme}:{c.status}")
            else:
                status_parts.append(f"{c.scheme}:ERR/{c.error}")
        parts.append(" ".join(status_parts))

    # Takeover warning — stands out clearly
    if info.takeover:
        t = info.takeover
        parts.append(f"[TAKEOVER: {t.provider} via {t.cname}]")

    return "  " + "  ".join(parts) if parts else ""


def _render_tree(
    node: dict,
    prefix: str,
    parent_fqdn: str,
    domain: str,
    hosts: Optional[dict[str, HostInfo]],
    did_status: bool,
    lines: list[str],
) -> None:
    items = sorted(node.items())
    for i, (label, children) in enumerate(items):
        is_last = i == len(items) - 1
        connector = "`--" if is_last else "|--"
        fqdn = f"{label}.{parent_fqdn}"
        suffix = _host_suffix(fqdn, hosts, did_status)
        lines.append(f"{prefix}{connector} {fqdn}{suffix}")
        child_prefix = prefix + ("    " if is_last else "|   ")
        if children:
            _render_tree(children, child_prefix, fqdn, domain, hosts, did_status, lines)


def render_tree_lines(
    domain: str,
    subdomains: list[str],
    hosts: Optional[dict[str, HostInfo]] = None,
    did_status: bool = False,
) -> list[str]:
    lines: list[str] = [domain]
    tree = _build_tree(domain, subdomains)
    if tree:
        _render_tree(tree, "", domain, domain, hosts, did_status, lines)
    return lines


# ---------------------------------------------------------------------------
# JSON tree
# ---------------------------------------------------------------------------

def _build_json_tree(
    node: dict,
    parent_fqdn: str,
    domain: str,
    hosts: Optional[dict[str, HostInfo]],
    did_status: bool,
) -> list[dict]:
    result = []
    for label, children in sorted(node.items()):
        fqdn = f"{label}.{parent_fqdn}"
        entry: dict = {"name": fqdn}
        if hosts is not None and fqdn in hosts:
            info = hosts[fqdn]
            entry["ips"] = info.ips
            entry["dns_error"] = info.dns_error
            entry["cname_chain"] = info.cname_chain
            if info.takeover:
                entry["takeover"] = info.takeover.to_dict()
            if did_status:
                entry["checks"] = [c.to_dict() for c in info.checks]
        if children:
            entry["children"] = _build_json_tree(children, fqdn, domain, hosts, did_status)
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# Main emit
# ---------------------------------------------------------------------------

def emit_results(
    domain: str,
    results: dict[str, SourceResult],
    unique: list[str],
    *,
    as_json: bool,
    out_file: Optional[object],
    hosts: Optional[dict[str, HostInfo]] = None,
    did_status: bool = False,
    takeover_count: int = 0,
) -> None:
    if as_json:
        tree = _build_tree(domain, unique)
        payload = {
            "domain": domain,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total": len(unique),
            "takeovers_found": takeover_count,
            "tree": _build_json_tree(tree, domain, domain, hosts, did_status),
            "sources": {
                name: {
                    "count": len(res.subdomains),
                    "error": res.error,
                    "subdomains": sorted(res.subdomains),
                }
                for name, res in sorted(results.items())
            },
        }
        json_output = json.dumps(payload, indent=2)
        if out_file is not None:
            out_file.seek(0)
            out_file.truncate(0)
            out_file.write(json_output + "\n")
        else:
            print(json_output)
        return

    # Terminal
    source_errors = {name: res.error for name, res in results.items() if res.error}
    source_ok = {name: res for name, res in results.items() if not res.error}

    if source_ok:
        print("\n[+] Sources authenticated successfully:")
        for name in sorted(source_ok):
            print(f"    [+] {name}: Authentication successful")

    if source_errors:
        print("\n[!] Some sources reported errors:")
        for name, error in sorted(source_errors.items()):
            print(f"    [{name}] {error}")

    print()

    for line in render_tree_lines(domain, unique, hosts, did_status):
        print(line)

    if takeover_count:
        print(f"\n[!] {takeover_count} potential takeover(s) found (marked above)", flush=True)

    # File
    if out_file is not None:
        for line in render_tree_lines(domain, unique, hosts, did_status):
            out_file.write(line + "\n")
        if takeover_count:
            out_file.write(f"\n[!] {takeover_count} potential takeover(s) found\n")