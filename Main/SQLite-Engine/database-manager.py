from __future__ import annotations

import argparse
import json
import logging
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

logger = logging.getLogger("dns_to_sqlite")

@dataclass
class ChildTableSpec:
    source_key: str
    table_name: str
    parent_fk:  str
    columns: dict[str, str] | None = None

@dataclass
class TableSpec:
    table_name:     str
    scalar_columns: list[str] | None = None
    json_columns:   list[str]        = field(default_factory=list)
    child_tables:   list[ChildTableSpec] = field(default_factory=list)
    index_columns:  list[str]        = field(default_factory=list)

def _build_specs() -> dict[str, TableSpec]:
    specs: dict[str, TableSpec] = {}
    specs["records"] = TableSpec(
        table_name="dns_records",
        scalar_columns=["scan_id", "record_type", "ttl", "value"],
        index_columns=["scan_id", "record_type"],
    )
    specs["axfr"] = TableSpec(
        table_name="dns_axfr",
        scalar_columns=["scan_id", "vulnerable"],
        index_columns=["scan_id"],
    )
    specs["reverse"] = TableSpec(
        table_name="dns_reverse",
        scalar_columns=["scan_id", "ip", "hostname"],
        index_columns=["scan_id", "ip"],
    )
    specs["dangling"] = TableSpec(
        table_name="dns_dangling",
        scalar_columns=["scan_id", "subdomain", "cname", "service"],
        index_columns=["scan_id"],
    )
    specs["mail"] = TableSpec(
        table_name="dns_mail",
        scalar_columns=["scan_id", "spf", "dmarc"],
        json_columns=["dkim"],
        index_columns=["scan_id"],
    )
    specs["doh"] = TableSpec(
        table_name="dns_doh",
        scalar_columns=["scan_id", "provider", "status"],
        json_columns=["ips"],
        index_columns=["scan_id", "provider"],
    )
    specs["dot"] = TableSpec(
        table_name="dns_dot",
        scalar_columns=["scan_id", "provider", "port_open", "cert_valid", "sni_match"],
        index_columns=["scan_id", "provider"],
    )
    specs["dnssec"] = TableSpec(
        table_name="dns_dnssec",
        scalar_columns=["scan_id", "dnskey", "ds", "rrsig", "nsec", "chain_valid"],
        index_columns=["scan_id"],
    )
    specs["open_resolver"] = TableSpec(
        table_name="dns_open_resolver",
        scalar_columns=["scan_id", "nameserver", "recursive", "amplification_risk"],
        index_columns=["scan_id"],
    )
    specs["ttl_anomalies"] = TableSpec(
        table_name="dns_ttl_anomalies",
        scalar_columns=["scan_id", "name", "type", "ttl", "value", "anomaly"],
        index_columns=["scan_id"],
    )
    specs["spf_flattening"] = TableSpec(
        table_name="dns_spf_flatten",
        scalar_columns=[
            "scan_id", "cidr", "version", "source", "mechanism",
            "lookup_count", "lookup_limit", "over_limit",
            "original_spf", "flat_record",
        ],
        index_columns=["scan_id"],
    )
    specs["source_ip"] = TableSpec(
        table_name="dns_origin_ip",
        scalar_columns=[
            "scan_id", "ip", "version", "methods", "notes",
            "confidence", "asn", "source",
        ],
        index_columns=["scan_id"],
    )
    specs["subdomains"] = TableSpec(
        table_name="subdomains",
        scalar_columns=[
            "scan_id", "name", "ips", "dns_error", "cname_chain",
            "takeover_cname", "takeover_provider", "takeover_evidence",
            "https_status", "http_status", "https_final_url", "http_final_url",
            "https_error", "http_error",
        ],
        index_columns=["scan_id", "name"],
    )
    specs["subdomain_sources"] = TableSpec(
        table_name="subdomain_sources",
        scalar_columns=["scan_id", "source_name", "sub_count", "error"],
        index_columns=["scan_id"],
    )
    specs["social_profiles"] = TableSpec(
        table_name="social_profiles",
        scalar_columns=["scan_id", "platform", "url", "source", "confidence"],
        index_columns=["scan_id", "platform"],
    )
    specs["social_emails"] = TableSpec(
        table_name="social_emails",
        scalar_columns=["scan_id", "address", "source", "context", "verified"],
        index_columns=["scan_id"],
    )
    specs["social_html_meta"] = TableSpec(
        table_name="social_html_meta",
        scalar_columns=["scan_id", "source", "name", "value"],
        index_columns=["scan_id", "source"],
    )
    specs["social_docs"] = TableSpec(
        table_name="social_docs",
        scalar_columns=["scan_id", "url", "category", "file_type", "source"],
        index_columns=["scan_id", "category"],
    )
    return specs

KNOWN_SPECS = _build_specs()

TECH_SPECS: dict[str, TableSpec] = {
    "tech_technologies": TableSpec(
        table_name="tech_technologies",
        scalar_columns=["scan_id", "name", "version", "category", "confidence", "detected_via", "raw_value"],
        index_columns=["scan_id", "category"],
    ),
    "tech_favicon": TableSpec(
        table_name="tech_favicon",
        scalar_columns=["scan_id", "favicon_found", "favicon_url", "size_bytes",
                        "mmh3", "md5", "sha1", "sha256",
                        "technology_name", "technology_category",
                        "version_in_path", "file_format", "file_metadata",
                        "shodan_query", "censys_query", "fofa_query",
                        "zoomeye_query", "quake_query", "hunter_query"],
        index_columns=["scan_id"],
    ),
    "tech_vulnerabilities": TableSpec(
        table_name="tech_vulnerabilities",
        scalar_columns=["scan_id", "library", "version", "script_url",
                        "severity", "summary", "cve", "github_id", "affected_range", "info_url"],
        index_columns=["scan_id", "severity"],
    ),
    "tech_waf": TableSpec(
        table_name="tech_waf",
        scalar_columns=["scan_id", "waf_detected", "waf_names", "generic_detected", "generic_reason"],
        index_columns=["scan_id"],
    ),
    "tech_headers": TableSpec(
        table_name="tech_headers",
        scalar_columns=["scan_id", "name", "category", "detected_via", "raw_value"],
        index_columns=["scan_id"],
    ),
    "tech_cms": TableSpec(
        table_name="tech_cms",
        scalar_columns=["scan_id", "cms_detected", "cms_id", "cms_name", "cms_url", "cms_version", "detection_method"],
        index_columns=["scan_id"],
    ),
    "tech_retire_js": TableSpec(
        table_name="tech_retire_js",
        scalar_columns=["scan_id", "scripts_checked", "library", "version", "script_url", "has_vulnerabilities"],
        index_columns=["scan_id"],
    ),
}

WAYBACK_SPECS: dict[str, TableSpec] = {
    "wayback_urls": TableSpec(
        table_name="wayback_urls",
        scalar_columns=["scan_id", "url", "source"],
        index_columns=["scan_id"],
    ),
    "wayback_subdomains": TableSpec(
        table_name="wayback_subdomains",
        scalar_columns=["scan_id", "url"],
        index_columns=["scan_id"],
    ),
    "wayback_critical_patterns": TableSpec(
        table_name="wayback_critical_patterns",
        scalar_columns=["scan_id", "pattern_name", "url"],
        index_columns=["scan_id", "pattern_name"],
    ),
    "wayback_files": TableSpec(
        table_name="wayback_files",
        scalar_columns=["scan_id", "url"],
        index_columns=["scan_id"],
    ),
    "wayback_parameters": TableSpec(
        table_name="wayback_parameters",
        scalar_columns=["scan_id", "param_name", "count", "is_sensitive"],
        index_columns=["scan_id", "param_name"],
    ),
}

TLS_SPECS: dict[str, TableSpec] = {
    "tls_scans": TableSpec(
        table_name="tls_scans",
        scalar_columns=[
            "target", "sni", "scanner", "scan_time", "source_file",
        ],
        index_columns=["target"],
    ),
    "tls_cert_chain": TableSpec(
        table_name="tls_cert_chain",
        scalar_columns=[
            "scan_id", "chain_index", "role",
            "subject_cn", "subject_o", "subject_c", "subject_l",
            "issuer_cn", "issuer_o", "issuer_c", "issuer_ou",
            "serial", "not_before", "not_after", "days_remaining",
            "expired", "not_yet_valid", "self_signed", "is_ca",
            "key_type", "key_bits", "key_weak",
            "signature_algorithm",
            "fingerprint_sha256", "fingerprint_sha1",
            "sct_count",
            "basic_constraints_ca", "basic_constraints_path_length",
            "key_usage", "extended_key_usage",
            "ocsp_urls", "ca_issuer_urls", "sans",
        ],
        index_columns=["scan_id", "chain_index", "role"],
    ),
    "tls_ct_entries": TableSpec(
        table_name="tls_ct_entries",
        scalar_columns=[
            "scan_id", "ct_id", "logged_at", "not_before", "not_after",
            "common_name", "issuer",
            "queried_domain", "source", "total_found",
        ],
        index_columns=["scan_id"],
    ),
    "tls_ocsp": TableSpec(
        table_name="tls_ocsp",
        scalar_columns=[
            "scan_id", "status", "responder",
            "this_update", "next_update", "revocation_time", "revocation_reason",
            "cert_status", "error",
        ],
        index_columns=["scan_id"],
    ),
    "tls_cert_assessment": TableSpec(
        table_name="tls_cert_assessment",
        scalar_columns=[
            "scan_id", "grade", "chain_complete", "chain_trusted",
            "issues", "warnings", "notes",
        ],
        index_columns=["scan_id"],
    ),
    "tls_protocols": TableSpec(
        table_name="tls_protocols",
        scalar_columns=[
            "scan_id", "version", "supported", "rating", "rating_reason",
            "cipher_name", "cipher_bits", "handshake_time_ms", "error",
        ],
        index_columns=["scan_id", "version"],
    ),
    "tls_handshake": TableSpec(
        table_name="tls_handshake",
        scalar_columns=[
            "scan_id", "negotiated_version",
            "cipher_name", "cipher_bits", "handshake_time_ms",
            "session_ticket",
        ],
        index_columns=["scan_id"],
    ),
    "tls_alpn": TableSpec(
        table_name="tls_alpn",
        scalar_columns=[
            "scan_id", "http2_supported", "http11_supported",
            "supported_protocols",
        ],
        index_columns=["scan_id"],
    ),
    "tls_proto_assessment": TableSpec(
        table_name="tls_proto_assessment",
        scalar_columns=[
            "scan_id", "grade", "issues", "warnings", "notes",
        ],
        index_columns=["scan_id"],
    ),
    "tls_ciphers": TableSpec(
        table_name="tls_ciphers",
        scalar_columns=[
            "scan_id", "name", "protocol", "bits", "supported",
            "pfs", "strength", "category", "error",
        ],
        index_columns=["scan_id", "supported", "category"],
    ),
    "tls_cipher_assessment": TableSpec(
        table_name="tls_cipher_assessment",
        scalar_columns=[
            "scan_id", "grade", "pfs_count", "non_pfs_count",
            "strong_count", "weak_count", "insecure_count",
            "issues", "warnings", "notes",
        ],
        index_columns=["scan_id"],
    ),
    "tls_pfs_groups": TableSpec(
        table_name="tls_pfs_groups",
        scalar_columns=[
            "scan_id", "name", "type", "supported",
            "key_bits", "protocol", "cipher", "handshake_time_ms",
            "classification", "error",
        ],
        index_columns=["scan_id", "type", "supported"],
    ),
    "tls_pfs_assessment": TableSpec(
        table_name="tls_pfs_assessment",
        scalar_columns=[
            "scan_id", "grade", "strength_level",
            "best_ecdhe_group", "best_ecdhe_bits",
            "best_ffdhe_group", "best_ffdhe_bits",
            "ecdhe_strong_count", "ecdhe_obsolete_count", "ecdhe_weak_count",
            "ffdhe_strong_count",
            "custom_dhe_supported", "dhe_bits", "dhe_strength",
            "issues", "warnings", "notes",
        ],
        index_columns=["scan_id"],
    ),
    "tls_fallback": TableSpec(
        table_name="tls_fallback",
        scalar_columns=[
            "scan_id", "highest_version",
            "vuln_name", "vulnerable", "certainty", "detail",
            "downgrade_attempted",
        ],
        index_columns=["scan_id"],
    ),
    "tls_fallback_assessment": TableSpec(
        table_name="tls_fallback_assessment",
        scalar_columns=[
            "scan_id", "grade",
            "confirmed_count", "probable_count", "potential_count",
            "unknown_count", "safe_count", "total_checked",
            "issues", "warnings", "notes",
        ],
        index_columns=["scan_id"],
    ),
    "tls_network_caa": TableSpec(
        table_name="tls_network_caa",
        scalar_columns=[
            "scan_id", "tag", "value", "flags", "critical", "summary",
        ],
        index_columns=["scan_id"],
    ),
    "tls_network_dane": TableSpec(
        table_name="tls_network_dane",
        scalar_columns=[
            "scan_id", "services", "validation",
        ],
        index_columns=["scan_id"],
    ),
    "tls_network_mta_sts": TableSpec(
        table_name="tls_network_mta_sts",
        scalar_columns=[
            "scan_id", "dns_record", "policy", "error",
        ],
        index_columns=["scan_id"],
    ),
    "tls_network_assessment": TableSpec(
        table_name="tls_network_assessment",
        scalar_columns=[
            "scan_id", "grade", "issues", "warnings", "notes",
        ],
        index_columns=["scan_id"],
    ),
}

def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'

def _sqlite_type(value: Any) -> str:
    if isinstance(value, bool):
        return "INTEGER"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "REAL"
    return "TEXT"

def _to_sqlite(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return value

class SqliteWriter:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._created: set[str] = set()
        self._cols:    dict[str, set[str]] = {}

    def ensure_table(self, table: str, col_types: dict[str, str]) -> None:
        cur = self.conn.cursor()
        if table not in self._created:
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            )
            if cur.fetchone() is None:
                cols_sql = ",\n    ".join(
                    f"{_quote(c)} {t}" for c, t in col_types.items()
                )
                cur.execute(
                    f"CREATE TABLE {_quote(table)} (\n"
                    f"    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                    f"    {cols_sql}\n"
                    f")"
                )
                self._cols[table] = set(col_types)
            else:
                cur.execute(f"PRAGMA table_info({_quote(table)})")
                existing = {row[1] for row in cur.fetchall()}
                for col, ctype in col_types.items():
                    if col not in existing:
                        cur.execute(
                            f"ALTER TABLE {_quote(table)} ADD COLUMN {_quote(col)} {ctype}"
                        )
                self._cols[table] = existing | set(col_types)
            self._created.add(table)
        else:
            known = self._cols[table]
            for col, ctype in col_types.items():
                if col not in known:
                    cur.execute(
                        f"ALTER TABLE {_quote(table)} ADD COLUMN {_quote(col)} {ctype}"
                    )
                    known.add(col)

    def insert(self, table: str, row: dict[str, Any]) -> int:
        cols = list(row)
        ph   = ", ".join("?" for _ in cols)
        cs   = ", ".join(_quote(c) for c in cols)
        cur  = self.conn.execute(
            f"INSERT INTO {_quote(table)} ({cs}) VALUES ({ph})",
            [row[c] for c in cols],
        )
        return cur.lastrowid

    def create_index(self, table: str, col: str) -> None:
        idx = f"idx_{table}_{col}"
        try:
            self.conn.execute(
                f"CREATE INDEX IF NOT EXISTS {_quote(idx)} "
                f"ON {_quote(table)} ({_quote(col)})"
            )
        except sqlite3.OperationalError as exc:
            logger.warning("Index skipped (%s.%s): %s", table, col, exc)

def _ensure_scans_table(writer: SqliteWriter) -> None:
    writer.ensure_table("scans", {
        "target":    "TEXT",
        "timestamp": "TEXT",
        "source_file": "TEXT",
    })

def _insert_scan(writer: SqliteWriter, target: str, timestamp: str, source_file: str) -> int:
    return writer.insert("scans", {
        "target":      _to_sqlite(target),
        "timestamp":   _to_sqlite(timestamp),
        "source_file": _to_sqlite(source_file),
    })

def _write_module_result(writer: SqliteWriter, scan_id: int, module: str, data: Any) -> None:
    writer.ensure_table("dns_module_results", {
        "scan_id": "INTEGER",
        "module":  "TEXT",
        "result":  "TEXT",
    })
    writer.insert("dns_module_results", {
        "scan_id": scan_id,
        "module":  module,
        "result":  _to_sqlite(data),
    })
    writer.create_index("dns_module_results", "scan_id")
    writer.create_index("dns_module_results", "module")

def _write_records(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec  = KNOWN_SPECS["records"]
    count = 0
    col_types = {
        "scan_id":     "INTEGER",
        "record_type": "TEXT",
        "ttl":         "INTEGER",
        "value":       "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    for rtype, values in data.items():
        if isinstance(values, dict):
            ttl  = values.get("ttl")
            recs = values.get("records", [])
            row_ttl = int(ttl) if ttl is not None else None
            for rec in recs:
                writer.insert(spec.table_name, {
                    "scan_id":     scan_id,
                    "record_type": str(rtype),
                    "ttl":         row_ttl,
                    "value":       str(rec),
                })
                count += 1
        elif isinstance(values, list):
            for val in values:
                if isinstance(val, dict):
                    row_value = str(val.get("value", ""))
                    row_ttl   = int(val["ttl"]) if val.get("ttl") is not None else None
                else:
                    row_value = str(val)
                    row_ttl   = None
                writer.insert(spec.table_name, {
                    "scan_id":     scan_id,
                    "record_type": str(rtype),
                    "ttl":         row_ttl,
                    "value":       row_value,
                })
                count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_axfr(writer: SqliteWriter, scan_id: int, data: bool) -> int:
    spec      = KNOWN_SPECS["axfr"]
    col_types = {
        "scan_id":     "INTEGER",
        "vulnerable":  "INTEGER",
        "error":       "TEXT",
        "any_records": "TEXT",
        "soa_info":    "TEXT",
        "zone_records": "TEXT",
        "notify_sources": "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    if isinstance(data, dict):
        vulnerable      = int(bool(data.get("vulnerable", False)))
        error           = data.get("error")
        any_records     = _to_sqlite(data.get("any_records", []))
        soa_info        = _to_sqlite(data.get("soa_info", {}))
        zone_records    = _to_sqlite(data.get("zone_records", []))
        notify_sources  = _to_sqlite(data.get("notify_sources", []))
    else:
        vulnerable      = int(bool(data))
        error           = None
        any_records     = _to_sqlite([])
        soa_info        = _to_sqlite({})
        zone_records    = _to_sqlite([])
        notify_sources  = _to_sqlite([])
    writer.insert(spec.table_name, {
        "scan_id":        scan_id,
        "vulnerable":     vulnerable,
        "error":          error,
        "any_records":    any_records,
        "soa_info":       soa_info,
        "zone_records":   zone_records,
        "notify_sources": notify_sources,
    })
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return 1

def _write_reverse(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec      = KNOWN_SPECS["reverse"]
    col_types = {"scan_id": "INTEGER", "ip": "TEXT", "hostname": "TEXT"}
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for ip, hostname in data.items():
        writer.insert(spec.table_name, {
            "scan_id":  scan_id,
            "ip":       str(ip),
            "hostname": str(hostname) if hostname else None,
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_dangling(writer: SqliteWriter, scan_id: int, data: list) -> int:
    spec      = KNOWN_SPECS["dangling"]
    col_types = {"scan_id": "INTEGER", "subdomain": "TEXT", "cname": "TEXT", "service": "TEXT"}
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for entry in data:
        writer.insert(spec.table_name, {
            "scan_id":   scan_id,
            "subdomain": entry.get("subdomain"),
            "cname":     entry.get("cname"),
            "service":   entry.get("service"),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_mail(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec      = KNOWN_SPECS["mail"]
    col_types = {"scan_id": "INTEGER", "spf": "TEXT", "dmarc": "TEXT", "dkim": "TEXT"}
    writer.ensure_table(spec.table_name, col_types)
    writer.insert(spec.table_name, {
        "scan_id": scan_id,
        "spf":     data.get("spf"),
        "dmarc":   data.get("dmarc"),
        "dkim":    _to_sqlite(data.get("dkim", {})),
    })
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return 1

def _write_doh(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec      = KNOWN_SPECS["doh"]
    col_types = {"scan_id": "INTEGER", "provider": "TEXT", "status": "TEXT", "ips": "TEXT"}
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for provider, result in data.items():
        writer.insert(spec.table_name, {
            "scan_id":  scan_id,
            "provider": str(provider),
            "status":   result.get("status"),
            "ips":      _to_sqlite(result.get("ips", [])),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_dot(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec      = KNOWN_SPECS["dot"]
    col_types = {
        "scan_id":    "INTEGER",
        "provider":   "TEXT",
        "port_open":  "INTEGER",
        "cert_valid": "INTEGER",
        "sni_match":  "INTEGER",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for provider, result in data.items():
        writer.insert(spec.table_name, {
            "scan_id":    scan_id,
            "provider":   str(provider),
            "port_open":  int(bool(result.get("port_open"))),
            "cert_valid": int(bool(result.get("cert_valid"))),
            "sni_match":  int(bool(result.get("sni_match"))),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_dnssec(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec      = KNOWN_SPECS["dnssec"]
    col_types = {
        "scan_id":        "INTEGER",
        "dnskey":         "INTEGER",
        "ds":             "INTEGER",
        "rrsig":          "INTEGER",
        "nsec":           "INTEGER",
        "chain_valid":    "INTEGER",
        "nsec_walk":      "TEXT",
        "nsec3_optout":   "TEXT",
        "sshfp":          "TEXT",
        "rrsig_expiry":   "TEXT",
        "tlsa":           "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    writer.insert(spec.table_name, {
        "scan_id":      scan_id,
        "dnskey":       int(bool(data.get("dnskey"))),
        "ds":           int(bool(data.get("ds"))),
        "rrsig":        int(bool(data.get("rrsig"))),
        "nsec":         int(bool(data.get("nsec"))),
        "chain_valid":  int(bool(data.get("chain_valid"))),
        "nsec_walk":    _to_sqlite(data.get("nsec_walk", [])),
        "nsec3_optout": _to_sqlite(data.get("nsec3_optout", {})),
        "sshfp":        _to_sqlite(data.get("sshfp", [])),
        "rrsig_expiry": _to_sqlite(data.get("rrsig_expiry", [])),
        "tlsa":         _to_sqlite(data.get("tlsa", [])),
    })
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return 1

def _write_open_resolver(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec      = KNOWN_SPECS["open_resolver"]
    col_types = {
        "scan_id":            "INTEGER",
        "nameserver":         "TEXT",
        "recursive":          "INTEGER",
        "amplification_risk": "INTEGER",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for ns, result in data.items():
        writer.insert(spec.table_name, {
            "scan_id":            scan_id,
            "nameserver":         str(ns),
            "recursive":          int(bool(result.get("recursive"))),
            "amplification_risk": int(bool(result.get("amplification_risk"))),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_ttl_anomalies(writer: SqliteWriter, scan_id: int, data: list) -> int:
    spec      = KNOWN_SPECS["ttl_anomalies"]
    col_types = {
        "scan_id": "INTEGER",
        "name":    "TEXT",
        "type":    "TEXT",
        "ttl":     "INTEGER",
        "value":   "TEXT",
        "anomaly": "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for entry in data:
        writer.insert(spec.table_name, {
            "scan_id": scan_id,
            "name":    entry.get("check")    or entry.get("name"),
            "type":    entry.get("severity") or entry.get("type"),
            "ttl":     entry.get("minimum")  or entry.get("ttl"),
            "value":   entry.get("detail")   or entry.get("value"),
            "anomaly": entry.get("check")    or entry.get("anomaly"),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_spf_flatten(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec = KNOWN_SPECS["spf_flattening"]
    col_types = {
        "scan_id":      "INTEGER",
        "cidr":         "TEXT",
        "version":      "TEXT",
        "source":       "TEXT",
        "mechanism":    "TEXT",
        "lookup_count": "INTEGER",
        "lookup_limit": "INTEGER",
        "over_limit":   "INTEGER",
        "original_spf": "TEXT",
        "flat_record":  "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    lookup_count = data.get("lookup_count", 0)
    lookup_limit = data.get("lookup_limit", 10)
    over_limit   = int(bool(data.get("over_limit", False)))
    original_spf = data.get("original_spf")
    flat_record  = data.get("flat_record")
    count        = 0

    def _collect_tree(node: dict, parent_domain: str):
        for ip in node.get("ip4", []):
            yield (ip, "ipv4", parent_domain, "ip4")
        for ip in node.get("ip6", []):
            yield (ip, "ipv6", parent_domain, "ip6")
        for inc_domain, child in node.get("includes", {}).items():
            yield from _collect_tree(child, inc_domain)
        for redir_domain, child in node.get("redirects", {}).items():
            yield from _collect_tree(child, redir_domain)

    tree = data.get("expansion_tree") or {}
    seen = set()
    for (cidr, version, source, mechanism) in _collect_tree(tree, "root"):
        key = (cidr, source)
        if key in seen:
            continue
        seen.add(key)
        writer.insert(spec.table_name, {
            "scan_id":      scan_id,
            "cidr":         cidr,
            "version":      version,
            "source":       source,
            "mechanism":    mechanism,
            "lookup_count": lookup_count,
            "lookup_limit": lookup_limit,
            "over_limit":   over_limit,
            "original_spf": original_spf,
            "flat_record":  flat_record,
        })
        count += 1

    if count == 0:
        for cidr in data.get("ip4", []):
            writer.insert(spec.table_name, {
                "scan_id":      scan_id,
                "cidr":         cidr,
                "version":      "ipv4",
                "source":       "spf_root",
                "mechanism":    "ip4",
                "lookup_count": lookup_count,
                "lookup_limit": lookup_limit,
                "over_limit":   over_limit,
                "original_spf": original_spf,
                "flat_record":  flat_record,
            })
            count += 1
        for cidr in data.get("ip6", []):
            writer.insert(spec.table_name, {
                "scan_id":      scan_id,
                "cidr":         cidr,
                "version":      "ipv6",
                "source":       "spf_root",
                "mechanism":    "ip6",
                "lookup_count": lookup_count,
                "lookup_limit": lookup_limit,
                "over_limit":   over_limit,
                "original_spf": original_spf,
                "flat_record":  flat_record,
            })
            count += 1

    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_source_ip(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    import ipaddress as _ipaddress
    spec = KNOWN_SPECS["source_ip"]
    col_types = {
        "scan_id":    "INTEGER",
        "ip":         "TEXT",
        "version":    "TEXT",
        "methods":    "TEXT",
        "notes":      "TEXT",
        "confidence": "TEXT",
        "asn":        "TEXT",
        "source":     "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    candidates = data.get("candidates", {})
    for ip_key, meta in candidates.items():
        methods = meta.get("methods", [])
        notes   = meta.get("notes", [])
        host = ip_key.split("/")[0]
        try:
            addr    = _ipaddress.ip_address(host)
            version = "ipv6" if addr.version == 6 else "ipv4"
        except ValueError:
            version = "ipv4"
        method_count = len(methods)
        confidence = "HIGH" if method_count >= 2 else ("MEDIUM" if method_count == 1 else "LOW")
        asn = ""
        for note in notes:
            if "cloudflare" in note.lower():
                asn = "Cloudflare"
                break
            if "akamai" in note.lower():
                asn = "Akamai"
                break
            if "fastly" in note.lower():
                asn = "Fastly"
                break
            if "amazon" in note.lower() or "aws" in note.lower():
                asn = "Amazon AWS"
                break
        writer.insert(spec.table_name, {
            "scan_id":    scan_id,
            "ip":         ip_key,
            "version":    version,
            "methods":    _to_sqlite(methods),
            "notes":      _to_sqlite(notes),
            "confidence": confidence,
            "asn":        asn or None,
            "source":     methods[0] if methods else None,
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _flatten_tree(nodes: list) -> Iterator[dict]:
    for node in nodes:
        yield node
        if node.get("children"):
            yield from _flatten_tree(node["children"])

def _write_subdomains(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    col_types = {
        "scan_id":           "INTEGER",
        "name":              "TEXT",
        "ips":               "TEXT",
        "dns_error":         "TEXT",
        "cname_chain":       "TEXT",
        "takeover_cname":    "TEXT",
        "takeover_provider": "TEXT",
        "takeover_evidence": "TEXT",
        "https_status":      "INTEGER",
        "http_status":       "INTEGER",
        "https_final_url":   "TEXT",
        "http_final_url":    "TEXT",
        "https_error":       "TEXT",
        "http_error":        "TEXT",
    }
    writer.ensure_table("subdomains", col_types)
    count = 0
    for node in _flatten_tree(data.get("tree", [])):
        takeover = node.get("takeover") or {}
        checks   = {c["scheme"]: c for c in (node.get("checks") or [])}
        https_c  = checks.get("https", {})
        http_c   = checks.get("http",  {})
        writer.insert("subdomains", {
            "scan_id":           scan_id,
            "name":              node.get("name"),
            "ips":               _to_sqlite(node.get("ips", [])),
            "dns_error":         node.get("dns_error"),
            "cname_chain":       _to_sqlite(node.get("cname_chain", [])),
            "takeover_cname":    takeover.get("cname"),
            "takeover_provider": takeover.get("provider"),
            "takeover_evidence": takeover.get("evidence"),
            "https_status":      https_c.get("status"),
            "http_status":       http_c.get("status"),
            "https_final_url":   https_c.get("final_url"),
            "http_final_url":    http_c.get("final_url"),
            "https_error":       https_c.get("error"),
            "http_error":        http_c.get("error"),
        })
        count += 1
    writer.create_index("subdomains", "scan_id")
    writer.create_index("subdomains", "name")
    return count

def _write_subdomain_sources(writer: SqliteWriter, scan_id: int, sources: dict) -> int:
    col_types = {
        "scan_id":     "INTEGER",
        "source_name": "TEXT",
        "sub_count":   "INTEGER",
        "error":       "TEXT",
    }
    writer.ensure_table("subdomain_sources", col_types)
    count = 0
    for name, info in sources.items():
        writer.insert("subdomain_sources", {
            "scan_id":     scan_id,
            "source_name": name,
            "sub_count":   info.get("count", 0),
            "error":       info.get("error"),
        })
        count += 1
    writer.create_index("subdomain_sources", "scan_id")
    return count

PLATFORM_SIGNATURES = {
    "linkedin":   [r"linkedin\.com", r"linkedin\.com/(company|in|school)/"],
    "twitter":    [r"twitter\.com/", r"x\.com/"],
    "github":     [r"github\.com/"],
    "facebook":   [r"facebook\.com/", r"fb\.com/"],
    "instagram":  [r"instagram\.com/"],
    "youtube":    [r"youtube\.com/", r"youtu\.be/"],
    "telegram":   [r"t\.me/"],
    "medium":     [r"medium\.com/"],
    "crunchbase": [r"crunchbase\.com/"],
    "glassdoor":  [r"glassdoor\.com/"],
}

def _detect_platform(url: str) -> str:
    import re
    for platform, patterns in PLATFORM_SIGNATURES.items():
        if any(re.search(p, url, re.IGNORECASE) for p in patterns):
            return platform.capitalize()
    return "Other"

def _conf_label(source: str) -> str:
    if source in ("rel_me", "link_rel_me"):
        return "high"
    if source == "anchor":
        return "medium"
    return "low"

def _write_social_profiles(writer: SqliteWriter, scan_id: int, items: list) -> int:
    col_types = {
        "scan_id":    "INTEGER",
        "platform":   "TEXT",
        "url":        "TEXT",
        "source":     "TEXT",
        "confidence": "TEXT",
    }
    writer.ensure_table("social_profiles", col_types)
    count = 0
    for item in items:
        url      = item.get("url") or item.get("value") or ""
        src      = item.get("source") or ""
        platform = item.get("platform") or _detect_platform(url)
        if not url or src == "hidden_input":
            continue
        writer.insert("social_profiles", {
            "scan_id":    scan_id,
            "platform":   platform,
            "url":        url,
            "source":     src,
            "confidence": _conf_label(src),
        })
        count += 1
    writer.create_index("social_profiles", "scan_id")
    writer.create_index("social_profiles", "platform")
    return count

def _write_social_emails(writer: SqliteWriter, scan_id: int, items: list) -> int:
    col_types = {
        "scan_id":  "INTEGER",
        "address":  "TEXT",
        "source":   "TEXT",
        "context":  "TEXT",
        "verified": "INTEGER",
    }
    writer.ensure_table("social_emails", col_types)
    count = 0
    for item in items:
        addr = item.get("email") or item.get("value") or item.get("address") or ""
        if "@" not in addr:
            continue
        writer.insert("social_emails", {
            "scan_id":  scan_id,
            "address":  addr,
            "source":   item.get("source") or "web",
            "context":  item.get("context") or item.get("note") or "",
            "verified": int(bool(item.get("verified", False))),
        })
        count += 1
    writer.create_index("social_emails", "scan_id")
    return count

def _write_social_html_meta(writer: SqliteWriter, scan_id: int, items: list) -> int:
    col_types = {
        "scan_id": "INTEGER",
        "source":  "TEXT",
        "name":    "TEXT",
        "value":   "TEXT",
    }
    writer.ensure_table("social_html_meta", col_types)
    count = 0
    for item in items:
        writer.insert("social_html_meta", {
            "scan_id": scan_id,
            "source":  item.get("source") or "",
            "name":    item.get("name") or item.get("property") or "",
            "value":   str(item.get("value") or ""),
        })
        count += 1
    writer.create_index("social_html_meta", "scan_id")
    writer.create_index("social_html_meta", "source")
    return count

_DOC_CONTAINER_KEYS = {"files", "findings", "items", "results", "rows", "documents", "docs"}

def _doc_ext(url: str) -> str:
    name = urlsplit(url).path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""

def _normalize_doc_items(items: Any) -> list[dict]:
    found: list[dict] = []

    def _add(url: Any, category: str = "", file_type: str = "", source: str = "") -> None:
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            found.append({
                "url":       url.strip(),
                "category":  (category or "").strip(),
                "file_type": (file_type or "").strip().lower(),
                "source":    (source or "").strip(),
            })

    def _walk(node: Any, category: str = "") -> None:
        if isinstance(node, dict):
            url = node.get("url") or node.get("value")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                _add(
                    url,
                    str(node.get("category") or category or ""),
                    str(node.get("file_type") or node.get("type") or node.get("extension") or node.get("ext") or ""),
                    str(node.get("source") or ""),
                )
                return
            for key, val in node.items():
                if isinstance(val, (list, dict)):
                    _walk(val, category if key in _DOC_CONTAINER_KEYS else str(key))
        elif isinstance(node, list):
            for entry in node:
                _walk(entry, category)
        elif isinstance(node, str):
            _add(node, category)

    _walk(items)

    seen: set[str] = set()
    unique: list[dict] = []
    for row in found:
        if row["url"] in seen:
            continue
        seen.add(row["url"])
        row["file_type"] = row["file_type"] or _doc_ext(row["url"])
        row["category"]  = row["category"] or "Other"
        unique.append(row)
    return unique

def _write_social_docs(writer: SqliteWriter, scan_id: int, items: Any) -> int:
    col_types = {
        "scan_id":   "INTEGER",
        "url":       "TEXT",
        "category":  "TEXT",
        "file_type": "TEXT",
        "source":    "TEXT",
    }
    writer.ensure_table("social_docs", col_types)
    count = 0
    for row in _normalize_doc_items(items):
        writer.insert("social_docs", {
            "scan_id":   scan_id,
            "url":       row["url"],
            "category":  row["category"],
            "file_type": row["file_type"],
            "source":    row["source"],
        })
        count += 1
    writer.create_index("social_docs", "scan_id")
    writer.create_index("social_docs", "category")
    return count

# ═══════════════════════════════════════════════════════════════════════════
# TLS SCANNER WRITERS
# ═══════════════════════════════════════════════════════════════════════════

def _is_tls_scanner(data: dict) -> bool:
    """Detect certificate.json produced by TLS Scanner."""
    meta = data.get("meta", {})
    return (
        isinstance(meta, dict)
        and "scanner" in meta
        and "target" in meta
        and "results" in data
        and isinstance(data.get("results"), dict)
        and "certificates" in data["results"]
    )

def _write_tls_scanner(
    writer: SqliteWriter,
    data: dict,
    source_file: str,
    progress_cb: "Callable[[str, int], None] | None" = None,
) -> dict[str, int]:
    meta    = data.get("meta", {})
    results = data.get("results", {})
    target  = meta.get("target", "")
    counts: dict[str, int] = {}

    # ── scans row ──────────────────────────────────────────────────────────
    writer.ensure_table("tls_scans", {
        "target":      "TEXT",
        "sni":         "TEXT",
        "scanner":     "TEXT",
        "scan_time":   "TEXT",
        "source_file": "TEXT",
    })
    scan_id = writer.insert("tls_scans", {
        "target":      target,
        "sni":         meta.get("sni"),
        "scanner":     meta.get("scanner"),
        "scan_time":   meta.get("scan_time"),
        "source_file": source_file,
    })
    writer.create_index("tls_scans", "target")
    counts["tls_scans"] = 1

    # ── certificates ───────────────────────────────────────────────────────
    certs_block  = results.get("certificates", {})
    chain        = certs_block.get("chain", [])
    ocsp_block   = certs_block.get("ocsp", {})
    ct_block     = certs_block.get("ct",   {})
    cert_assess  = certs_block.get("assessment", {})

    # cert chain
    writer.ensure_table("tls_cert_chain", {
        "scan_id": "INTEGER", "chain_index": "INTEGER", "role": "TEXT",
        "subject_cn": "TEXT", "subject_o": "TEXT", "subject_c": "TEXT", "subject_l": "TEXT",
        "issuer_cn": "TEXT",  "issuer_o": "TEXT",  "issuer_c": "TEXT",  "issuer_ou": "TEXT",
        "serial": "TEXT", "not_before": "TEXT", "not_after": "TEXT",
        "days_remaining": "INTEGER", "expired": "INTEGER", "not_yet_valid": "INTEGER",
        "self_signed": "INTEGER", "is_ca": "INTEGER",
        "key_type": "TEXT", "key_bits": "INTEGER", "key_weak": "INTEGER",
        "signature_algorithm": "TEXT",
        "fingerprint_sha256": "TEXT", "fingerprint_sha1": "TEXT",
        "sct_count": "INTEGER",
        "basic_constraints_ca": "INTEGER", "basic_constraints_path_length": "INTEGER",
        "key_usage": "TEXT", "extended_key_usage": "TEXT",
        "ocsp_urls": "TEXT", "ca_issuer_urls": "TEXT", "sans": "TEXT",
    })
    for cert in chain:
        subj = cert.get("subject", {})
        iss  = cert.get("issuer",  {})
        key  = cert.get("key",     {})
        fps  = cert.get("fingerprints", {})
        bc   = cert.get("basic_constraints", {})
        writer.insert("tls_cert_chain", {
            "scan_id":       scan_id,
            "chain_index":   cert.get("index"),
            "role":          cert.get("role"),
            "subject_cn":    subj.get("CN"),
            "subject_o":     subj.get("O"),
            "subject_c":     subj.get("C"),
            "subject_l":     subj.get("L"),
            "issuer_cn":     iss.get("CN"),
            "issuer_o":      iss.get("O"),
            "issuer_c":      iss.get("C"),
            "issuer_ou":     iss.get("OU"),
            "serial":        cert.get("serial"),
            "not_before":    cert.get("not_before"),
            "not_after":     cert.get("not_after"),
            "days_remaining": cert.get("days_remaining"),
            "expired":       int(bool(cert.get("expired"))),
            "not_yet_valid": int(bool(cert.get("not_yet_valid"))),
            "self_signed":   int(bool(cert.get("self_signed"))),
            "is_ca":         int(bool(cert.get("is_ca"))),
            "key_type":      key.get("type"),
            "key_bits":      key.get("bits"),
            "key_weak":      int(bool(key.get("weak"))),
            "signature_algorithm": cert.get("signature_algorithm"),
            "fingerprint_sha256":  fps.get("sha256"),
            "fingerprint_sha1":    fps.get("sha1"),
            "sct_count":     cert.get("sct_count"),
            "basic_constraints_ca":          int(bool(bc.get("ca"))),
            "basic_constraints_path_length": bc.get("path_length"),
            "key_usage":      _to_sqlite(cert.get("key_usage", [])),
            "extended_key_usage": _to_sqlite(cert.get("extended_key_usage", [])),
            "ocsp_urls":      _to_sqlite(cert.get("ocsp_urls", [])),
            "ca_issuer_urls": _to_sqlite(cert.get("ca_issuer_urls", [])),
            "sans":           _to_sqlite([s.get("value") for s in cert.get("sans", [])]),
        })
    writer.create_index("tls_cert_chain", "scan_id")
    writer.create_index("tls_cert_chain", "role")
    counts["tls_cert_chain"] = len(chain)
    if progress_cb: progress_cb("tls_cert_chain", len(chain))

    # CT entries
    ct_entries = ct_block.get("entries", [])
    writer.ensure_table("tls_ct_entries", {
        "scan_id": "INTEGER", "ct_id": "TEXT", "logged_at": "TEXT",
        "not_before": "TEXT", "not_after": "TEXT",
        "common_name": "TEXT", "issuer": "TEXT",
        "queried_domain": "TEXT", "source": "TEXT", "total_found": "INTEGER",
    })
    for entry in ct_entries:
        writer.insert("tls_ct_entries", {
            "scan_id":       scan_id,
            "ct_id":         entry.get("id"),
            "logged_at":     entry.get("logged_at"),
            "not_before":    entry.get("not_before"),
            "not_after":     entry.get("not_after"),
            "common_name":   entry.get("common_name"),
            "issuer":        entry.get("issuer"),
            "queried_domain": ct_block.get("queried_domain"),
            "source":        ct_block.get("source"),
            "total_found":   ct_block.get("total_found"),
        })
    writer.create_index("tls_ct_entries", "scan_id")
    counts["tls_ct_entries"] = len(ct_entries)
    if progress_cb: progress_cb("tls_ct_entries", len(ct_entries))

    # OCSP
    writer.ensure_table("tls_ocsp", {
        "scan_id": "INTEGER", "status": "TEXT", "responder": "TEXT",
        "this_update": "TEXT", "next_update": "TEXT",
        "revocation_time": "TEXT", "revocation_reason": "TEXT",
        "cert_status": "TEXT", "error": "TEXT",
    })
    writer.insert("tls_ocsp", {
        "scan_id":           scan_id,
        "status":            ocsp_block.get("status"),
        "responder":         ocsp_block.get("responder"),
        "this_update":       ocsp_block.get("this_update"),
        "next_update":       ocsp_block.get("next_update"),
        "revocation_time":   ocsp_block.get("revocation_time"),
        "revocation_reason": ocsp_block.get("revocation_reason"),
        "cert_status":       ocsp_block.get("cert_status"),
        "error":             ocsp_block.get("error"),
    })
    writer.create_index("tls_ocsp", "scan_id")
    counts["tls_ocsp"] = 1
    if progress_cb: progress_cb("tls_ocsp", 1)

    # cert assessment
    writer.ensure_table("tls_cert_assessment", {
        "scan_id": "INTEGER", "grade": "TEXT",
        "chain_complete": "INTEGER", "chain_trusted": "INTEGER",
        "issues": "TEXT", "warnings": "TEXT", "notes": "TEXT",
    })
    writer.insert("tls_cert_assessment", {
        "scan_id":       scan_id,
        "grade":         cert_assess.get("grade"),
        "chain_complete": int(bool(cert_assess.get("chain_complete"))),
        "chain_trusted":  int(bool(cert_assess.get("chain_trusted"))),
        "issues":   _to_sqlite(cert_assess.get("issues",   [])),
        "warnings": _to_sqlite(cert_assess.get("warnings", [])),
        "notes":    _to_sqlite(cert_assess.get("notes",    [])),
    })
    writer.create_index("tls_cert_assessment", "scan_id")
    counts["tls_cert_assessment"] = 1
    if progress_cb: progress_cb("tls_cert_assessment", 1)

    # ── protocols ──────────────────────────────────────────────────────────
    proto_block  = results.get("protocols", {})
    proto_list   = proto_block.get("protocols", [])
    handshake    = proto_block.get("handshake", {})
    alpn         = proto_block.get("alpn", {})
    proto_assess = proto_block.get("assessment", {})

    writer.ensure_table("tls_protocols", {
        "scan_id": "INTEGER", "version": "TEXT", "supported": "INTEGER",
        "rating": "TEXT", "rating_reason": "TEXT",
        "cipher_name": "TEXT", "cipher_bits": "INTEGER",
        "handshake_time_ms": "REAL", "error": "TEXT",
    })
    for p in proto_list:
        cipher = p.get("cipher") or {}
        writer.insert("tls_protocols", {
            "scan_id":          scan_id,
            "version":          p.get("version"),
            "supported":        int(bool(p.get("supported"))),
            "rating":           p.get("rating"),
            "rating_reason":    p.get("rating_reason"),
            "cipher_name":      cipher.get("name"),
            "cipher_bits":      cipher.get("bits"),
            "handshake_time_ms": p.get("handshake_time_ms"),
            "error":            p.get("error"),
        })
    writer.create_index("tls_protocols", "scan_id")
    writer.create_index("tls_protocols", "version")
    counts["tls_protocols"] = len(proto_list)
    if progress_cb: progress_cb("tls_protocols", len(proto_list))

    # handshake
    hs_cipher = handshake.get("cipher") or {}
    writer.ensure_table("tls_handshake", {
        "scan_id": "INTEGER", "negotiated_version": "TEXT",
        "cipher_name": "TEXT", "cipher_bits": "INTEGER",
        "handshake_time_ms": "REAL", "session_ticket": "INTEGER",
    })
    writer.insert("tls_handshake", {
        "scan_id":            scan_id,
        "negotiated_version": handshake.get("negotiated_version"),
        "cipher_name":        hs_cipher.get("name"),
        "cipher_bits":        hs_cipher.get("bits"),
        "handshake_time_ms":  handshake.get("handshake_time_ms"),
        "session_ticket":     int(bool(handshake.get("session_ticket"))),
    })
    writer.create_index("tls_handshake", "scan_id")
    counts["tls_handshake"] = 1

    # ALPN
    writer.ensure_table("tls_alpn", {
        "scan_id": "INTEGER",
        "http2_supported": "INTEGER", "http11_supported": "INTEGER",
        "supported_protocols": "TEXT",
    })
    writer.insert("tls_alpn", {
        "scan_id":             scan_id,
        "http2_supported":     int(bool(alpn.get("http2_supported"))),
        "http11_supported":    int(bool(alpn.get("http11_supported"))),
        "supported_protocols": _to_sqlite(alpn.get("supported_protocols", [])),
    })
    writer.create_index("tls_alpn", "scan_id")
    counts["tls_alpn"] = 1

    # protocol assessment
    writer.ensure_table("tls_proto_assessment", {
        "scan_id": "INTEGER", "grade": "TEXT",
        "issues": "TEXT", "warnings": "TEXT", "notes": "TEXT",
    })
    writer.insert("tls_proto_assessment", {
        "scan_id":  scan_id,
        "grade":    proto_assess.get("grade"),
        "issues":   _to_sqlite(proto_assess.get("issues",   [])),
        "warnings": _to_sqlite(proto_assess.get("warnings", [])),
        "notes":    _to_sqlite(proto_assess.get("notes",    [])),
    })
    writer.create_index("tls_proto_assessment", "scan_id")
    counts["tls_proto_assessment"] = 1
    if progress_cb: progress_cb("tls_proto_assessment", 1)

    # ── ciphers ────────────────────────────────────────────────────────────
    cipher_block   = results.get("ciphers", {})
    cipher_list    = cipher_block.get("ciphers", [])
    cipher_cls     = cipher_block.get("classification", {})
    pfs_analysis   = cipher_block.get("pfs_analysis",   {})
    cipher_assess  = cipher_block.get("assessment",     {})

    # build category map from classification
    _cat_map: dict[str, str] = {}
    for cat_name, cat_items in cipher_cls.items():
        for ci in (cat_items or []):
            if isinstance(ci, dict) and ci.get("name"):
                _cat_map[ci["name"]] = cat_name

    writer.ensure_table("tls_ciphers", {
        "scan_id": "INTEGER", "name": "TEXT", "protocol": "TEXT",
        "bits": "INTEGER", "supported": "INTEGER",
        "pfs": "INTEGER", "strength": "TEXT", "category": "TEXT", "error": "TEXT",
    })
    for c in cipher_list:
        writer.insert("tls_ciphers", {
            "scan_id":   scan_id,
            "name":      c.get("name"),
            "protocol":  c.get("protocol"),
            "bits":      c.get("bits"),
            "supported": int(bool(c.get("supported"))),
            "pfs":       int(bool(c.get("pfs"))),
            "strength":  c.get("strength"),
            "category":  _cat_map.get(c.get("name", ""), "unknown"),
            "error":     c.get("error"),
        })
    writer.create_index("tls_ciphers", "scan_id")
    writer.create_index("tls_ciphers", "supported")
    writer.create_index("tls_ciphers", "category")
    counts["tls_ciphers"] = len(cipher_list)
    if progress_cb: progress_cb("tls_ciphers", len(cipher_list))

    # cipher assessment
    writer.ensure_table("tls_cipher_assessment", {
        "scan_id": "INTEGER", "grade": "TEXT",
        "pfs_count": "INTEGER", "non_pfs_count": "INTEGER",
        "strong_count": "INTEGER", "weak_count": "INTEGER", "insecure_count": "INTEGER",
        "issues": "TEXT", "warnings": "TEXT", "notes": "TEXT",
    })
    writer.insert("tls_cipher_assessment", {
        "scan_id":       scan_id,
        "grade":         cipher_assess.get("grade"),
        "pfs_count":     pfs_analysis.get("pfs_count"),
        "non_pfs_count": pfs_analysis.get("non_pfs_count"),
        "strong_count":  cipher_assess.get("strong_count"),
        "weak_count":    cipher_assess.get("weak_count"),
        "insecure_count": cipher_assess.get("insecure_count"),
        "issues":   _to_sqlite(cipher_assess.get("issues",   [])),
        "warnings": _to_sqlite(cipher_assess.get("warnings", [])),
        "notes":    _to_sqlite(cipher_assess.get("notes",    [])),
    })
    writer.create_index("tls_cipher_assessment", "scan_id")
    counts["tls_cipher_assessment"] = 1
    if progress_cb: progress_cb("tls_cipher_assessment", 1)

    # ── PFS / groups ───────────────────────────────────────────────────────
    # "pfs" block: pfs_support, ecdh_curves, dhe_params, cipher_preference,
    #              session_resumption, assessment
    # "groups" block: groups (list), classification, strength_analysis,
    #                 dhe_params, assessment
    pfs_block      = results.get("pfs",    {})
    groups_block   = results.get("groups", {})
    pfs_groups     = groups_block.get("groups", [])
    pfs_cls        = groups_block.get("classification", {})
    pfs_strength   = groups_block.get("strength_analysis", {})
    pfs_dhe        = groups_block.get("dhe_params", pfs_block.get("dhe_params", {}))
    pfs_assess     = groups_block.get("assessment",  pfs_block.get("assessment", {}))

    # ── pfs_support sub-table ──────────────────────────────────────────────
    pfs_support = pfs_block.get("pfs_support", {})
    writer.ensure_table("tls_pfs_support", {
        "scan_id": "INTEGER",
        "pfs_available": "INTEGER",
        "pfs_supported_kex": "TEXT",
        "non_pfs_supported_kex": "TEXT",
        "all_supported_kex": "TEXT",
        "unsupported_kex": "TEXT",
    })
    writer.insert("tls_pfs_support", {
        "scan_id":              scan_id,
        "pfs_available":        int(bool(pfs_support.get("pfs_available"))),
        "pfs_supported_kex":    _to_sqlite(pfs_support.get("pfs_supported_kex", [])),
        "non_pfs_supported_kex": _to_sqlite(pfs_support.get("non_pfs_supported_kex", [])),
        "all_supported_kex":    _to_sqlite(pfs_support.get("all_supported_kex", [])),
        "unsupported_kex":      _to_sqlite(pfs_support.get("unsupported_kex", [])),
    })
    writer.create_index("tls_pfs_support", "scan_id")
    counts["tls_pfs_support"] = 1

    # ── ecdh_curves sub-table ──────────────────────────────────────────────
    ecdh_curves = pfs_block.get("ecdh_curves", {})
    writer.ensure_table("tls_ecdh_curves", {
        "scan_id": "INTEGER",
        "supported_curves": "TEXT",
        "unsupported_curves": "TEXT",
        "strong_curves": "TEXT",
        "obsolete_curves": "TEXT",
        "weak_curves": "TEXT",
    })
    writer.insert("tls_ecdh_curves", {
        "scan_id":           scan_id,
        "supported_curves":  _to_sqlite(ecdh_curves.get("supported_curves",  [])),
        "unsupported_curves":_to_sqlite(ecdh_curves.get("unsupported_curves",[])),
        "strong_curves":     _to_sqlite(ecdh_curves.get("strong_curves",     [])),
        "obsolete_curves":   _to_sqlite(ecdh_curves.get("obsolete_curves",   [])),
        "weak_curves":       _to_sqlite(ecdh_curves.get("weak_curves",       [])),
    })
    writer.create_index("tls_ecdh_curves", "scan_id")
    counts["tls_ecdh_curves"] = 1

    # ── cipher_preference sub-table ────────────────────────────────────────
    cp = pfs_block.get("cipher_preference", {})
    writer.ensure_table("tls_cipher_preference", {
        "scan_id": "INTEGER",
        "preference_known": "INTEGER",
        "pfs_preferred": "INTEGER",
        "pfs_at_position": "INTEGER",
        "pfs_cipher_count": "INTEGER",
        "non_pfs_cipher_count": "INTEGER",
        "preference": "TEXT",
    })
    writer.insert("tls_cipher_preference", {
        "scan_id":             scan_id,
        "preference_known":    int(bool(cp.get("preference_known"))),
        "pfs_preferred":       int(bool(cp.get("pfs_preferred"))),
        "pfs_at_position":     cp.get("pfs_at_position"),
        "pfs_cipher_count":    cp.get("pfs_cipher_count"),
        "non_pfs_cipher_count": cp.get("non_pfs_cipher_count"),
        "preference":          _to_sqlite(cp.get("preference", [])),
    })
    writer.create_index("tls_cipher_preference", "scan_id")
    counts["tls_cipher_preference"] = 1

    # ── session_resumption sub-table ───────────────────────────────────────
    sr = pfs_block.get("session_resumption", {})
    sr_details = sr.get("details", {})
    sid = sr_details.get("session_id", {})
    ticket = sr_details.get("session_ticket", {})
    writer.ensure_table("tls_session_resumption", {
        "scan_id": "INTEGER",
        "resumption_mode": "TEXT",
        "session_id_supported": "INTEGER",
        "session_ticket_supported": "INTEGER",
        "ticket_lifetime_hours": "REAL",
        "ticket_lifetime_warning": "TEXT",
        "sid_error": "TEXT",
        "sid_present": "INTEGER",
        "ticket_present": "INTEGER",
        "ticket_error": "TEXT",
    })
    writer.insert("tls_session_resumption", {
        "scan_id":                  scan_id,
        "resumption_mode":          sr.get("resumption_mode"),
        "session_id_supported":     int(bool(sr.get("session_id_supported"))),
        "session_ticket_supported": int(bool(sr.get("session_ticket_supported"))),
        "ticket_lifetime_hours":    sr.get("ticket_lifetime_hours"),
        "ticket_lifetime_warning":  sr.get("ticket_lifetime_warning"),
        "sid_error":                sid.get("error"),
        "sid_present":              int(bool(sid.get("session_id_present"))),
        "ticket_present":           int(bool(ticket.get("ticket_present"))),
        "ticket_error":             ticket.get("error"),
    })
    writer.create_index("tls_session_resumption", "scan_id")
    counts["tls_session_resumption"] = 1
    if progress_cb: progress_cb("tls_session_resumption", 1)

    # build PFS category map
    _pfs_cat_map: dict[str, str] = {}
    for cat, items in pfs_cls.items():
        for gi in (items or []):
            if isinstance(gi, dict) and gi.get("name"):
                _pfs_cat_map[gi["name"]] = cat

    writer.ensure_table("tls_pfs_groups", {
        "scan_id": "INTEGER", "name": "TEXT", "type": "TEXT",
        "supported": "INTEGER", "key_bits": "INTEGER",
        "protocol": "TEXT", "cipher": "TEXT",
        "handshake_time_ms": "REAL", "classification": "TEXT", "error": "TEXT",
    })
    for g in pfs_groups:
        writer.insert("tls_pfs_groups", {
            "scan_id":          scan_id,
            "name":             g.get("name"),
            "type":             g.get("type"),
            "supported":        int(bool(g.get("supported"))),
            "key_bits":         g.get("key_bits"),
            "protocol":         g.get("protocol"),
            "cipher":           g.get("cipher"),
            "handshake_time_ms": g.get("handshake_time_ms"),
            "classification":   _pfs_cat_map.get(g.get("name", ""), "unknown"),
            "error":            g.get("error"),
        })
    writer.create_index("tls_pfs_groups", "scan_id")
    writer.create_index("tls_pfs_groups", "type")
    writer.create_index("tls_pfs_groups", "supported")
    counts["tls_pfs_groups"] = len(pfs_groups)
    if progress_cb: progress_cb("tls_pfs_groups", len(pfs_groups))

    # PFS assessment
    writer.ensure_table("tls_pfs_assessment", {
        "scan_id": "INTEGER", "grade": "TEXT", "strength_level": "TEXT",
        "best_ecdhe_group": "TEXT", "best_ecdhe_bits": "INTEGER",
        "best_ffdhe_group": "TEXT", "best_ffdhe_bits": "INTEGER",
        "ecdhe_strong_count": "INTEGER", "ecdhe_obsolete_count": "INTEGER",
        "ecdhe_weak_count": "INTEGER", "ffdhe_strong_count": "INTEGER",
        "custom_dhe_supported": "INTEGER", "dhe_bits": "INTEGER", "dhe_strength": "TEXT",
        "issues": "TEXT", "warnings": "TEXT", "notes": "TEXT",
    })
    writer.insert("tls_pfs_assessment", {
        "scan_id":               scan_id,
        "grade":                 pfs_assess.get("grade"),
        "strength_level":        pfs_strength.get("strength_level"),
        "best_ecdhe_group":      pfs_strength.get("best_ecdhe_group"),
        "best_ecdhe_bits":       pfs_strength.get("best_ecdhe_bits"),
        "best_ffdhe_group":      pfs_strength.get("best_ffdhe_group"),
        "best_ffdhe_bits":       pfs_strength.get("best_ffdhe_bits"),
        "ecdhe_strong_count":    pfs_strength.get("ecdhe_strong_count"),
        "ecdhe_obsolete_count":  pfs_strength.get("ecdhe_obsolete_count"),
        "ecdhe_weak_count":      pfs_strength.get("ecdhe_weak_count"),
        "ffdhe_strong_count":    pfs_strength.get("ffdhe_strong_count"),
        "custom_dhe_supported":  int(bool(pfs_dhe.get("custom_dhe_supported"))),
        "dhe_bits":              pfs_dhe.get("dhe_bits"),
        "dhe_strength":          pfs_dhe.get("strength"),
        "issues":   _to_sqlite(pfs_assess.get("issues",   [])),
        "warnings": _to_sqlite(pfs_assess.get("warnings", [])),
        "notes":    _to_sqlite(pfs_assess.get("notes",    [])),
    })
    writer.create_index("tls_pfs_assessment", "scan_id")
    counts["tls_pfs_assessment"] = 1
    if progress_cb: progress_cb("tls_pfs_assessment", 1)

    # ── headers ────────────────────────────────────────────────────────────
    headers_block = results.get("headers", {})
    hsts_block    = headers_block.get("hsts",      {})
    ect_block     = headers_block.get("expect_ct", {})
    hpkp_block    = headers_block.get("hpkp",      {})
    hdr_score     = headers_block.get("score",     {})
    raw_headers   = headers_block.get("raw_headers", {})

    writer.ensure_table("tls_headers", {
        "scan_id": "INTEGER",
        "raw_headers": "TEXT",
        # HSTS
        "hsts_present": "INTEGER",
        "hsts_max_age": "INTEGER",
        "hsts_include_subdomains": "INTEGER",
        "hsts_preload": "INTEGER",
        "hsts_header": "TEXT",
        "hsts_error": "TEXT",
        # Expect-CT
        "expect_ct_present": "INTEGER",
        "expect_ct_max_age": "INTEGER",
        "expect_ct_enforce": "INTEGER",
        "expect_ct_report_uri": "TEXT",
        "expect_ct_header": "TEXT",
        "expect_ct_error": "TEXT",
        # HPKP
        "hpkp_present": "INTEGER",
        "hpkp_pins": "TEXT",
        "hpkp_max_age": "INTEGER",
        "hpkp_include_subdomains": "INTEGER",
        "hpkp_error": "TEXT",
        # Score
        "score_grade": "TEXT",
        "score_issues": "TEXT",
        "score_warnings": "TEXT",
        "score_notes": "TEXT",
    })
    writer.insert("tls_headers", {
        "scan_id":                 scan_id,
        "raw_headers":             _to_sqlite(raw_headers),
        "hsts_present":            int(bool(hsts_block.get("present"))),
        "hsts_max_age":            hsts_block.get("max_age"),
        "hsts_include_subdomains": int(bool(hsts_block.get("include_subdomains"))),
        "hsts_preload":            int(bool(hsts_block.get("preload"))),
        "hsts_header":             hsts_block.get("header"),
        "hsts_error":              hsts_block.get("error"),
        "expect_ct_present":       int(bool(ect_block.get("present"))),
        "expect_ct_max_age":       ect_block.get("max_age"),
        "expect_ct_enforce":       int(bool(ect_block.get("enforce"))),
        "expect_ct_report_uri":    ect_block.get("report_uri"),
        "expect_ct_header":        ect_block.get("header"),
        "expect_ct_error":         ect_block.get("error"),
        "hpkp_present":            int(bool(hpkp_block.get("present"))),
        "hpkp_pins":               _to_sqlite(hpkp_block.get("pins", [])),
        "hpkp_max_age":            hpkp_block.get("max_age"),
        "hpkp_include_subdomains": int(bool(hpkp_block.get("include_subdomains"))),
        "hpkp_error":              hpkp_block.get("error"),
        "score_grade":    hdr_score.get("grade"),
        "score_issues":   _to_sqlite(hdr_score.get("issues",   [])),
        "score_warnings": _to_sqlite(hdr_score.get("warnings", [])),
        "score_notes":    _to_sqlite(hdr_score.get("notes",    [])),
    })
    writer.create_index("tls_headers", "scan_id")
    counts["tls_headers"] = 1
    if progress_cb: progress_cb("tls_headers", 1)

    # ── fallback ───────────────────────────────────────────────────────────
    fallback_block   = results.get("fallback", {})
    fallback_vulns   = fallback_block.get("vulnerabilities", {})
    fallback_assess  = fallback_block.get("assessment", {})

    writer.ensure_table("tls_fallback", {
        "scan_id": "INTEGER", "highest_version": "TEXT",
        "vuln_name": "TEXT", "vulnerable": "INTEGER",
        "certainty": "TEXT", "detail": "TEXT", "downgrade_attempted": "TEXT",
    })
    for vuln_name, vuln in fallback_vulns.items():
        writer.insert("tls_fallback", {
            "scan_id":              scan_id,
            "highest_version":      fallback_block.get("highest_version"),
            "vuln_name":            vuln_name,
            "vulnerable":           int(bool(vuln.get("vulnerable"))),
            "certainty":            vuln.get("certainty"),
            "detail":               vuln.get("detail"),
            "downgrade_attempted":  vuln.get("downgrade_attempted"),
        })
    writer.create_index("tls_fallback", "scan_id")
    counts["tls_fallback"] = len(fallback_vulns)
    if progress_cb: progress_cb("tls_fallback", len(fallback_vulns))

    # fallback assessment
    writer.ensure_table("tls_fallback_assessment", {
        "scan_id": "INTEGER", "grade": "TEXT",
        "confirmed_count": "INTEGER", "probable_count": "INTEGER",
        "potential_count": "INTEGER", "unknown_count": "INTEGER",
        "safe_count": "INTEGER", "total_checked": "INTEGER",
        "issues": "TEXT", "warnings": "TEXT", "notes": "TEXT",
    })
    writer.insert("tls_fallback_assessment", {
        "scan_id":         scan_id,
        "grade":           fallback_assess.get("grade"),
        "confirmed_count": fallback_assess.get("confirmed_count"),
        "probable_count":  fallback_assess.get("probable_count"),
        "potential_count": fallback_assess.get("potential_count"),
        "unknown_count":   fallback_assess.get("unknown_count"),
        "safe_count":      fallback_assess.get("safe_count"),
        "total_checked":   fallback_assess.get("total_checked"),
        "issues":   _to_sqlite(fallback_assess.get("issues",   [])),
        "warnings": _to_sqlite(fallback_assess.get("warnings", [])),
        "notes":    _to_sqlite(fallback_assess.get("notes",    [])),
    })
    writer.create_index("tls_fallback_assessment", "scan_id")
    counts["tls_fallback_assessment"] = 1
    if progress_cb: progress_cb("tls_fallback_assessment", 1)

    # ── network_checks ─────────────────────────────────────────────────────
    net_block  = results.get("network_checks", {})
    caa_block  = net_block.get("caa", {})
    dane_block = net_block.get("dane", {})
    mta_block  = net_block.get("mta_sts", {})
    net_assess = net_block.get("assessment", {})

    # CAA records
    caa_records = caa_block.get("records", [])
    writer.ensure_table("tls_network_caa", {
        "scan_id": "INTEGER", "tag": "TEXT", "value": "TEXT",
        "flags": "INTEGER", "critical": "INTEGER", "summary": "TEXT",
    })
    for rec in caa_records:
        writer.insert("tls_network_caa", {
            "scan_id":  scan_id,
            "tag":      rec.get("tag"),
            "value":    rec.get("value"),
            "flags":    rec.get("flags"),
            "critical": int(bool(rec.get("critical"))),
            "summary":  caa_block.get("summary"),
        })
    writer.create_index("tls_network_caa", "scan_id")
    counts["tls_network_caa"] = len(caa_records)
    if progress_cb: progress_cb("tls_network_caa", len(caa_records))

    # DANE
    writer.ensure_table("tls_network_dane", {
        "scan_id": "INTEGER", "services": "TEXT", "validation": "TEXT",
    })
    writer.insert("tls_network_dane", {
        "scan_id":    scan_id,
        "services":   _to_sqlite(dane_block.get("services", {})),
        "validation": _to_sqlite(dane_block.get("validation", {})),
    })
    writer.create_index("tls_network_dane", "scan_id")
    counts["tls_network_dane"] = 1

    # MTA-STS
    writer.ensure_table("tls_network_mta_sts", {
        "scan_id": "INTEGER", "dns_record": "TEXT", "policy": "TEXT", "error": "TEXT",
    })
    writer.insert("tls_network_mta_sts", {
        "scan_id":    scan_id,
        "dns_record": _to_sqlite(mta_block.get("dns_record")),
        "policy":     _to_sqlite(mta_block.get("policy")),
        "error":      mta_block.get("error"),
    })
    writer.create_index("tls_network_mta_sts", "scan_id")
    counts["tls_network_mta_sts"] = 1

    # network assessment
    writer.ensure_table("tls_network_assessment", {
        "scan_id": "INTEGER", "grade": "TEXT",
        "issues": "TEXT", "warnings": "TEXT", "notes": "TEXT",
    })
    writer.insert("tls_network_assessment", {
        "scan_id":  scan_id,
        "grade":    net_assess.get("grade"),
        "issues":   _to_sqlite(net_assess.get("issues",   [])),
        "warnings": _to_sqlite(net_assess.get("warnings", [])),
        "notes":    _to_sqlite(net_assess.get("notes",    [])),
    })
    writer.create_index("tls_network_assessment", "scan_id")
    counts["tls_network_assessment"] = 1
    if progress_cb: progress_cb("tls_network_assessment", 1)

    logger.info("%-40s -> scan_id=%d  (%s)  [tls-scanner]", source_file, scan_id, target)
    return counts

# ═══════════════════════════════════════════════════════════════════════════

def _is_social_metadata(data: dict) -> bool:
    return "meta" in data and "results" in data and isinstance(data.get("results"), dict) and (
        "social" in data["results"] or "emails" in data["results"] or
        "html_meta" in data["results"] or "docs_osint" in data["results"]
    )

def _is_whois_checker(data: dict) -> bool:
    return (
        "tool" in data and "queried_at" in data and "domain" in data
        and ("whois" in data or "dns" in data or "ips" in data)
    )

def _is_email_infra(data: dict) -> bool:
    return (
        "generated_at" in data
        and "results" in data
        and isinstance(data.get("results"), dict)
        and any("harvest_recon" in v or "dns_sec" in v for v in data["results"].values() if isinstance(v, dict))
    )

def _write_email_infra(writer: SqliteWriter, data: dict, source_file: str) -> dict[str, int]:
    timestamp = data.get("generated_at", "")
    results = data.get("results", {})
    counts: dict[str, int] = {}
    scan_id = 0
    writer.ensure_table("email_results_payload", {
        "scan_id": "INTEGER",
        "domain": "TEXT",
        "payload": "TEXT",
    })
    for domain, categories in results.items():
        scan_id = _insert_scan(writer, domain, timestamp, source_file)
        writer.insert("email_results_payload", {
            "scan_id": scan_id,
            "domain": domain,
            "payload": _to_sqlite(categories),
        })
        counts["email_results_payload"] = counts.get("email_results_payload", 0) + 1
        for category, content in categories.items():
            if content is None:
                continue
            if not isinstance(content, dict):
                content = {"data": content}
            table_name = f"email_{category}"
            if category == "breaches" and "findings" in content and isinstance(content["findings"], list):
                findings = content["findings"]
                if findings:
                    col_types = {"scan_id": "INTEGER"}
                    for finding in findings:
                        for k in finding.keys():
                            if k not in col_types:
                                col_types[k] = "TEXT"
                    writer.ensure_table(table_name, col_types)
                    for finding in findings:
                        row_data = {"scan_id": scan_id}
                        for k, v in finding.items():
                            row_data[k] = _to_sqlite(v)
                        writer.insert(table_name, row_data)
                        counts[table_name] = counts.get(table_name, 0) + 1
                writer.create_index(table_name, "scan_id")
                continue
            col_types = {"scan_id": "INTEGER"}
            row_data = {"scan_id": scan_id}
            for k, v in content.items():
                clean_k = k.replace("-", "_")
                col_types[clean_k] = "INTEGER" if isinstance(v, bool) else "TEXT"
                row_data[clean_k] = _to_sqlite(v)
            writer.ensure_table(table_name, col_types)
            writer.insert(table_name, row_data)
            writer.create_index(table_name, "scan_id")
            counts[table_name] = counts.get(table_name, 0) + 1
    writer.create_index("email_results_payload", "scan_id")
    writer.create_index("email_results_payload", "domain")
    logger.info("%-40s -> scan_id=%d  [email-infra]", source_file, scan_id)
    return counts

def _ensure_whois_tables(writer: "SqliteWriter") -> None:
    writer.ensure_table("whois_scans", {
        "domain":      "TEXT",
        "tld":         "TEXT",
        "queried_at":  "TEXT",
        "tool":        "TEXT",
        "version":     "TEXT",
        "source_file": "TEXT",
    })
    writer.ensure_table("whois_results_payload", {
        "scan_id": "INTEGER",
        "payload": "TEXT",
    })
    writer.ensure_table("whois_info", {
        "scan_id":           "INTEGER",
        "created":           "TEXT",
        "updated":           "TEXT",
        "expires":           "TEXT",
        "days_until_expiry": "INTEGER",
        "expiry_warning":    "INTEGER",
        "status":            "TEXT",
        "registrar":         "TEXT",
        "registrar_iana_id": "TEXT",
        "name_servers":      "TEXT",
        "dnssec":            "TEXT",
        "sources":           "TEXT",
        "privacy_enabled":   "INTEGER",
        "privacy_note":      "TEXT",
        "privacy_indicators":"TEXT",
        "raw":               "TEXT",
    })
    writer.ensure_table("whois_contacts", {
        "scan_id":      "INTEGER",
        "role":         "TEXT",
        "name":         "TEXT",
        "organization": "TEXT",
        "address":      "TEXT",
        "country":      "TEXT",
        "phone":        "TEXT",
        "email":        "TEXT",
    })
    writer.ensure_table("whois_dns", {
        "scan_id":  "INTEGER",
        "a":        "TEXT",
        "aaaa":     "TEXT",
        "ns":       "TEXT",
        "mx":       "TEXT",
        "cname":    "TEXT",
        "txt":      "TEXT",
        "resolver": "TEXT",
    })
    writer.ensure_table("whois_ips", {
        "scan_id":      "INTEGER",
        "ip":           "TEXT",
        "asn":          "INTEGER",
        "as_name":      "TEXT",
        "org":          "TEXT",
        "isp":          "TEXT",
        "country":      "TEXT",
        "country_code": "TEXT",
        "city":         "TEXT",
        "region":       "TEXT",
        "lat":          "REAL",
        "lon":          "REAL",
        "timezone":     "TEXT",
        "hosting":      "INTEGER",
        "proxy_or_vpn": "INTEGER",
        "usage_type":   "TEXT",
        "ptr":          "TEXT",
        "cidr":         "TEXT",
        "source":       "TEXT",
    })
    writer.ensure_table("whois_cdn", {
        "scan_id":    "INTEGER",
        "behind_cdn": "INTEGER",
        "vendors":    "TEXT",
        "note":       "TEXT",
        "evidence":   "TEXT",
    })
    writer.ensure_table("whois_http", {
        "scan_id":   "INTEGER",
        "url":       "TEXT",
        "status":    "INTEGER",
        "final_url": "TEXT",
        "headers":   "TEXT",
    })
    writer.ensure_table("whois_errors", {
        "scan_id": "INTEGER",
        "error":   "TEXT",
    })
    writer.ensure_table("whois_cdn_advanced", {
        "scan_id":      "INTEGER",
        "behind_cdn":   "INTEGER",
        "vendors":      "TEXT",
        "waf_detected": "TEXT",
        "anycast":      "INTEGER",
        "evidence":     "TEXT",
        "note":         "TEXT",
    })
    writer.ensure_table("whois_blacklist", {
        "scan_id":     "INTEGER",
        "domain":      "TEXT",
        "score":       "INTEGER",
        "risk":        "TEXT",
        "ips_checked": "TEXT",
        "checked":     "TEXT",
    })
    writer.ensure_table("whois_blacklist_hits", {
        "scan_id":   "INTEGER",
        "list_name": "TEXT",
        "query":     "TEXT",
        "response":  "TEXT",
        "type":      "TEXT",
    })
    writer.ensure_table("whois_cross_search", {
        "scan_id":          "INTEGER",
        "domain":           "TEXT",
        "registrant_email": "TEXT",
        "registrant_org":   "TEXT",
        "nameservers":      "TEXT",
        "ips_pivoted":      "TEXT",
        "pivots_used":      "TEXT",
        "related_count":    "INTEGER",
    })
    writer.ensure_table("whois_related_domains", {
        "scan_id": "INTEGER",
        "domain":  "TEXT",
        "pivot":   "TEXT",
        "value":   "TEXT",
        "source":  "TEXT",
    })
    writer.ensure_table("whois_historical", {
        "scan_id":            "INTEGER",
        "domain":             "TEXT",
        "archive_first_seen": "TEXT",
        "archive_last_seen":  "TEXT",
        "archive_source":     "TEXT",
    })
    writer.ensure_table("whois_rdap_events", {
        "scan_id": "INTEGER",
        "action":  "TEXT",
        "date":    "TEXT",
    })
    writer.ensure_table("whois_snapshots", {
        "scan_id":      "INTEGER",
        "date":         "TEXT",
        "registrar":    "TEXT",
        "created":      "TEXT",
        "expires":      "TEXT",
        "status":       "TEXT",
        "name_servers": "TEXT",
        "source":       "TEXT",
    })

def _j(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, (list, dict)):
        return json.dumps(val, ensure_ascii=False) if val else None
    return str(val)

def _write_whois_cdn_advanced(writer: "SqliteWriter", scan_id: int, data: dict) -> int:
    writer.insert("whois_cdn_advanced", {
        "scan_id":      scan_id,
        "behind_cdn":   int(bool(data.get("behind_cdn"))),
        "vendors":      _j(data.get("vendors")),
        "waf_detected": _j(data.get("waf_detected")),
        "anycast":      int(bool(data.get("anycast"))),
        "evidence":     _j(data.get("evidence")),
        "note":         data.get("note"),
    })
    writer.create_index("whois_cdn_advanced", "scan_id")
    return 1

def _write_whois_blacklist(writer: "SqliteWriter", scan_id: int, data: dict) -> int:
    writer.insert("whois_blacklist", {
        "scan_id":     scan_id,
        "domain":      data.get("domain"),
        "score":       data.get("score", 0),
        "risk":        data.get("risk", "clean"),
        "ips_checked": _j(data.get("ips_checked")),
        "checked":     _j(data.get("checked")),
    })
    writer.create_index("whois_blacklist", "scan_id")
    n_hits = 0
    for hit in (data.get("hits") or []):
        writer.insert("whois_blacklist_hits", {
            "scan_id":   scan_id,
            "list_name": hit.get("list") or hit.get("list_name"),
            "query":     hit.get("query"),
            "response":  hit.get("response"),
            "type":      hit.get("type"),
        })
        n_hits += 1
    writer.create_index("whois_blacklist_hits", "scan_id")
    return 1 + n_hits

def _write_whois_cross_search(writer: "SqliteWriter", scan_id: int, data: dict) -> int:
    related = data.get("related_domains") or []
    writer.insert("whois_cross_search", {
        "scan_id":          scan_id,
        "domain":           data.get("domain"),
        "registrant_email": data.get("registrant_email"),
        "registrant_org":   data.get("registrant_org"),
        "nameservers":      _j(data.get("nameservers")),
        "ips_pivoted":      _j(data.get("ips_pivoted")),
        "pivots_used":      _j(data.get("pivots_used")),
        "related_count":    data.get("related_count", len(related)),
    })
    writer.create_index("whois_cross_search", "scan_id")
    n_rel = 0
    for rd in related:
        writer.insert("whois_related_domains", {
            "scan_id": scan_id,
            "domain":  rd.get("domain"),
            "pivot":   rd.get("pivot"),
            "value":   rd.get("value"),
            "source":  rd.get("source"),
        })
        n_rel += 1
    writer.create_index("whois_related_domains", "scan_id")
    return 1 + n_rel

def _write_whois_historical(writer: "SqliteWriter", scan_id: int, data: dict) -> int:
    archive = data.get("archive") or {}
    writer.insert("whois_historical", {
        "scan_id":            scan_id,
        "domain":             data.get("domain"),
        "archive_first_seen": archive.get("first_seen"),
        "archive_last_seen":  archive.get("last_seen"),
        "archive_source":     archive.get("source"),
    })
    writer.create_index("whois_historical", "scan_id")
    n_events = 0
    for ev in (data.get("rdap_events") or []):
        writer.insert("whois_rdap_events", {
            "scan_id": scan_id,
            "action":  ev.get("action"),
            "date":    ev.get("date"),
        })
        n_events += 1
    writer.create_index("whois_rdap_events", "scan_id")
    n_snaps = 0
    for snap in (data.get("snapshots") or []):
        writer.insert("whois_snapshots", {
            "scan_id":      scan_id,
            "date":         snap.get("date"),
            "registrar":    snap.get("registrar"),
            "created":      snap.get("created"),
            "expires":      snap.get("expires"),
            "status":       _j(snap.get("status")),
            "name_servers": _j(snap.get("name_servers")),
            "source":       snap.get("source"),
        })
        n_snaps += 1
    writer.create_index("whois_snapshots", "scan_id")
    return 1 + n_events + n_snaps

def _write_whois_checker(writer: "SqliteWriter", data: dict, source_file: str) -> dict[str, int]:
    _ensure_whois_tables(writer)
    scan_row = {
        "domain":      data.get("domain") or "",
        "tld":         data.get("tld") or "",
        "queried_at":  data.get("queried_at") or "",
        "tool":        data.get("tool") or "whois-checker",
        "version":     data.get("version") or "",
        "source_file": source_file,
    }
    scan_id = writer.insert("whois_scans", scan_row)
    counts: dict[str, int] = {"whois_scans": 1}
    writer.insert("whois_results_payload", {
        "scan_id": scan_id,
        "payload": _to_sqlite(data),
    })
    writer.create_index("whois_results_payload", "scan_id")
    counts["whois_results_payload"] = 1
    w = data.get("whois") or {}
    if w:
        priv = w.get("privacy") or {}
        writer.insert("whois_info", {
            "scan_id":           scan_id,
            "created":           w.get("created"),
            "updated":           w.get("updated"),
            "expires":           w.get("expires"),
            "days_until_expiry": w.get("days_until_expiry"),
            "expiry_warning":    int(bool(w.get("expiry_warning"))),
            "status":            _j(w.get("status")),
            "registrar":         w.get("registrar"),
            "registrar_iana_id": w.get("registrar_iana_id"),
            "name_servers":      _j(w.get("name_servers")),
            "dnssec":            w.get("dnssec"),
            "sources":           _j(w.get("sources")),
            "privacy_enabled":   int(bool(priv.get("enabled"))),
            "privacy_note":      priv.get("note"),
            "privacy_indicators":_j(priv.get("indicators")),
            "raw":               w.get("raw") or "",
        })
        counts["whois_info"] = 1
        contacts = w.get("contacts") or {}
        n_contacts = 0
        for role, c in contacts.items():
            if not c:
                continue
            writer.insert("whois_contacts", {
                "scan_id":      scan_id,
                "role":         role,
                "name":         c.get("name"),
                "organization": c.get("organization"),
                "address":      c.get("address"),
                "country":      c.get("country"),
                "phone":        c.get("phone"),
                "email":        c.get("email"),
            })
            n_contacts += 1
        if n_contacts:
            counts["whois_contacts"] = n_contacts
    d = data.get("dns") or {}
    if d:
        writer.insert("whois_dns", {
            "scan_id":  scan_id,
            "a":        _j(d.get("a")),
            "aaaa":     _j(d.get("aaaa")),
            "ns":       _j(d.get("ns")),
            "mx":       _j(d.get("mx")),
            "cname":    _j(d.get("cname")),
            "txt":      _j(d.get("txt")),
            "resolver": d.get("resolver"),
        })
        counts["whois_dns"] = 1
    ips = data.get("ips") or []
    n_ips = 0
    for ip in ips:
        writer.insert("whois_ips", {
            "scan_id":      scan_id,
            "ip":           ip.get("ip"),
            "asn":          ip.get("asn"),
            "as_name":      ip.get("as_name"),
            "org":          ip.get("org"),
            "isp":          ip.get("isp"),
            "country":      ip.get("country"),
            "country_code": ip.get("country_code"),
            "city":         ip.get("city"),
            "region":       ip.get("region"),
            "lat":          ip.get("lat"),
            "lon":          ip.get("lon"),
            "timezone":     ip.get("timezone"),
            "hosting":      int(bool(ip.get("hosting"))),
            "proxy_or_vpn": int(bool(ip.get("proxy_or_vpn"))),
            "usage_type":   ip.get("usage_type"),
            "ptr":          ip.get("ptr"),
            "cidr":         ip.get("cidr"),
            "source":       _j(ip.get("source")),
        })
        n_ips += 1
    if n_ips:
        counts["whois_ips"] = n_ips
    cdn = data.get("cdn") or {}
    if cdn:
        writer.insert("whois_cdn", {
            "scan_id":    scan_id,
            "behind_cdn": int(bool(cdn.get("behind_cdn"))),
            "vendors":    _j(cdn.get("vendors")),
            "note":       cdn.get("note"),
            "evidence":   _j(cdn.get("evidence")),
        })
        counts["whois_cdn"] = 1
    cdn_adv = data.get("cdn_advanced") or {}
    if cdn_adv:
        n = _write_whois_cdn_advanced(writer, scan_id, cdn_adv)
        counts["whois_cdn_advanced"] = n
    blacklist = data.get("blacklist") or {}
    if blacklist:
        n = _write_whois_blacklist(writer, scan_id, blacklist)
        counts["whois_blacklist"] = n
    cross_search = data.get("cross_search") or {}
    if cross_search:
        n = _write_whois_cross_search(writer, scan_id, cross_search)
        counts["whois_cross_search"] = n
    historical = data.get("historical") or {}
    if historical:
        n = _write_whois_historical(writer, scan_id, historical)
        counts["whois_historical"] = n
    http_probes = data.get("http") or []
    n_http = 0
    for p in http_probes:
        writer.insert("whois_http", {
            "scan_id":   scan_id,
            "url":       p.get("url"),
            "status":    p.get("status"),
            "final_url": p.get("final_url"),
            "headers":   _j(p.get("headers")),
        })
        n_http += 1
    if n_http:
        counts["whois_http"] = n_http
    errors = data.get("errors") or []
    n_err = 0
    for e in errors:
        writer.insert("whois_errors", {"scan_id": scan_id, "error": str(e)})
        n_err += 1
    if n_err:
        counts["whois_errors"] = n_err
    for tbl in ("whois_info", "whois_contacts", "whois_dns", "whois_ips",
                "whois_cdn", "whois_cdn_advanced", "whois_http", "whois_errors",
                "whois_blacklist", "whois_blacklist_hits",
                "whois_cross_search", "whois_related_domains",
                "whois_historical", "whois_rdap_events", "whois_snapshots"):
        writer.create_index(tbl, "scan_id")
    logger.info(
        "whois-checker -> scan_id=%d  domain=%s  tables=%s",
        scan_id, data.get("domain"), list(counts.keys()),
    )
    return counts

_MODULE_WRITERS = {
    "records":        _write_records,
    "axfr":           _write_axfr,
    "reverse":        _write_reverse,
    "dangling":       _write_dangling,
    "mail":           _write_mail,
    "doh":            _write_doh,
    "dot":            _write_dot,
    "dnssec":         _write_dnssec,
    "open_resolver":  _write_open_resolver,
    "ttl_anomalies":  _write_ttl_anomalies,
    "spf_flattening": _write_spf_flatten,
    "source_ip":      _write_source_ip,
}

def _write_tech_technologies(writer: SqliteWriter, scan_id: int, data: list) -> int:
    spec = TECH_SPECS["tech_technologies"]
    col_types = {
        "scan_id":      "INTEGER",
        "name":         "TEXT",
        "version":      "TEXT",
        "category":     "TEXT",
        "confidence":   "TEXT",
        "detected_via": "TEXT",
        "raw_value":    "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for item in data:
        raw_cat = item.get("category") or item.get("categories")
        if isinstance(raw_cat, list):
            raw_cat = raw_cat[0] if raw_cat else None
        writer.insert(spec.table_name, {
            "scan_id":      scan_id,
            "name":         item.get("name"),
            "version":      item.get("version"),
            "category":     raw_cat,
            "confidence":   str(item.get("confidence", "")),
            "detected_via": item.get("detected_via"),
            "raw_value":    item.get("raw_value"),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_tech_favicon(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec = TECH_SPECS["tech_favicon"]
    col_types = {c: "TEXT" for c in spec.scalar_columns}
    col_types["scan_id"]       = "INTEGER"
    col_types["favicon_found"] = "INTEGER"
    col_types["size_bytes"]    = "INTEGER"
    writer.ensure_table(spec.table_name, col_types)
    hashes    = data.get("hashes", {})
    queries   = data.get("search_queries", {})
    tech      = data.get("technology") or {}
    file_meta = data.get("file_metadata", {})
    writer.insert(spec.table_name, {
        "scan_id":             scan_id,
        "favicon_found":       int(bool(data.get("favicon_found"))),
        "favicon_url":         data.get("favicon_url"),
        "size_bytes":          data.get("size_bytes"),
        "mmh3":                str(hashes.get("mmh3", "")),
        "md5":                 hashes.get("md5"),
        "sha1":                hashes.get("sha1"),
        "sha256":              hashes.get("sha256"),
        "technology_name":     tech.get("name") if tech else None,
        "technology_category": tech.get("category") if tech else None,
        "version_in_path":     data.get("version_in_path"),
        "file_format":         file_meta.get("format"),
        "file_metadata":       _to_sqlite(file_meta),
        "shodan_query":        queries.get("shodan"),
        "censys_query":        queries.get("censys"),
        "fofa_query":          queries.get("fofa"),
        "zoomeye_query":       queries.get("zoomeye"),
        "quake_query":         queries.get("quake"),
        "hunter_query":        queries.get("hunter"),
    })
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return 1

def _write_tech_vulnerabilities(writer: SqliteWriter, scan_id: int, data: list) -> int:
    spec = TECH_SPECS["tech_vulnerabilities"]
    col_types = {
        "scan_id":        "INTEGER",
        "library":        "TEXT",
        "version":        "TEXT",
        "script_url":     "TEXT",
        "severity":       "TEXT",
        "summary":        "TEXT",
        "cve":            "TEXT",
        "github_id":      "TEXT",
        "affected_range": "TEXT",
        "info_url":       "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for finding in data:
        lib     = finding.get("library")
        version = finding.get("version")
        url     = finding.get("script_url")
        for vuln in finding.get("vulnerabilities", []):
            ids      = vuln.get("identifiers", {})
            cve_list = ids.get("CVE", [])
            writer.insert(spec.table_name, {
                "scan_id":        scan_id,
                "library":        lib,
                "version":        version,
                "script_url":     url,
                "severity":       vuln.get("severity"),
                "summary":        ids.get("summary"),
                "cve":            _to_sqlite(cve_list),
                "github_id":      ids.get("githubID"),
                "affected_range": vuln.get("affected_range"),
                "info_url":       _to_sqlite(vuln.get("info", [])),
            })
            count += 1
        if not finding.get("vulnerabilities"):
            writer.insert(spec.table_name, {
                "scan_id":        scan_id,
                "library":        lib,
                "version":        version,
                "script_url":     url,
                "severity":       None,
                "summary":        None,
                "cve":            None,
                "github_id":      None,
                "affected_range": None,
                "info_url":       None,
            })
            count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_tech_waf(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec = TECH_SPECS["tech_waf"]
    col_types = {
        "scan_id":          "INTEGER",
        "waf_detected":     "INTEGER",
        "waf_names":        "TEXT",
        "generic_detected": "INTEGER",
        "generic_reason":   "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    writer.insert(spec.table_name, {
        "scan_id":          scan_id,
        "waf_detected":     int(bool(data.get("waf_detected"))),
        "waf_names":        _to_sqlite(data.get("waf_names", [])),
        "generic_detected": int(bool(data.get("generic_detected"))),
        "generic_reason":   data.get("generic_reason"),
    })
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return 1

def _write_tech_headers(writer: SqliteWriter, scan_id: int, data: list) -> int:
    spec = TECH_SPECS["tech_headers"]
    col_types = {
        "scan_id":      "INTEGER",
        "name":         "TEXT",
        "category":     "TEXT",
        "detected_via": "TEXT",
        "raw_value":    "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    count = 0
    for item in data:
        writer.insert(spec.table_name, {
            "scan_id":      scan_id,
            "name":         item.get("name"),
            "category":     item.get("category"),
            "detected_via": item.get("detected_via"),
            "raw_value":    item.get("raw_value"),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

def _write_tech_cms(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec = TECH_SPECS["tech_cms"]
    col_types = {
        "scan_id":          "INTEGER",
        "cms_detected":     "INTEGER",
        "cms_id":           "TEXT",
        "cms_name":         "TEXT",
        "cms_url":          "TEXT",
        "cms_version":      "TEXT",
        "detection_method": "TEXT",
    }
    writer.ensure_table(spec.table_name, col_types)
    writer.insert(spec.table_name, {
        "scan_id":          scan_id,
        "cms_detected":     int(bool(data.get("cms_detected"))),
        "cms_id":           data.get("cms_id"),
        "cms_name":         data.get("cms_name"),
        "cms_url":          data.get("cms_url"),
        "cms_version":      data.get("cms_version"),
        "detection_method": data.get("detection_method"),
    })
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return 1

def _write_tech_retire_js(writer: SqliteWriter, scan_id: int, data: dict) -> int:
    spec = TECH_SPECS["tech_retire_js"]
    col_types = {
        "scan_id":             "INTEGER",
        "scripts_checked":     "INTEGER",
        "library":             "TEXT",
        "version":             "TEXT",
        "script_url":          "TEXT",
        "has_vulnerabilities": "INTEGER",
    }
    writer.ensure_table(spec.table_name, col_types)
    scripts_checked = data.get("scripts_checked", 0)
    count = 0
    for finding in data.get("findings", []):
        writer.insert(spec.table_name, {
            "scan_id":             scan_id,
            "scripts_checked":     scripts_checked,
            "library":             finding.get("library"),
            "version":             finding.get("version"),
            "script_url":          finding.get("script_url"),
            "has_vulnerabilities": int(bool(finding.get("vulnerabilities"))),
        })
        count += 1
    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)
    return count

_TECH_MODULE_WRITERS = {
    "WebAppAnalyzer": lambda w, s, d: _write_tech_technologies(w, s, d.get("technologies", [])),
    "WappalyzerNext": lambda w, s, d: _write_tech_technologies(w, s, d.get("technologies", [])),
    "FaviconRecon":   _write_tech_favicon,
    "RetireJS":       _write_tech_retire_js,
    "WafW00f":        _write_tech_waf,
    "HeaderScanner":  lambda w, s, d: _write_tech_headers(w, s, d.get("technologies", [])),
    "CMSeeK":         _write_tech_cms,
}

HEADERS_GRADE_ORDER = ["A+", "A", "B", "C", "D", "E", "F"]

def _headers_grade_rank(grade: str) -> int:
    return HEADERS_GRADE_ORDER.index(grade) if grade in HEADERS_GRADE_ORDER else len(HEADERS_GRADE_ORDER)

def _headers_entries(data: dict) -> list[dict]:
    entries = data.get("entries")
    if isinstance(entries, list):
        return [e for e in entries if isinstance(e, dict)]
    if isinstance(data.get("modules"), dict):
        score = data.get("score")
        return [{
            "id":          "1",
            "source":      data.get("source"),
            "method":      data.get("method"),
            "url":         data.get("url"),
            "status_code": data.get("status_code"),
            "modules":     data["modules"],
            "score":       score if isinstance(score, dict) else {},
        }]
    return []

def _is_headers_analyzer(data: dict) -> bool:
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("entries"), list) and "domain" in data:
        return all(
            isinstance(e, dict) and isinstance(e.get("modules"), dict)
            for e in data["entries"][:5]
        )
    return (
        isinstance(data.get("modules"), dict)
        and "url" in data
        and "status_code" in data
    )

def _headers_build_summary(entries: list[dict]) -> list[dict]:
    rows: dict[tuple, dict] = {}
    for entry in entries:
        entry_id = str(entry.get("id", ""))
        for module_name, module_data in (entry.get("modules") or {}).items():
            if not isinstance(module_data, dict):
                continue
            for finding in (module_data.get("findings") or []):
                if finding.get("severity") == "OK":
                    continue
                key = (module_name, finding.get("severity"), finding.get("header"), finding.get("detail"))
                row = rows.setdefault(key, {
                    "module":    module_name,
                    "severity":  finding.get("severity"),
                    "header":    finding.get("header"),
                    "detail":    finding.get("detail"),
                    "count":     0,
                    "entry_ids": [],
                })
                row["count"] += 1
                row["entry_ids"].append(entry_id)
    return list(rows.values())

def _headers_overall(entries: list[dict]) -> tuple[str | None, float | None]:
    scores: list[float] = []
    tally: dict[str, int] = {}
    for entry in entries:
        score = entry.get("score") or {}
        if isinstance(score.get("score"), (int, float)):
            scores.append(float(score["score"]))
        if score.get("grade"):
            grade = str(score["grade"])
            tally[grade] = tally.get(grade, 0) + 1
    average = round(sum(scores) / len(scores), 1) if scores else None
    grade = max(tally, key=lambda g: (tally[g], _headers_grade_rank(g))) if tally else None
    return grade, average

def _ensure_headers_tables(writer: "SqliteWriter") -> None:
    writer.ensure_table("headers_scans", {
        "domain":             "TEXT",
        "url":                "TEXT",
        "final_url":          "TEXT",
        "status_code":        "INTEGER",
        "timestamp":          "TEXT",
        "elapsed_ms":         "REAL",
        "records_read":       "INTEGER",
        "responses_analyzed": "INTEGER",
        "intercept_files":    "TEXT",
        "grade":              "TEXT",
        "score":              "REAL",
        "source_file":        "TEXT",
    })
    writer.ensure_table("headers_results_payload", {
        "scan_id": "INTEGER",
        "payload": "TEXT",
    })
    writer.ensure_table("headers_entries", {
        "scan_id":         "INTEGER",
        "entry_id":        "TEXT",
        "source":          "TEXT",
        "method":          "TEXT",
        "url":             "TEXT",
        "status_code":     "INTEGER",
        "grade":           "TEXT",
        "score":           "REAL",
        "recommendations": "TEXT",
    })
    writer.ensure_table("headers_findings", {
        "scan_id":  "INTEGER",
        "entry_id": "TEXT",
        "module":   "TEXT",
        "severity": "TEXT",
        "header":   "TEXT",
        "detail":   "TEXT",
    })
    writer.ensure_table("headers_metadata", {
        "scan_id":  "INTEGER",
        "entry_id": "TEXT",
        "module":   "TEXT",
        "key":      "TEXT",
        "value":    "TEXT",
    })
    writer.ensure_table("headers_summary", {
        "scan_id":   "INTEGER",
        "module":    "TEXT",
        "severity":  "TEXT",
        "header":    "TEXT",
        "detail":    "TEXT",
        "count":     "INTEGER",
        "entry_ids": "TEXT",
    })
    writer.ensure_table("headers_websocket", {
        "scan_id":        "INTEGER",
        "handshakes":     "INTEGER",
        "accepted":       "INTEGER",
        "rejected":       "INTEGER",
        "other_upgrades": "INTEGER",
        "endpoints":      "TEXT",
        "notes":          "TEXT",
    })
    writer.ensure_table("headers_cookies", {
        "scan_id":        "INTEGER",
        "name":           "TEXT",
        "host":           "TEXT",
        "fingerprint":    "TEXT",
        "category":       "TEXT",
        "sensitive":      "INTEGER",
        "value_type":     "TEXT",
        "layers":         "TEXT",
        "decoded":        "TEXT",
        "is_jwt":         "INTEGER",
        "jwt_alg":        "TEXT",
        "jwt_exp":        "REAL",
        "jwt_issuer":     "TEXT",
        "jwt_audience":   "TEXT",
        "secure":         "INTEGER",
        "httponly":       "INTEGER",
        "samesite":       "TEXT",
        "partitioned":    "INTEGER",
        "domain":         "TEXT",
        "path":           "TEXT",
        "max_age":        "TEXT",
        "expires":        "TEXT",
        "lifetime_seconds": "REAL",
        "entropy":        "TEXT",
        "hash_candidates": "TEXT",
        "provider_tokens": "TEXT",
        "issued_total":   "INTEGER",
        "sent_total":     "INTEGER",
        "issued_in":      "TEXT",
        "sent_in":        "TEXT",
        "distinct_values": "INTEGER",
        "values":         "TEXT",
        "attribute_sets": "TEXT",
    })
    writer.ensure_table("headers_cookie_findings", {
        "scan_id":  "INTEGER",
        "cookie":   "TEXT",
        "host":     "TEXT",
        "severity": "TEXT",
        "header":   "TEXT",
        "detail":   "TEXT",
        "count":    "INTEGER",
    })

def _headers_jwt_info(cookie: dict) -> dict[str, Any]:
    info: dict[str, Any] = {"is_jwt": 0, "alg": None, "exp": None, "iss": None, "aud": None}
    if cookie.get("value_type") != "jwt":
        return info
    info["is_jwt"] = 1
    decoded = cookie.get("decoded")
    if not isinstance(decoded, str):
        return info
    try:
        obj = json.loads(decoded)
        header = obj.get("header") if isinstance(obj.get("header"), dict) else {}
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    except (ValueError, AttributeError):
        header, payload = {}, {}
        alg = re.search(r'"alg"\s*:\s*"([^"]+)"', decoded)
        exp = re.search(r'"exp"\s*:\s*(\d+)', decoded)
        if alg:
            header["alg"] = alg.group(1)
        if exp:
            payload["exp"] = int(exp.group(1))
    info["alg"] = str(header["alg"]) if header.get("alg") is not None else None
    if isinstance(payload.get("exp"), (int, float)) and not isinstance(payload.get("exp"), bool):
        info["exp"] = float(payload["exp"])
    if payload.get("iss") is not None:
        info["iss"] = str(payload["iss"])
    aud = payload.get("aud")
    if aud is not None:
        info["aud"] = ", ".join(str(a) for a in aud) if isinstance(aud, list) else str(aud)
    return info

def _write_headers_cookies(writer: "SqliteWriter", scan_id: int, report: dict) -> dict[str, int]:
    counts = {"headers_cookies": 0, "headers_cookie_findings": 0}
    for cookie in report.get("cookies") or []:
        if not isinstance(cookie, dict) or not cookie.get("name"):
            continue
        attribute_sets = cookie.get("attribute_sets") or []
        attrs = attribute_sets[0] if attribute_sets and isinstance(attribute_sets[0], dict) else {}
        jwt = _headers_jwt_info(cookie)
        writer.insert("headers_cookies", {
            "scan_id":          scan_id,
            "name":             cookie.get("name"),
            "host":             cookie.get("host"),
            "fingerprint":      cookie.get("fingerprint"),
            "category":         cookie.get("category"),
            "sensitive":        _to_sqlite(bool(cookie.get("sensitive"))),
            "value_type":       cookie.get("value_type"),
            "layers":           _to_sqlite(cookie.get("layers") or []),
            "decoded":          cookie.get("decoded"),
            "is_jwt":           jwt["is_jwt"],
            "jwt_alg":          jwt["alg"],
            "jwt_exp":          jwt["exp"],
            "jwt_issuer":       jwt["iss"],
            "jwt_audience":     jwt["aud"],
            "secure":           _to_sqlite(attrs.get("secure")),
            "httponly":         _to_sqlite(attrs.get("httponly")),
            "samesite":         attrs.get("samesite"),
            "partitioned":      _to_sqlite(attrs.get("partitioned")),
            "domain":           attrs.get("domain"),
            "path":             attrs.get("path"),
            "max_age":          attrs.get("max_age"),
            "expires":          attrs.get("expires"),
            "lifetime_seconds": attrs.get("lifetime_seconds"),
            "entropy":          _to_sqlite(cookie.get("entropy")),
            "hash_candidates":  _to_sqlite(cookie.get("hash_candidates") or []),
            "provider_tokens":  _to_sqlite(cookie.get("provider_tokens") or []),
            "issued_total":     cookie.get("issued_total", 0),
            "sent_total":       cookie.get("sent_total", 0),
            "issued_in":        _to_sqlite(cookie.get("issued_in") or []),
            "sent_in":          _to_sqlite(cookie.get("sent_in") or []),
            "distinct_values":  cookie.get("distinct_values", 0),
            "values":           _to_sqlite(cookie.get("values") or []),
            "attribute_sets":   _to_sqlite(attribute_sets),
        })
        counts["headers_cookies"] += 1
        for finding in cookie.get("findings") or []:
            writer.insert("headers_cookie_findings", {
                "scan_id":  scan_id,
                "cookie":   cookie.get("name"),
                "host":     cookie.get("host"),
                "severity": finding.get("severity"),
                "header":   finding.get("header"),
                "detail":   finding.get("detail"),
                "count":    finding.get("count", 1),
            })
            counts["headers_cookie_findings"] += 1
    for finding in report.get("general_findings") or []:
        writer.insert("headers_cookie_findings", {
            "scan_id":  scan_id,
            "cookie":   None,
            "host":     None,
            "severity": finding.get("severity"),
            "header":   finding.get("header"),
            "detail":   finding.get("detail"),
            "count":    finding.get("count", 1),
        })
        counts["headers_cookie_findings"] += 1
    return counts

def _write_headers_analyzer(writer: "SqliteWriter", data: dict, source_file: str) -> dict[str, int]:
    _ensure_headers_tables(writer)
    entries = _headers_entries(data)
    first_url = (entries[0].get("url") if entries else None) or data.get("url") or ""
    domain = data.get("domain") or urlsplit(first_url).hostname or ""
    summary = data.get("summary") if isinstance(data.get("summary"), list) else _headers_build_summary(entries)
    websocket = data.get("websocket") if isinstance(data.get("websocket"), dict) else {}
    grade, average = _headers_overall(entries)
    payload = {
        "domain":             domain,
        "intercept_files":    data.get("intercept_files") or [],
        "timestamp":          data.get("timestamp"),
        "elapsed_ms":         data.get("elapsed_ms"),
        "records_read":       data.get("records_read", len(entries)),
        "responses_analyzed": data.get("responses_analyzed", len(entries)),
        "entries":            entries,
        "summary":            summary,
        "websocket":          websocket,
    }
    cookie_report = data.get("cookie_report") if isinstance(data.get("cookie_report"), dict) else None
    if cookie_report is not None:
        payload["cookie_report"] = cookie_report
    scan_id = writer.insert("headers_scans", {
        "domain":             domain,
        "url":                data.get("url") or (f"https://{domain}" if domain else None),
        "final_url":          data.get("final_url"),
        "status_code":        data.get("status_code"),
        "timestamp":          payload["timestamp"],
        "elapsed_ms":         payload["elapsed_ms"],
        "records_read":       payload["records_read"],
        "responses_analyzed": payload["responses_analyzed"],
        "intercept_files":    _to_sqlite(payload["intercept_files"]),
        "grade":              grade,
        "score":              average,
        "source_file":        source_file,
    })
    counts: dict[str, int] = {
        "headers_scans":           1,
        "headers_results_payload": 1,
        "headers_entries":         0,
        "headers_findings":        0,
        "headers_metadata":        0,
        "headers_summary":         0,
        "headers_websocket":       1,
        "headers_cookies":         0,
        "headers_cookie_findings": 0,
    }
    writer.insert("headers_results_payload", {
        "scan_id": scan_id,
        "payload": _to_sqlite(payload),
    })
    for entry in entries:
        entry_id = str(entry.get("id", ""))
        score = entry.get("score") or {}
        writer.insert("headers_entries", {
            "scan_id":         scan_id,
            "entry_id":        entry_id,
            "source":          entry.get("source"),
            "method":          entry.get("method"),
            "url":             entry.get("url"),
            "status_code":     entry.get("status_code"),
            "grade":           score.get("grade"),
            "score":           score.get("score"),
            "recommendations": _to_sqlite(score.get("recommendations") or []),
        })
        counts["headers_entries"] += 1
        for module_name, module_data in (entry.get("modules") or {}).items():
            if not isinstance(module_data, dict):
                continue
            for finding in (module_data.get("findings") or []):
                writer.insert("headers_findings", {
                    "scan_id":  scan_id,
                    "entry_id": entry_id,
                    "module":   module_name,
                    "severity": finding.get("severity"),
                    "header":   finding.get("header"),
                    "detail":   finding.get("detail"),
                })
                counts["headers_findings"] += 1
            for meta_key, meta_val in (module_data.get("metadata") or {}).items():
                writer.insert("headers_metadata", {
                    "scan_id":  scan_id,
                    "entry_id": entry_id,
                    "module":   module_name,
                    "key":      meta_key,
                    "value":    _to_sqlite(meta_val),
                })
                counts["headers_metadata"] += 1
    for row in summary:
        writer.insert("headers_summary", {
            "scan_id":   scan_id,
            "module":    row.get("module"),
            "severity":  row.get("severity"),
            "header":    row.get("header"),
            "detail":    row.get("detail"),
            "count":     row.get("count"),
            "entry_ids": _to_sqlite(row.get("entry_ids") or []),
        })
        counts["headers_summary"] += 1
    totals = websocket.get("totals") or {}
    writer.insert("headers_websocket", {
        "scan_id":        scan_id,
        "handshakes":     totals.get("handshakes", 0),
        "accepted":       totals.get("accepted", 0),
        "rejected":       totals.get("rejected", 0),
        "other_upgrades": totals.get("other_upgrades", 0),
        "endpoints":      _to_sqlite(websocket.get("endpoints") or []),
        "notes":          _to_sqlite(websocket.get("notes") or []),
    })
    if cookie_report is not None:
        counts.update(_write_headers_cookies(writer, scan_id, cookie_report))
    writer.create_index("headers_scans", "domain")
    for table in ("headers_results_payload", "headers_entries", "headers_findings",
                  "headers_metadata", "headers_summary", "headers_websocket",
                  "headers_cookies", "headers_cookie_findings"):
        writer.create_index(table, "scan_id")
    writer.create_index("headers_entries", "entry_id")
    writer.create_index("headers_findings", "entry_id")
    writer.create_index("headers_findings", "module")
    writer.create_index("headers_metadata", "entry_id")
    writer.create_index("headers_metadata", "module")
    writer.create_index("headers_cookies", "name")
    logger.info("%-40s -> scan_id=%d  (%s)  [headers-analyzer]  entries=%d findings=%d cookies=%d",
                source_file, scan_id, domain, counts["headers_entries"], counts["headers_findings"], counts["headers_cookies"])
    return counts

def _is_tech_fingerprint(data: dict) -> bool:
    return (
        "domain" in data
        and "results" in data
        and isinstance(data.get("results"), dict)
        and any(k in data["results"] for k in _TECH_MODULE_WRITERS)
    )

def _write_tech_fingerprint(writer: SqliteWriter, data: dict, source_file: str) -> dict[str, int]:
    domain    = data.get("domain", "")
    timestamp = data.get("scanned_at", "")
    scan_id   = _insert_scan(writer, domain, timestamp, source_file)
    results   = data.get("results", {})
    counts: dict[str, int] = {}
    vuln_findings = []
    retire_data = results.get("RetireJS")
    if retire_data:
        vuln_findings = retire_data.get("findings", [])
    if vuln_findings:
        n = _write_tech_vulnerabilities(writer, scan_id, vuln_findings)
        counts["tech_vulnerabilities"] = n
    for module_key, module_data in results.items():
        fn = _TECH_MODULE_WRITERS.get(module_key)
        if fn is None:
            logger.warning("No tech writer for module '%s' - skipped", module_key)
            continue
        try:
            n = fn(writer, scan_id, module_data)
            counts[module_key] = counts.get(module_key, 0) + n
        except Exception as exc:
            logger.error("Failed writing tech module '%s': %s", module_key, exc)
    logger.info("%-40s -> scan_id=%d  (%s)  [tech-fingerprint]",
                source_file, scan_id, domain)
    return counts

def _is_subdomain_hunter(data: dict) -> bool:
    return "tree" in data and "domain" in data and "sources" in data

def _is_wayback_scanner(data: dict) -> bool:
    return (
        "meta" in data
        and "results" in data
        and isinstance(data.get("results"), dict)
        and "sources" in data["results"]
        and isinstance(data["results"]["sources"], dict)
        and "urls" in data["results"]["sources"]
    )

def _ensure_wayback_tables(writer: SqliteWriter) -> None:
    writer.ensure_table("wayback_scans", {
        "tool":        "TEXT",
        "timestamp":   "TEXT",
        "source_file": "TEXT",
    })
    writer.ensure_table("wayback_urls", {
        "scan_id": "INTEGER",
        "url":     "TEXT",
        "source":  "TEXT",
    })
    writer.ensure_table("wayback_subdomains", {
        "scan_id": "INTEGER",
        "url":     "TEXT",
    })
    writer.ensure_table("wayback_critical_patterns", {
        "scan_id":      "INTEGER",
        "pattern_name": "TEXT",
        "url":          "TEXT",
    })
    writer.ensure_table("wayback_files", {
        "scan_id": "INTEGER",
        "url":     "TEXT",
    })
    writer.ensure_table("wayback_parameters", {
        "scan_id":      "INTEGER",
        "param_name":   "TEXT",
        "count":        "INTEGER",
        "is_sensitive": "INTEGER",
    })

def _write_wayback_scanner(writer: SqliteWriter, data: dict, source_file: str) -> dict[str, int]:
    _ensure_wayback_tables(writer)
    meta = data.get("meta", {})
    scan_id = writer.insert("wayback_scans", {
        "tool":        meta.get("tool", "WebArchive Scanner"),
        "timestamp":   meta.get("timestamp", ""),
        "source_file": source_file,
    })
    writer.create_index("wayback_scans", "id")
    counts: dict[str, int] = {"wayback_scans": 1}
    sources = data["results"]["sources"]
    n_urls = 0
    for url in (sources.get("urls") or []):
        writer.insert("wayback_urls", {"scan_id": scan_id, "url": str(url), "source": "wayback"})
        n_urls += 1
    writer.create_index("wayback_urls", "scan_id")
    counts["wayback_urls"] = n_urls
    n_sub = 0
    for url in (sources.get("subdomain") or []):
        writer.insert("wayback_subdomains", {"scan_id": scan_id, "url": str(url)})
        n_sub += 1
    writer.create_index("wayback_subdomains", "scan_id")
    counts["wayback_subdomains"] = n_sub
    n_cp = 0
    for pattern_name, url_list in (sources.get("critical_pattern") or {}).items():
        for url in (url_list or []):
            writer.insert("wayback_critical_patterns", {
                "scan_id":      scan_id,
                "pattern_name": str(pattern_name),
                "url":          str(url),
            })
            n_cp += 1
    writer.create_index("wayback_critical_patterns", "scan_id")
    writer.create_index("wayback_critical_patterns", "pattern_name")
    counts["wayback_critical_patterns"] = n_cp
    n_files = 0
    for url in (sources.get("files") or []):
        writer.insert("wayback_files", {"scan_id": scan_id, "url": str(url)})
        n_files += 1
    writer.create_index("wayback_files", "scan_id")
    counts["wayback_files"] = n_files
    params_block = data["results"].get("params", {})
    raw_params   = params_block.get("params", {})
    sensitive_keys = set((params_block.get("sensitive_keys") or {}).keys())
    n_params = 0
    for param_name, count_val in raw_params.items():
        writer.insert("wayback_parameters", {
            "scan_id":      scan_id,
            "param_name":   str(param_name),
            "count":        int(count_val) if isinstance(count_val, (int, float)) else 0,
            "is_sensitive": int(param_name in sensitive_keys),
        })
        n_params += 1
    writer.create_index("wayback_parameters", "scan_id")
    writer.create_index("wayback_parameters", "param_name")
    counts["wayback_parameters"] = n_params
    logger.info("%-40s -> scan_id=%d  [wayback-scanner]  urls=%d subdomains=%d patterns=%d files=%d params=%d",
                source_file, scan_id, n_urls, n_sub, n_cp, n_files, n_params)
    return counts

def convert_file(
    json_path: str | Path,
    conn: sqlite3.Connection,
    progress_cb: Callable[[str, int], None] | None = None,
) -> dict[str, int]:
    json_path = Path(json_path)
    with json_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    writer = SqliteWriter(conn)
    _ensure_scans_table(writer)
    if _is_tls_scanner(data):
        counts = _write_tls_scanner(writer, data, json_path.name,
                                    progress_cb=progress_cb)
        conn.commit()
        return counts
    if _is_email_infra(data):
        counts = _write_email_infra(writer, data, json_path.name)
        if progress_cb:
            for table, n in counts.items():
                progress_cb(table, n)
        conn.commit()
        return counts
    if _is_headers_analyzer(data):
        counts = _write_headers_analyzer(writer, data, json_path.name)
        if progress_cb:
            for table, n in counts.items():
                progress_cb(table, n)
        conn.commit()
        return counts
    if _is_tech_fingerprint(data):
        counts = _write_tech_fingerprint(writer, data, json_path.name)
        conn.commit()
        return counts
    if _is_whois_checker(data):
        counts = _write_whois_checker(writer, data, json_path.name)
        conn.commit()
        return counts
    if _is_social_metadata(data):
        meta      = data.get("meta", {})
        target    = meta.get("target", "")
        timestamp = meta.get("generated_at", "")
        scan_id   = _insert_scan(writer, target, timestamp, json_path.name)
        results = data.get("results", {})
        counts: dict[str, int] = {}
        writers_map = {
            "social":     ("social_profiles", _write_social_profiles),
            "emails":     ("social_emails",   _write_social_emails),
            "html_meta":  ("social_html_meta", _write_social_html_meta),
            "docs_osint": ("social_docs",      _write_social_docs),
        }
        for key, (table, fn) in writers_map.items():
            items = results.get(key, [])
            if items is None:
                items = []
            try:
                n = fn(writer, scan_id, items)
                counts[table] = n
                if progress_cb:
                    progress_cb(key, n)
            except Exception as exc:
                logger.error("Failed writing social module '%s': %s", key, exc)
        logger.info("%-40s -> scan_id=%d  (%s)  [social-metadata]",
                    json_path.name, scan_id, target)
        return counts
    if _is_wayback_scanner(data):
        counts = _write_wayback_scanner(writer, data, json_path.name)
        if progress_cb:
            for table, n in counts.items():
                progress_cb(table, n)
        conn.commit()
        return counts
    if _is_subdomain_hunter(data):
        target    = data.get("domain", "")
        timestamp = data.get("scanned_at", "")
        scan_id   = _insert_scan(writer, target, timestamp, json_path.name)
        counts: dict[str, int] = {}
        n = _write_subdomains(writer, scan_id, data)
        counts["subdomains"] = n
        if progress_cb:
            progress_cb("subdomains", n)
        n = _write_subdomain_sources(writer, scan_id, data.get("sources", {}))
        counts["subdomain_sources"] = n
        if progress_cb:
            progress_cb("subdomain_sources", n)
        logger.info("%-40s -> scan_id=%d  (%s)  [subdomain-hunter]",
                    json_path.name, scan_id, target)
        return counts
    target    = data.get("target", "")
    timestamp = data.get("timestamp", "")
    results   = data.get("results", {})
    scan_id   = _insert_scan(writer, target, timestamp, json_path.name)
    counts = {}
    for module_key, module_data in results.items():
        _write_module_result(writer, scan_id, module_key, module_data)
        writer_fn = _MODULE_WRITERS.get(module_key)
        if writer_fn is None:
            logger.warning("No writer for module '%s' - skipped", module_key)
            continue
        try:
            n = writer_fn(writer, scan_id, module_data)
            table = KNOWN_SPECS[module_key].table_name
            counts[table] = counts.get(table, 0) + n
            if progress_cb:
                progress_cb(module_key, n)
        except Exception as exc:
            logger.error("Failed writing module '%s': %s", module_key, exc)
    logger.info("%-40s -> scan_id=%d  (%s)  [dns-enumeration]",
                json_path.name, scan_id, target)
    return counts

def convert_directory(
    input_dir:     str | Path,
    output_db:     str | Path,
    pattern:       str  = "*.json",
    progress:      bool = True,
    delete_source: bool = False,
) -> dict[str, int]:
    input_dir = Path(input_dir)
    output_db = Path(output_db)
    if not input_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {input_dir}")
    files = sorted(input_dir.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No files matching '{pattern}' found in: {input_dir}")
    output_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(output_db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    totals:    dict[str, int] = {}
    succeeded: list[Path]    = []
    failed:    list[tuple[Path, Exception]] = []
    try:
        for f in files:
            def _cb(module: str, n: int, _name=f.name) -> None:
                if progress:
                    print(
                        f"\r  {_name}: [{module}] {n} rows ...",
                        end="", file=sys.stderr, flush=True,
                    )
            try:
                counts = convert_file(f, conn, progress_cb=_cb if progress else None)
                if progress:
                    print(file=sys.stderr)
                conn.commit()
                for table, n in counts.items():
                    totals[table] = totals.get(table, 0) + n
                succeeded.append(f)
            except Exception as exc:
                conn.rollback()
                if progress:
                    print(file=sys.stderr)
                logger.error("Failed to process %s: %s", f.name, exc)
                failed.append((f, exc))
    finally:
        conn.close()
    if delete_source:
        for f in succeeded:
            try:
                f.unlink()
            except OSError as exc:
                logger.error("Could not delete %s: %s", f, exc)
    if failed:
        logger.warning(
            "%d file(s) failed: %s",
            len(failed),
            ", ".join(f.name for f, _ in failed),
        )
    return totals

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns_engine",
        description=(
            "Convert DNS-Enumeration / Wayback / Whois / Social JSON result files "
            "into a single SQLite database."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="Scan-Results",
        help="Path to a single .json result file OR a directory of result files (default: Scan-Results/)",
    )
    parser.add_argument(
        "-o", "--output",
        default="Scan-Results/dns_results.db",
        help="Output .db file path (default: Scan-Results/dns_results.db)",
    )
    parser.add_argument(
        "--pattern",
        default="*.json",
        help="Glob pattern when input is a directory (default: *.json)",
    )
    parser.add_argument(
        "--delete-source",
        action="store_true",
        help="Delete successfully imported source files after conversion",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Debug-level logging",
    )
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args   = parser.parse_args(argv)
    log_level = (
        logging.CRITICAL + 1 if args.quiet else
        logging.DEBUG        if args.verbose else
        logging.INFO
    )
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")
    input_path = Path(args.input)
    try:
        if input_path.is_file():
            conn = sqlite3.connect(args.output)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            counts = convert_file(input_path, conn)
            conn.commit()
            conn.close()
        elif input_path.is_dir():
            counts = convert_directory(
                input_path,
                args.output,
                pattern=args.pattern,
                progress=not args.quiet,
                delete_source=args.delete_source,
            )
        else:
            logger.error("Input not found: %s", input_path)
            return 1
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 1
    if not args.quiet:
        total = sum(counts.values())
        print(f"\nDone. Output: {args.output}")
        print(f"{'Table':<35} {'Rows':>8}")
        print("-" * 44)
        for table, n in sorted(counts.items()):
            print(f"{table:<35} {n:>8}")
        print("-" * 44)
        print(f"{'TOTAL':<35} {total:>8}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())