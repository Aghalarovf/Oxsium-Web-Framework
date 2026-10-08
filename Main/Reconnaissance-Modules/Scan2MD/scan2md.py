#!/usr/bin/env python3

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def db_connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.exists():
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


def fetch(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list:
    if not conn:
        return []
    try:
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def parse_json_field(value) -> any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def json_payload_block(title: str, payload) -> str:
    parsed = parse_json_field(payload)
    if parsed is None:
        return ""
    return f"\n### {title}\n\n```json\n{json.dumps(parsed, indent=2, ensure_ascii=False, default=str)}\n```\n"


def md_table(headers: list, rows: list) -> str:
    if not rows:
        return "_No data._\n"
    col_widths = [len(h) for h in headers]
    str_rows = []
    for row in rows:
        sr = [str(v) if v is not None else "" for v in row]
        for i, cell in enumerate(sr):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(cell))
        str_rows.append(sr)
    def fmt_row(cells):
        return "| " + " | ".join(
            str(c).ljust(col_widths[i]) if i < len(col_widths) else str(c)
            for i, c in enumerate(cells)
        ) + " |"
    sep = "| " + " | ".join("-" * w for w in col_widths) + " |"
    lines = [fmt_row(headers), sep]
    for r in str_rows:
        lines.append(fmt_row(r))
    return "\n".join(lines) + "\n"


def severity_badge(s: str) -> str:
    mapping = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🔵 LOW",
        "INFO": "⚪ INFO",
        "PASS": "✅ PASS",
        "WARN": "⚠️ WARN",
    }
    return mapping.get(str(s).upper(), str(s))


def get_domain(conn: sqlite3.Connection) -> str:
    rows = fetch(conn, "SELECT target FROM scans LIMIT 1")
    if rows:
        t = rows[0].get("target", "unknown")
        return t.replace("https://", "").replace("http://", "").rstrip("/")
    return "unknown"


def section_metadata(conn: sqlite3.Connection) -> str:
    out = ["## Scan Metadata\n"]
    rows = fetch(conn, "SELECT id, target, timestamp, source_file FROM scans ORDER BY id")
    if rows:
        out.append(md_table(
            ["ID", "Target", "Timestamp", "Source File"],
            [[r["id"], r["target"], r["timestamp"], r["source_file"]] for r in rows]
        ))
    else:
        out.append("_No scan metadata found._\n")
    return "\n".join(out) + "\n"


def section_dns(conn: sqlite3.Connection) -> str:
    out = ["## DNS\n"]

    records = fetch(conn, "SELECT record_type, ttl, value FROM dns_records ORDER BY record_type")
    if records:
        out.append("### DNS Records\n")
        out.append(md_table(
            ["Type", "TTL", "Value"],
            [[r["record_type"], r["ttl"], r["value"]] for r in records]
        ))

    axfr = fetch(conn, "SELECT vulnerable, error, any_records, soa_info FROM dns_axfr LIMIT 1")
    if axfr:
        a = axfr[0]
        out.append("### Zone Transfer (AXFR)\n")
        out.append(f"- **Vulnerable:** {'Yes ⚠️' if a['vulnerable'] else 'No ✅'}\n")
        if a.get("error"):
            out.append(f"- **Error:** {a['error']}\n")
        if a.get("soa_info"):
            soa = parse_json_field(a["soa_info"])
            out.append(f"- **SOA:** {soa}\n")

    dnssec = fetch(conn, "SELECT * FROM dns_dnssec LIMIT 1")
    if dnssec:
        d = dnssec[0]
        out.append("\n### DNSSEC\n")
        flags = {
            "DNSKEY": d.get("dnskey"),
            "DS": d.get("ds"),
            "RRSIG": d.get("rrsig"),
            "NSEC": d.get("nsec"),
            "Chain Valid": d.get("chain_valid"),
        }
        for k, v in flags.items():
            icon = "✅" if v else "❌"
            out.append(f"- **{k}:** {icon}\n")
        sshfp = parse_json_field(d.get("sshfp"))
        if sshfp:
            out.append(f"- **SSHFP Records:** {sshfp}\n")

    reverse = fetch(conn, "SELECT ip, hostname FROM dns_reverse")
    if any(r.get("ip") for r in reverse):
        out.append("\n### Reverse DNS\n")
        out.append(md_table(
            ["IP", "Hostname"],
            [[r["ip"], r["hostname"]] for r in reverse if r.get("ip")]
        ))

    dangling = fetch(conn, "SELECT subdomain, cname, service FROM dns_dangling WHERE subdomain IS NOT NULL")
    if dangling:
        out.append("\n### Dangling DNS Records\n")
        out.append(md_table(
            ["Subdomain", "CNAME", "Service"],
            [[r["subdomain"], r["cname"], r["service"]] for r in dangling]
        ))
    else:
        out.append("\n### Dangling DNS Records\n")
        out.append("_No dangling records detected._\n")

    ttl_anom = fetch(conn, "SELECT name, type, ttl, value, anomaly FROM dns_ttl_anomalies")
    if ttl_anom:
        out.append("\n### TTL Anomalies\n")
        out.append(md_table(
            ["Name", "Type", "TTL", "Value", "Anomaly"],
            [[r["name"], r["type"], r["ttl"], r["value"], r["anomaly"]] for r in ttl_anom]
        ))

    module_results = fetch(conn, "SELECT module, result FROM dns_module_results")
    if module_results:
        out.append("\n### Module Results\n")
        out.append(md_table(
            ["Module", "Result"],
            [[r["module"], r["result"]] for r in module_results]
        ))

    return "\n".join(out) + "\n"


def section_tls(conn: sqlite3.Connection) -> str:
    out = ["## TLS / SSL\n"]

    scan = fetch(conn, "SELECT target, sni, scanner, scan_time FROM tls_scans LIMIT 1")
    if scan:
        s = scan[0]
        out.append(f"- **Target:** {s.get('target')}\n")
        out.append(f"- **SNI:** {s.get('sni')}\n")
        out.append(f"- **Scanner:** {s.get('scanner')}\n")
        out.append(f"- **Scan Time:** {s.get('scan_time')}\n\n")

    handshake = fetch(conn, "SELECT negotiated_version, cipher_name, cipher_bits, handshake_time_ms, session_ticket FROM tls_handshake LIMIT 1")
    if handshake:
        h = handshake[0]
        out.append("### Negotiated Handshake\n")
        out.append(f"- **Version:** {h.get('negotiated_version')}\n")
        out.append(f"- **Cipher:** {h.get('cipher_name')} ({h.get('cipher_bits')} bits)\n")
        out.append(f"- **Handshake Time:** {h.get('handshake_time_ms')} ms\n")
        out.append(f"- **Session Ticket:** {'Yes' if h.get('session_ticket') else 'No'}\n\n")

    alpn = fetch(conn, "SELECT http2_supported, http11_supported, supported_protocols FROM tls_alpn LIMIT 1")
    if alpn:
        a = alpn[0]
        protos = parse_json_field(a.get("supported_protocols")) or []
        out.append("### ALPN\n")
        out.append(f"- **HTTP/2:** {'✅' if a.get('http2_supported') else '❌'}\n")
        out.append(f"- **HTTP/1.1:** {'✅' if a.get('http11_supported') else '❌'}\n")
        if protos:
            out.append(f"- **Supported:** {', '.join(protos)}\n")
        out.append("\n")

    protocols = fetch(conn, "SELECT version, supported, rating, rating_reason, cipher_name, cipher_bits, error FROM tls_protocols ORDER BY id")
    if protocols:
        out.append("### Protocol Support\n")
        out.append(md_table(
            ["Version", "Supported", "Rating", "Reason", "Cipher", "Bits"],
            [
                [
                    p["version"],
                    "✅" if p["supported"] else "❌",
                    severity_badge(p.get("rating", "")),
                    p.get("rating_reason", ""),
                    p.get("cipher_name", ""),
                    p.get("cipher_bits", ""),
                ]
                for p in protocols
            ]
        ))

    cert_assess = fetch(conn, "SELECT grade, chain_complete, chain_trusted, issues, warnings, notes FROM tls_cert_assessment LIMIT 1")
    if cert_assess:
        c = cert_assess[0]
        out.append("\n### Certificate Assessment\n")
        out.append(f"- **Grade:** {c.get('grade')}\n")
        out.append(f"- **Chain Complete:** {'✅' if c.get('chain_complete') else '❌'}\n")
        out.append(f"- **Chain Trusted:** {'✅' if c.get('chain_trusted') else '❌'}\n")
        issues = parse_json_field(c.get("issues")) or []
        warnings = parse_json_field(c.get("warnings")) or []
        if issues:
            out.append(f"- **Issues:** {', '.join(issues)}\n")
        if warnings:
            out.append(f"- **Warnings:** {', '.join(warnings)}\n")

    chain = fetch(conn, """
        SELECT role, subject_cn, subject_o, issuer_cn, not_before, not_after,
               days_remaining, expired, self_signed, key_type, key_bits,
               key_weak, signature_algorithm
        FROM tls_cert_chain ORDER BY chain_index
    """)
    if chain:
        out.append("\n### Certificate Chain\n")
        out.append(md_table(
            ["Role", "Subject CN", "Subject Org", "Issuer CN", "Not Before", "Not After", "Days Left", "Expired", "Self-Signed", "Key", "Bits", "Weak", "Sig Alg"],
            [
                [
                    r["role"], r["subject_cn"], r["subject_o"], r["issuer_cn"],
                    r["not_before"], r["not_after"], r["days_remaining"],
                    "⚠️ Yes" if r["expired"] else "No",
                    "⚠️ Yes" if r["self_signed"] else "No",
                    r["key_type"], r["key_bits"],
                    "⚠️ Yes" if r["key_weak"] else "No",
                    r["signature_algorithm"],
                ]
                for r in chain
            ]
        ))

    ocsp = fetch(conn, "SELECT status, responder, this_update, next_update, cert_status, error FROM tls_ocsp LIMIT 1")
    if ocsp:
        o = ocsp[0]
        out.append("\n### OCSP\n")
        out.append(f"- **Status:** {o.get('status')}\n")
        out.append(f"- **Cert Status:** {o.get('cert_status')}\n")
        out.append(f"- **Responder:** {o.get('responder')}\n")
        if o.get("error"):
            out.append(f"- **Error:** {o.get('error')}\n")

    ct = fetch(conn, "SELECT ct_id, logged_at, common_name, issuer, queried_domain, total_found FROM tls_ct_entries LIMIT 1")
    if ct:
        c = ct[0]
        out.append("\n### Certificate Transparency\n")
        out.append(f"- **CT ID:** {c.get('ct_id')}\n")
        out.append(f"- **Logged At:** {c.get('logged_at')}\n")
        out.append(f"- **Common Name:** {c.get('common_name')}\n")
        out.append(f"- **Issuer:** {c.get('issuer')}\n")
        out.append(f"- **Total Found:** {c.get('total_found')}\n")

    cipher_assess = fetch(conn, """
        SELECT grade, pfs_count, non_pfs_count, strong_count, weak_count,
               insecure_count, issues, warnings
        FROM tls_cipher_assessment LIMIT 1
    """)
    if cipher_assess:
        ca = cipher_assess[0]
        out.append("\n### Cipher Assessment\n")
        out.append(f"- **Grade:** {ca.get('grade')}\n")
        out.append(f"- **PFS Ciphers:** {ca.get('pfs_count')} | Non-PFS: {ca.get('non_pfs_count')}\n")
        out.append(f"- **Strong:** {ca.get('strong_count')} | Weak: {ca.get('weak_count')} | Insecure: {ca.get('insecure_count')}\n")
        issues = parse_json_field(ca.get("issues")) or []
        warnings = parse_json_field(ca.get("warnings")) or []
        if issues:
            out.append(f"- **Issues:** {', '.join(issues)}\n")
        if warnings:
            out.append(f"- **Warnings:** {', '.join(warnings)}\n")

    ciphers_supported = fetch(conn, """
        SELECT name, protocol, bits, pfs, strength, category
        FROM tls_ciphers WHERE supported=1 ORDER BY protocol, name
    """)
    if ciphers_supported:
        out.append("\n### Supported Ciphers\n")
        out.append(md_table(
            ["Name", "Protocol", "Bits", "PFS", "Strength", "Category"],
            [
                [c["name"], c["protocol"], c["bits"],
                 "✅" if c["pfs"] else "❌",
                 c["strength"], c["category"]]
                for c in ciphers_supported
            ]
        ))

    pfs = fetch(conn, "SELECT * FROM tls_pfs_assessment LIMIT 1")
    if pfs:
        p = pfs[0]
        out.append("\n### PFS Assessment\n")
        out.append(f"- **Grade:** {p.get('grade')}\n")
        out.append(f"- **Strength Level:** {p.get('strength_level')}\n")
        out.append(f"- **Best ECDHE Group:** {p.get('best_ecdhe_group')} ({p.get('best_ecdhe_bits')} bits)\n")
        out.append(f"- **ECDHE Strong/Obsolete/Weak:** {p.get('ecdhe_strong_count')}/{p.get('ecdhe_obsolete_count')}/{p.get('ecdhe_weak_count')}\n")
        out.append(f"- **Custom DHE Supported:** {'Yes' if p.get('custom_dhe_supported') else 'No'}\n")
        warnings = parse_json_field(p.get("warnings")) or []
        if warnings:
            out.append(f"- **Warnings:** {'; '.join(warnings)}\n")

    pfs_support = fetch(conn, "SELECT * FROM tls_pfs_support LIMIT 1")
    if pfs_support:
        ps = pfs_support[0]
        out.append("\n### PFS Key Exchange Support\n")
        for field, label in [
            ("pfs_available", "PFS Available"),
            ("pfs_supported_kex", "Supported Key Exchanges"),
            ("non_pfs_supported_kex", "Non-PFS Key Exchanges"),
            ("all_supported_kex", "All Supported Key Exchanges"),
            ("unsupported_kex", "Unsupported Key Exchanges"),
        ]:
            value = parse_json_field(ps.get(field))
            if field == "pfs_available":
                value = "Yes" if value else "No"
            elif isinstance(value, list):
                value = ", ".join(str(item) for item in value)
            out.append(f"- **{label}:** {value}\n")

    pfs_groups = fetch(conn, """
        SELECT name, type, supported, key_bits, protocol, cipher,
               handshake_time_ms, classification, error
        FROM tls_pfs_groups ORDER BY type, name
    """)
    if pfs_groups:
        out.append("\n### PFS Groups\n")
        out.append(md_table(
            ["Name", "Type", "Supported", "Bits", "Protocol", "Cipher",
             "Handshake (ms)", "Classification", "Error"],
            [[r["name"], r["type"], "✅" if r["supported"] else "❌",
              r["key_bits"], r["protocol"], r["cipher"], r["handshake_time_ms"],
              r["classification"], r["error"]] for r in pfs_groups]
        ))

    cipher_preference = fetch(conn, "SELECT * FROM tls_cipher_preference LIMIT 1")
    if cipher_preference:
        cp = cipher_preference[0]
        preference = parse_json_field(cp.get("preference")) or []
        out.append("\n### Cipher Preference\n")
        out.append(f"- **Preference Known:** {'Yes' if cp.get('preference_known') else 'No'}\n")
        out.append(f"- **PFS Preferred:** {'Yes' if cp.get('pfs_preferred') else 'No'}\n")
        out.append(f"- **PFS Position:** {cp.get('pfs_at_position')}\n")
        out.append(f"- **PFS Ciphers:** {cp.get('pfs_cipher_count')} | **Non-PFS Ciphers:** {cp.get('non_pfs_cipher_count')}\n")
        if preference:
            out.append(md_table(
                ["Order", "Cipher"],
                [[index, cipher] for index, cipher in enumerate(preference, 1)]
            ))

    ecdh = fetch(conn, "SELECT supported_curves, strong_curves, obsolete_curves, weak_curves FROM tls_ecdh_curves LIMIT 1")
    if ecdh:
        e = ecdh[0]
        out.append("\n### ECDH Curves\n")
        for field, label in [("supported_curves", "Supported"), ("strong_curves", "Strong"),
                              ("obsolete_curves", "Obsolete"), ("weak_curves", "Weak")]:
            val = parse_json_field(e.get(field))
            if val:
                out.append(f"- **{label}:** {', '.join(val) if isinstance(val, list) else val}\n")

    fallback = fetch(conn, "SELECT vuln_name, vulnerable, certainty, detail FROM tls_fallback")
    if fallback:
        out.append("\n### Fallback / Downgrade Tests\n")
        out.append(md_table(
            ["Vulnerability", "Vulnerable", "Certainty", "Detail"],
            [
                [f["vuln_name"], "⚠️ Yes" if f["vulnerable"] else "No ✅",
                 f["certainty"], f["detail"]]
                for f in fallback
            ]
        ))

    fb_assess = fetch(conn, """
        SELECT grade, confirmed_count, probable_count, potential_count,
               safe_count, total_checked, issues, warnings
        FROM tls_fallback_assessment LIMIT 1
    """)
    if fb_assess:
        fa = fb_assess[0]
        out.append("\n### Fallback Assessment\n")
        out.append(f"- **Grade:** {fa.get('grade')}\n")
        out.append(f"- **Confirmed/Probable/Potential/Safe:** "
                   f"{fa.get('confirmed_count')}/{fa.get('probable_count')}/"
                   f"{fa.get('potential_count')}/{fa.get('safe_count')} (of {fa.get('total_checked')})\n")
        issues = parse_json_field(fa.get("issues")) or []
        if issues:
            out.append(f"- **Issues:** {'; '.join(issues)}\n")

    session = fetch(conn, """
        SELECT resumption_mode, session_id_supported, session_ticket_supported,
               ticket_lifetime_hours, ticket_lifetime_warning
        FROM tls_session_resumption LIMIT 1
    """)
    if session:
        sr = session[0]
        out.append("\n### Session Resumption\n")
        out.append(f"- **Mode:** {sr.get('resumption_mode')}\n")
        out.append(f"- **Session ID:** {'✅' if sr.get('session_id_supported') else '❌'}\n")
        out.append(f"- **Session Ticket:** {'✅' if sr.get('session_ticket_supported') else '❌'}\n")
        if sr.get("ticket_lifetime_hours") is not None:
            out.append(f"- **Ticket Lifetime:** {sr.get('ticket_lifetime_hours')} hours\n")
        if sr.get("ticket_lifetime_warning"):
            out.append(f"- **Warning:** {sr.get('ticket_lifetime_warning')}\n")

    proto_assess = fetch(conn, "SELECT grade, issues, warnings, notes FROM tls_proto_assessment LIMIT 1")
    if proto_assess:
        pa = proto_assess[0]
        out.append("\n### Protocol Assessment\n")
        out.append(f"- **Grade:** {pa.get('grade')}\n")
        issues = parse_json_field(pa.get("issues")) or []
        warnings = parse_json_field(pa.get("warnings")) or []
        notes = parse_json_field(pa.get("notes")) or []
        if issues:
            out.append(f"- **Issues:** {'; '.join(issues)}\n")
        if warnings:
            out.append(f"- **Warnings:** {'; '.join(warnings)}\n")
        if notes:
            out.append(f"- **Notes:** {'; '.join(notes)}\n")

    tls_hdrs = fetch(conn, """
        SELECT hsts_present, hsts_max_age, hsts_include_subdomains, hsts_preload,
               hsts_header, expect_ct_present, hpkp_present, score_grade,
               score_issues, score_warnings
        FROM tls_headers LIMIT 1
    """)
    if tls_hdrs:
        th = tls_hdrs[0]
        out.append("\n### TLS-Specific Headers\n")
        out.append(f"- **HSTS Present:** {'✅' if th.get('hsts_present') else '❌'}\n")
        if th.get("hsts_header"):
            out.append(f"  - Header: `{th.get('hsts_header')}`\n")
            out.append(f"  - Max-Age: {th.get('hsts_max_age')} | Subdomains: {'Yes' if th.get('hsts_include_subdomains') else 'No'} | Preload: {'Yes' if th.get('hsts_preload') else 'No'}\n")
        out.append(f"- **Expect-CT Present:** {'✅' if th.get('expect_ct_present') else '❌'}\n")
        out.append(f"- **HPKP Present:** {'Yes ⚠️' if th.get('hpkp_present') else 'No'}\n")
        if th.get("score_grade"):
            out.append(f"- **Score Grade:** {th.get('score_grade')}\n")
        score_issues = parse_json_field(th.get("score_issues")) or []
        if score_issues:
            out.append(f"- **Score Issues:** {'; '.join(score_issues)}\n")

    net_assess = fetch(conn, "SELECT grade, issues, warnings, notes FROM tls_network_assessment LIMIT 1")
    if net_assess:
        na = net_assess[0]
        out.append("\n### Network Assessment\n")
        out.append(f"- **Grade:** {na.get('grade')}\n")
        issues = parse_json_field(na.get("issues")) or []
        warnings = parse_json_field(na.get("warnings")) or []
        notes = parse_json_field(na.get("notes")) or []
        if issues:
            out.append(f"- **Issues:** {'; '.join(issues)}\n")
        if warnings:
            out.append(f"- **Warnings:** {'; '.join(warnings)}\n")
        if notes:
            out.append(f"- **Notes:** {'; '.join(notes)}\n")

    dane = fetch(conn, "SELECT services, validation FROM tls_network_dane LIMIT 1")
    if dane:
        d = dane[0]
        services = parse_json_field(d.get("services"))
        validation = parse_json_field(d.get("validation"))
        out.append("\n### DANE\n")
        if services:
            out.append(f"- **Services:** {services}\n")
        if validation:
            out.append(f"- **Validation:** {validation}\n")

    mta_sts = fetch(conn, "SELECT dns_record, policy, error FROM tls_network_mta_sts LIMIT 1")
    if mta_sts:
        m = mta_sts[0]
        out.append("\n### MTA-STS\n")
        if m.get("dns_record"):
            dns_r = parse_json_field(m.get("dns_record"))
            out.append(f"- **DNS Record:** {dns_r}\n")
        if m.get("policy"):
            policy = parse_json_field(m.get("policy"))
            out.append(f"- **Policy:** {policy}\n")
        if m.get("error"):
            out.append(f"- **Error:** {m.get('error')}\n")

    caa = fetch(conn, "SELECT tag, value, flags, critical FROM tls_network_caa")
    if caa:
        out.append("\n### CAA Records\n")
        out.append(md_table(
            ["Tag", "Value", "Flags", "Critical"],
            [[r["tag"], r["value"], r["flags"], "Yes" if r["critical"] else "No"] for r in caa]
        ))

    return "\n".join(out) + "\n"


def section_whois(conn: sqlite3.Connection) -> str:
    out = ["## WHOIS\n"]

    scan = fetch(conn, "SELECT domain, tld, queried_at, tool, version FROM whois_scans LIMIT 1")
    if scan:
        s = scan[0]
        out.append(f"- **Domain:** {s.get('domain')}\n")
        out.append(f"- **TLD:** {s.get('tld')}\n")
        out.append(f"- **Queried At:** {s.get('queried_at')}\n")
        out.append(f"- **Tool:** {s.get('tool')} v{s.get('version')}\n\n")

    info = fetch(conn, """
        SELECT created, updated, expires, days_until_expiry, expiry_warning,
               status, registrar, registrar_iana_id, name_servers,
               dnssec, privacy_enabled, privacy_note
        FROM whois_info LIMIT 1
    """)
    if info:
        wi = info[0]
        out.append("### Registration Info\n")
        out.append(f"- **Created:** {wi.get('created')}\n")
        out.append(f"- **Updated:** {wi.get('updated')}\n")
        out.append(f"- **Expires:** {wi.get('expires')}\n")
        days = wi.get("days_until_expiry")
        warn = "⚠️ " if wi.get("expiry_warning") else ""
        out.append(f"- **Days Until Expiry:** {warn}{days}\n")
        out.append(f"- **Registrar:** {wi.get('registrar')} (IANA: {wi.get('registrar_iana_id')})\n")
        status = parse_json_field(wi.get("status")) or []
        out.append(f"- **Status:** {', '.join(status) if isinstance(status, list) else status}\n")
        ns = parse_json_field(wi.get("name_servers")) or []
        out.append(f"- **Name Servers:** {', '.join(ns) if isinstance(ns, list) else ns}\n")
        out.append(f"- **DNSSEC:** {wi.get('dnssec')}\n")
        out.append(f"- **Privacy Enabled:** {'Yes' if wi.get('privacy_enabled') else 'No'}\n")
        if wi.get("privacy_note"):
            out.append(f"- **Privacy Note:** {wi.get('privacy_note')}\n")

    contacts = fetch(conn, "SELECT role, name, organization, address, country, phone, email FROM whois_contacts")
    if contacts:
        out.append("\n### Contacts\n")
        out.append(md_table(
            ["Role", "Name", "Organization", "Address", "Country", "Phone", "Email"],
            [[r["role"], r["name"], r["organization"], r["address"],
              r["country"], r["phone"], r["email"]] for r in contacts]
        ))

    rdap_events = fetch(conn, "SELECT action, date FROM whois_rdap_events ORDER BY date")
    if rdap_events:
        out.append("\n### RDAP Events\n")
        out.append(md_table(
            ["Action", "Date"],
            [[r["action"], r["date"]] for r in rdap_events]
        ))

    ips = fetch(conn, """
        SELECT ip, asn, as_name, isp, country, country_code, city,
               hosting, proxy_or_vpn, usage_type, ptr, cidr
        FROM whois_ips
    """)
    if ips:
        out.append("\n### IP Information\n")
        out.append(md_table(
            ["IP", "ASN", "AS Name", "ISP", "Country", "City", "Hosting", "Proxy/VPN", "Usage", "PTR", "CIDR"],
            [
                [r["ip"], r["asn"], r["as_name"], r["isp"],
                 f"{r['country']} ({r['country_code']})", r["city"],
                 "Yes" if r["hosting"] else "No",
                 "Yes" if r["proxy_or_vpn"] else "No",
                 r["usage_type"], r["ptr"], r["cidr"]]
                for r in ips
            ]
        ))

    dns = fetch(conn, "SELECT a, aaaa, ns, mx, cname, txt, resolver FROM whois_dns LIMIT 1")
    if dns:
        d = dns[0]
        out.append("\n### DNS Intelligence\n")
        out.append(md_table(
            ["Record", "Value"],
            [[label, parse_json_field(d.get(field)) or ""]
             for field, label in [("a", "A"), ("aaaa", "AAAA"), ("ns", "NS"),
                                  ("mx", "MX"), ("cname", "CNAME"), ("txt", "TXT"),
                                  ("resolver", "Resolver")]
             if d.get(field)]
        ))

    http = fetch(conn, "SELECT url, status, final_url, headers FROM whois_http ORDER BY id")
    if http:
        out.append("\n### HTTP Probes\n")
        out.append(md_table(
            ["URL", "Status", "Final URL", "Headers"],
            [[r["url"], r["status"], r["final_url"], parse_json_field(r["headers"]) or ""]
             for r in http]
        ))

    errors = fetch(conn, "SELECT * FROM whois_errors ORDER BY id")
    if errors:
        out.append("\n### WHOIS Errors\n")
        out.append(md_table(
            [key for key in errors[0] if key != "id"],
            [[row.get(key, "") for key in errors[0] if key != "id"] for row in errors]
        ))

    cdn = fetch(conn, "SELECT behind_cdn, vendors, note, evidence FROM whois_cdn LIMIT 1")
    if cdn:
        c = cdn[0]
        out.append("\n### CDN / WAF Detection\n")
        out.append(f"- **Behind CDN:** {'Yes' if c.get('behind_cdn') else 'No'}\n")
        vendors = parse_json_field(c.get("vendors"))
        if vendors:
            out.append(f"- **Vendors:** {vendors}\n")
        waf = c.get("waf_detected")
        if waf:
            out.append(f"- **WAF Detected:** {waf}\n")
        if c.get("note"):
            out.append(f"- **Note:** {c.get('note')}\n")

    blacklist = fetch(conn, "SELECT domain, score, risk, ips_checked FROM whois_blacklist LIMIT 1")
    if blacklist:
        b = blacklist[0]
        out.append("\n### Blacklist Check\n")
        out.append(f"- **Domain:** {b.get('domain')}\n")
        out.append(f"- **Risk Score:** {b.get('score')}\n")
        out.append(f"- **Risk Level:** {b.get('risk')}\n")
        ips_checked = parse_json_field(b.get("ips_checked"))
        if ips_checked:
            out.append(f"- **IPs Checked:** {ips_checked}\n")

    bl_hits = fetch(conn, "SELECT list_name, query, response, type FROM whois_blacklist_hits")
    if bl_hits:
        out.append("\n### Blacklist Hits\n")
        out.append(md_table(
            ["List", "Query", "Response", "Type"],
            [[r["list_name"], r["query"], r["response"], r["type"]] for r in bl_hits]
        ))
    else:
        out.append("\n### Blacklist Hits\n_No blacklist hits._\n")

    cross = fetch(conn, """
        SELECT domain, registrant_email, registrant_org, nameservers,
               ips_pivoted, related_count
        FROM whois_cross_search LIMIT 1
    """)
    if cross:
        cr = cross[0]
        out.append("\n### Cross-Search (Pivot)\n")
        out.append(f"- **Registrant Email:** {cr.get('registrant_email')}\n")
        out.append(f"- **Registrant Org:** {cr.get('registrant_org')}\n")
        out.append(f"- **Related Domains Found:** {cr.get('related_count')}\n")
        pivots = parse_json_field(cr.get("ips_pivoted"))
        if pivots:
            out.append(f"- **IPs Pivoted:** {pivots}\n")

    related = fetch(conn, "SELECT domain, pivot, value, source FROM whois_related_domains")
    if related:
        out.append("\n### Related Domains\n")
        out.append(md_table(
            ["Domain", "Pivot", "Value", "Source"],
            [[r["domain"], r["pivot"], r["value"], r["source"]] for r in related]
        ))

    historical = fetch(conn, "SELECT domain, archive_first_seen, archive_last_seen, archive_source FROM whois_historical LIMIT 1")
    if historical:
        h = historical[0]
        out.append("\n### Historical Archive\n")
        out.append(f"- **First Seen:** {h.get('archive_first_seen')}\n")
        out.append(f"- **Last Seen:** {h.get('archive_last_seen')}\n")
        out.append(f"- **Source:** {h.get('archive_source')}\n")

    snapshots = fetch(conn, "SELECT date, registrar, created, expires, status, name_servers, source FROM whois_snapshots ORDER BY date")
    if snapshots:
        out.append("\n### Historical Snapshots\n")
        out.append(md_table(
            ["Date", "Registrar", "Created", "Expires", "Status", "Name Servers", "Source"],
            [[r["date"], r["registrar"], r["created"], r["expires"],
              r["status"], r["name_servers"], r["source"]] for r in snapshots]
        ))

    payload = fetch(conn, "SELECT payload FROM whois_results_payload ORDER BY id DESC LIMIT 1")
    if payload:
        out.append(json_payload_block("WHOIS Result Payload", payload[0].get("payload")))

    return "\n".join(out) + "\n"


def section_headers(conn: sqlite3.Connection) -> str:
    out = ["## HTTP Security Headers\n"]

    scan = fetch(conn, """
        SELECT domain, url, final_url, status_code, grade, score,
               records_read, responses_analyzed, timestamp
        FROM headers_scans LIMIT 1
    """)
    if scan:
        s = scan[0]
        out.append(f"- **Domain:** {s.get('domain')}\n")
        out.append(f"- **URL:** {s.get('url')}\n")
        out.append(f"- **Final URL:** {s.get('final_url')}\n")
        out.append(f"- **Status Code:** {s.get('status_code')}\n")
        out.append(f"- **Grade:** {s.get('grade')}\n")
        out.append(f"- **Score:** {s.get('score')}\n")
        out.append(f"- **Records Read:** {s.get('records_read')} | Responses Analyzed: {s.get('responses_analyzed')}\n\n")

    summary = fetch(conn, """
        SELECT module, severity, header, detail, count
        FROM headers_summary ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4
                ELSE 5 END, count DESC
    """)
    if summary:
        out.append("### Findings Summary\n")
        out.append(md_table(
            ["Module", "Severity", "Header", "Detail", "Count"],
            [
                [r["module"], severity_badge(r["severity"]), r["header"], r["detail"], r["count"]]
                for r in summary
            ]
        ))

    entries = fetch(conn, """
        SELECT source, method, url, status_code, grade, score, recommendations
        FROM headers_entries ORDER BY score ASC
    """)
    if entries:
        out.append("\n### Analyzed Entries\n")
        out.append(md_table(
            ["Source", "Method", "URL", "Status", "Grade", "Score", "Recommendations"],
            [
                [r["source"], r["method"], r["url"], r["status_code"],
                 r["grade"], r["score"], r["recommendations"]]
                for r in entries
            ]
        ))

    ws = fetch(conn, "SELECT handshakes, accepted, rejected, other_upgrades, endpoints, notes FROM headers_websocket LIMIT 1")
    if ws:
        w = ws[0]
        endpoints = parse_json_field(w.get("endpoints")) or []
        out.append("\n### WebSocket\n")
        out.append(f"- **Handshakes:** {w.get('handshakes')} | Accepted: {w.get('accepted')} | Rejected: {w.get('rejected')}\n")
        if endpoints:
            out.append(f"- **Endpoints:** {', '.join(endpoints)}\n")
        if w.get("notes"):
            out.append(f"- **Notes:** {w.get('notes')}\n")

    cookies = fetch(conn, """
        SELECT name, host, sensitive, secure, httponly, samesite,
               partitioned, is_jwt, jwt_alg, category, value_type,
               lifetime_seconds, issued_total, sent_total, distinct_values
        FROM headers_cookies ORDER BY sensitive DESC, name
    """)
    if cookies:
        out.append("\n### Cookies\n")
        out.append(md_table(
            ["Name", "Host", "Sensitive", "Secure", "HttpOnly", "SameSite", "JWT", "Category", "Lifetime (s)", "Issued", "Sent"],
            [
                [
                    r["name"], r["host"],
                    "⚠️ Yes" if r["sensitive"] else "No",
                    "✅" if r["secure"] else "❌",
                    "✅" if r["httponly"] else "❌",
                    r["samesite"] or "Not Set",
                    f"Yes ({r['jwt_alg']})" if r["is_jwt"] else "No",
                    r["category"], r["lifetime_seconds"],
                    r["issued_total"], r["sent_total"],
                ]
                for r in cookies
            ]
        ))

    cookie_findings = fetch(conn, """
        SELECT cookie, host, severity, header, detail, count
        FROM headers_cookie_findings ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
    """)
    if cookie_findings:
        out.append("\n### Cookie Findings\n")
        out.append(md_table(
            ["Cookie", "Host", "Severity", "Header", "Detail", "Count"],
            [
                [r["cookie"], r["host"], severity_badge(r["severity"]),
                 r["header"], r["detail"], r["count"]]
                for r in cookie_findings
            ]
        ))

    findings = fetch(conn, """
        SELECT entry_id, module, severity, header, detail
        FROM headers_findings ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, entry_id
    """)
    if findings:
        out.append("\n### Detailed Header Findings\n")
        out.append(md_table(
            ["Entry", "Module", "Severity", "Header", "Detail"],
            [[r["entry_id"], r["module"], severity_badge(r["severity"]),
              r["header"], r["detail"]] for r in findings]
        ))

    metadata = fetch(conn, """
        SELECT entry_id, module, key, value
        FROM headers_metadata ORDER BY entry_id, module, key
    """)
    if metadata:
        out.append("\n### Header Metadata\n")
        out.append(md_table(
            ["Entry", "Module", "Key", "Value"],
            [[r["entry_id"], r["module"], r["key"], r["value"]] for r in metadata]
        ))

    payload = fetch(conn, "SELECT payload FROM headers_results_payload ORDER BY id DESC LIMIT 1")
    if payload:
        out.append(json_payload_block("Headers Result Payload", payload[0].get("payload")))

    return "\n".join(out) + "\n"


def section_tech(conn: sqlite3.Connection) -> str:
    out = ["## Technology Fingerprinting\n"]

    waf = fetch(conn, "SELECT waf_detected, waf_names, generic_detected, generic_reason FROM tech_waf LIMIT 1")
    if waf:
        w = waf[0]
        names = parse_json_field(w.get("waf_names")) or []
        out.append("### WAF Detection\n")
        out.append(f"- **WAF Detected:** {'Yes ⚠️ — ' + ', '.join(names) if w.get('waf_detected') else 'No ✅'}\n")
        out.append(f"- **Generic WAF Detected:** {'Yes — ' + str(w.get('generic_reason')) if w.get('generic_detected') else 'No'}\n\n")

    cms = fetch(conn, "SELECT cms_detected, cms_name, cms_version, cms_url, detection_method FROM tech_cms LIMIT 1")
    if cms:
        c = cms[0]
        out.append("### CMS Detection\n")
        if c.get("cms_detected"):
            out.append(f"- **CMS:** {c.get('cms_name')} {c.get('cms_version') or ''}\n")
            out.append(f"- **URL:** {c.get('cms_url')}\n")
            out.append(f"- **Detection Method:** {c.get('detection_method')}\n")
        else:
            out.append("- **CMS Detected:** No\n")
        out.append("\n")

    favicon = fetch(conn, """
        SELECT favicon_found, favicon_url, technology_name, technology_category,
               mmh3, md5, sha1, sha256, file_format, version_in_path,
               shodan_query, fofa_query
        FROM tech_favicon LIMIT 1
    """)
    if favicon:
        f = favicon[0]
        out.append("### Favicon\n")
        out.append(f"- **Found:** {'Yes' if f.get('favicon_found') else 'No'}\n")
        if f.get("favicon_url"):
            out.append(f"- **URL:** {f.get('favicon_url')}\n")
        if f.get("technology_name"):
            out.append(f"- **Technology:** {f.get('technology_name')} ({f.get('technology_category')})\n")
        out.append(f"- **MMH3:** `{f.get('mmh3')}`\n")
        out.append(f"- **MD5:** `{f.get('md5')}`\n")
        out.append(f"- **SHA1:** `{f.get('sha1')}`\n")
        if f.get("file_format"):
            out.append(f"- **File Format:** {f.get('file_format')}\n")
        if f.get("shodan_query"):
            out.append(f"- **Shodan Query:** `{f.get('shodan_query')}`\n")
        if f.get("fofa_query"):
            out.append(f"- **FOFA Query:** `{f.get('fofa_query')}`\n")
        out.append("\n")

    technologies = fetch(conn, "SELECT name, version, category, confidence, detected_via FROM tech_technologies ORDER BY category, name")
    if technologies:
        out.append("### Detected Technologies\n")
        out.append(md_table(
            ["Name", "Version", "Category", "Confidence", "Detected Via"],
            [[r["name"], r["version"], r["category"], r["confidence"], r["detected_via"]] for r in technologies]
        ))
    else:
        out.append("### Detected Technologies\n_No technologies detected._\n")

    retire_js = fetch(conn, "SELECT library, version, script_url, has_vulnerabilities FROM tech_retire_js")
    if retire_js:
        out.append("\n### RetireJS (Vulnerable Libraries)\n")
        out.append(md_table(
            ["Library", "Version", "Script URL", "Has Vulnerabilities"],
            [
                [r["library"], r["version"], r["script_url"],
                 "⚠️ Yes" if r["has_vulnerabilities"] else "No"]
                for r in retire_js
            ]
        ))
    else:
        out.append("\n### RetireJS (Vulnerable Libraries)\n_No vulnerable libraries detected._\n")

    tech_headers = fetch(conn, "SELECT name, category, detected_via, raw_value FROM tech_headers")
    if tech_headers:
        out.append("\n### Technologies via Headers\n")
        out.append(md_table(
            ["Name", "Category", "Detected Via", "Raw Value"],
            [[r["name"], r["category"], r["detected_via"], r["raw_value"]] for r in tech_headers]
        ))

    return "\n".join(out) + "\n"


def section_social(conn: sqlite3.Connection) -> str:
    out = ["## Social & Metadata\n"]

    profiles = fetch(conn, "SELECT platform, url, source, confidence FROM social_profiles ORDER BY platform")
    if profiles:
        out.append("### Social Profiles\n")
        out.append(md_table(
            ["Platform", "URL", "Source", "Confidence"],
            [[r["platform"], r["url"], r["source"], r["confidence"]] for r in profiles]
        ))

    emails = fetch(conn, "SELECT address, source, context, verified FROM social_emails")
    if emails:
        out.append("\n### Emails Found\n")
        out.append(md_table(
            ["Address", "Source", "Context", "Verified"],
            [
                [r["address"], r["source"], r["context"],
                 "✅" if r["verified"] else "❌"]
                for r in emails
            ]
        ))

    docs = fetch(conn, "SELECT url, category, file_type, source FROM social_docs ORDER BY category, file_type")
    if docs:
        out.append("\n### Public Documents\n")
        out.append(md_table(
            ["URL", "Category", "File Type", "Source"],
            [[r["url"], r["category"], r["file_type"], r["source"]] for r in docs]
        ))

    meta = fetch(conn, "SELECT source, name, value FROM social_html_meta WHERE value != '' ORDER BY name LIMIT 100")
    if meta:
        out.append("\n### HTML Meta Tags (first 100)\n")
        out.append(md_table(
            ["Source", "Name", "Value"],
            [[r["source"], r["name"], r["value"]] for r in meta]
        ))

    return "\n".join(out) + "\n"


def section_subdomains(conn: sqlite3.Connection) -> str:
    out = ["## Subdomain Enumeration\n"]

    sources = fetch(conn, "SELECT source_name, sub_count, error FROM subdomain_sources ORDER BY sub_count DESC")
    if sources:
        out.append("### Enumeration Sources\n")
        out.append(md_table(
            ["Source", "Count", "Error"],
            [[r["source_name"], r["sub_count"], r["error"] or ""] for r in sources]
        ))

    total = fetch(conn, "SELECT COUNT(*) as cnt FROM subdomains")[0]["cnt"]
    live_https = fetch(conn, "SELECT COUNT(*) as cnt FROM subdomains WHERE https_status > 0")[0]["cnt"]
    live_http = fetch(conn, "SELECT COUNT(*) as cnt FROM subdomains WHERE http_status > 0")[0]["cnt"]
    takeover = fetch(conn, "SELECT COUNT(*) as cnt FROM subdomains WHERE takeover_provider IS NOT NULL")[0]["cnt"]

    out.append(f"\n### Statistics\n")
    out.append(f"- **Total Subdomains:** {total}\n")
    out.append(f"- **Live (HTTPS):** {live_https}\n")
    out.append(f"- **Live (HTTP):** {live_http}\n")
    out.append(f"- **Potential Takeovers:** {takeover}\n\n")

    takeover_subs = fetch(conn, """
        SELECT name, ips, takeover_provider, takeover_cname, takeover_evidence
        FROM subdomains WHERE takeover_provider IS NOT NULL
    """)
    if takeover_subs:
        out.append("### Subdomain Takeover Candidates\n")
        out.append(md_table(
            ["Subdomain", "IPs", "Provider", "CNAME", "Evidence"],
            [[r["name"], r["ips"], r["takeover_provider"],
              r["takeover_cname"], r["takeover_evidence"]] for r in takeover_subs]
        ))

    subs = fetch(conn, """
        SELECT name, ips, https_status, http_status, https_final_url,
               https_error, http_error
        FROM subdomains ORDER BY name
    """)
    if subs:
        out.append("\n### All Subdomains\n")
        out.append(md_table(
            ["Subdomain", "IPs", "HTTPS", "HTTP", "Final URL (HTTPS)", "HTTPS Error", "HTTP Error"],
            [
                [
                    r["name"], r["ips"], r["https_status"] or "", r["http_status"] or "",
                    r["https_final_url"] or "", r["https_error"] or "", r["http_error"] or ""
                ]
                for r in subs
            ]
        ))

    return "\n".join(out) + "\n"


def section_wayback(conn: sqlite3.Connection) -> str:
    out = ["## Wayback Machine\n"]

    scan = fetch(conn, "SELECT tool, timestamp FROM wayback_scans LIMIT 1")
    if scan:
        s = scan[0]
        out.append(f"- **Tool:** {s.get('tool')}\n")
        out.append(f"- **Timestamp:** {s.get('timestamp')}\n\n")

    url_count = fetch(conn, "SELECT COUNT(*) as cnt FROM wayback_urls")[0]["cnt"]
    sub_count = fetch(conn, "SELECT COUNT(*) as cnt FROM wayback_subdomains")[0]["cnt"]
    pattern_count = fetch(conn, "SELECT COUNT(*) as cnt FROM wayback_critical_patterns")[0]["cnt"]
    file_count = fetch(conn, "SELECT COUNT(*) as cnt FROM wayback_files")[0]["cnt"]

    out.append("### Summary\n")
    out.append(f"- **Total URLs Archived:** {url_count}\n")
    out.append(f"- **Subdomains Discovered:** {sub_count}\n")
    out.append(f"- **Critical Pattern Hits:** {pattern_count}\n")
    out.append(f"- **Interesting Files:** {file_count}\n\n")

    subdomains = fetch(conn, "SELECT url FROM wayback_subdomains ORDER BY url")
    if subdomains:
        out.append("### Discovered Subdomains\n")
        for r in subdomains:
            out.append(f"- {r['url']}\n")
        out.append("\n")

    patterns = fetch(conn, "SELECT pattern_name, url FROM wayback_critical_patterns ORDER BY pattern_name")
    if patterns:
        out.append("### Critical Pattern Matches\n")
        out.append(md_table(
            ["Pattern", "URL"],
            [[r["pattern_name"], r["url"]] for r in patterns]
        ))

    files = fetch(conn, "SELECT url FROM wayback_files ORDER BY url")
    if files:
        out.append("\n### Interesting Files\n")
        for r in files:
            out.append(f"- {r['url']}\n")
        out.append("\n")

    params = fetch(conn, "SELECT param_name, count, is_sensitive FROM wayback_parameters ORDER BY is_sensitive DESC, count DESC")
    if params:
        out.append("### URL Parameters\n")
        out.append(md_table(
            ["Parameter", "Count", "Sensitive"],
            [
                [r["param_name"], r["count"],
                 "⚠️ Yes" if r["is_sensitive"] else "No"]
                for r in params
            ]
        ))

    return "\n".join(out) + "\n"


def section_email(conn: sqlite3.Connection) -> str:
    out = ["## Email Security\n"]

    dns_sec = fetch(conn, "SELECT spf, dkim, dmarc, spoofing_risk, mta_sts, null_mx, bimi, dane, caa FROM email_dns_sec LIMIT 1")
    if dns_sec:
        d = dns_sec[0]
        spf = parse_json_field(d.get("spf")) or {}
        dkim = parse_json_field(d.get("dkim")) or {}
        dmarc = parse_json_field(d.get("dmarc")) or {}
        spoofing = parse_json_field(d.get("spoofing_risk")) or {}

        out.append("### DNS Security\n")
        out.append("#### SPF\n")
        if isinstance(spf, dict):
            out.append(f"- **Record:** `{spf.get('record', 'N/A')}`\n")
            out.append(f"- **All Qualifier:** `{spf.get('all_qualifier', 'N/A')}`\n")
            out.append(f"- **Include Count:** {spf.get('include_count', 0)}\n")
            spf_issues = spf.get("issues") or []
            if spf_issues:
                out.append(f"- **Issues:** {', '.join(spf_issues)}\n")
            else:
                out.append("- **Issues:** None ✅\n")
        else:
            out.append(f"- {spf}\n")

        out.append("\n#### DKIM\n")
        if isinstance(dkim, dict):
            selectors = dkim.get("found_selectors") or []
            out.append(f"- **Selectors Found:** {', '.join(selectors) if selectors else 'None'}\n")
            dkim_issues = dkim.get("issues") or []
            out.append(f"- **Issues:** {', '.join(dkim_issues) if dkim_issues else 'None ✅'}\n")
        else:
            out.append(f"- {dkim}\n")

        out.append("\n#### DMARC\n")
        if isinstance(dmarc, dict):
            out.append(f"- **Record:** `{dmarc.get('record', 'N/A')}`\n")
            out.append(f"- **Policy:** {dmarc.get('policy', 'N/A')}\n")
            out.append(f"- **Subdomain Policy:** {dmarc.get('subdomain_policy', 'N/A')}\n")
            out.append(f"- **PCT:** {dmarc.get('pct', 'N/A')}\n")
            rua = dmarc.get("rua") or []
            out.append(f"- **RUA:** {', '.join(rua) if rua else 'None'}\n")
            dmarc_issues = dmarc.get("issues") or []
            if dmarc_issues:
                for issue in dmarc_issues:
                    out.append(f"- ⚠️ {issue}\n")
            else:
                out.append("- **Issues:** None ✅\n")
        else:
            out.append(f"- {dmarc}\n")

        if isinstance(spoofing, dict):
            out.append(f"\n#### Spoofing Risk\n")
            out.append(f"- **Score:** {spoofing.get('score')}\n")
            out.append(f"- **Level:** {spoofing.get('level')}\n")

        null_mx = parse_json_field(d.get("null_mx")) or {}
        if isinstance(null_mx, dict) and null_mx.get("null_mx_present"):
            out.append("\n#### Null MX\n")
            out.append("- ⚠️ **Null MX present** — domain does not accept mail\n")

        bimi = parse_json_field(d.get("bimi"))
        if bimi:
            out.append(f"\n#### BIMI\n- {bimi}\n")

        dane_v = parse_json_field(d.get("dane"))
        if dane_v:
            out.append(f"\n#### DANE (Email)\n- {dane_v}\n")

    provider = fetch(conn, "SELECT email_provider, mail_relays, security_gateways FROM email_provider_gateways LIMIT 1")
    if provider:
        p = provider[0]
        out.append("\n### Email Provider & Gateways\n")
        out.append(f"- **Provider:** {p.get('email_provider')}\n")
        relays = parse_json_field(p.get("mail_relays"))
        gateways = parse_json_field(p.get("security_gateways"))
        if relays:
            out.append(f"- **Mail Relays:** {relays}\n")
        if gateways:
            out.append(f"- **Security Gateways:** {gateways}\n")

    service = fetch(conn, """
        SELECT port_scan, smtp_enum, catch_all, auth_mechanisms,
               open_relay, starttls_downgrade, ehlo_helo
        FROM email_service_config LIMIT 1
    """)
    if service:
        s = service[0]
        out.append("\n### SMTP Service Configuration\n")
        for field, label in [
            ("port_scan", "Port Scan"),
            ("smtp_enum", "SMTP Enum"),
            ("catch_all", "Catch-All"),
            ("auth_mechanisms", "Auth Mechanisms"),
            ("open_relay", "Open Relay"),
            ("starttls_downgrade", "STARTTLS Downgrade"),
            ("ehlo_helo", "EHLO/HELO"),
        ]:
            val = parse_json_field(s.get(field))
            if val is not None:
                out.append(f"- **{label}:** {val}\n")

    exchange = fetch(conn, "SELECT findings FROM email_exchange LIMIT 1")
    if exchange:
        findings = parse_json_field(exchange[0].get("findings"))
        if findings:
            out.append("\n### Exchange Findings\n")
            out.append(f"```json\n{json.dumps(findings, indent=2)}\n```\n")

    harvest = fetch(conn, "SELECT harvested_emails, social_patterns, conventional_emails FROM email_harvest_recon LIMIT 1")
    if harvest:
        h = harvest[0]
        harvested = parse_json_field(h.get("harvested_emails")) or []
        conventional = parse_json_field(h.get("conventional_emails")) or []
        social = parse_json_field(h.get("social_patterns")) or {}

        if harvested:
            out.append("\n### Harvested Emails\n")
            for email in harvested:
                if isinstance(email, dict):
                    out.append(f"- {email.get('address')} ({email.get('source', '')})\n")
                else:
                    out.append(f"- {email}\n")

        if conventional:
            out.append("\n### Conventional / Guessed Emails\n")
            out.append(md_table(
                ["Address", "Status", "Confidence"],
                [
                    [e.get("address"), e.get("status"), e.get("confidence")]
                    for e in conventional
                    if isinstance(e, dict)
                ]
            ))

        if social:
            out.append("\n### Social Recon\n")
            out.append(f"- **LinkedIn Found:** {'Yes' if social.get('linkedin_found') else 'No'}\n")
            out.append(f"- **GitHub Found:** {'Yes' if social.get('github_found') else 'No'}\n")

    breach_stats = fetch(conn, "SELECT severity, COUNT(*) as cnt FROM email_breaches GROUP BY severity ORDER BY cnt DESC")
    total_breaches = fetch(conn, "SELECT COUNT(*) as cnt FROM email_breaches")[0]["cnt"]

    if total_breaches > 0:
        out.append(f"\n### Breach Data\n")
        out.append(f"**Total Breach Records: {total_breaches}**\n\n")
        out.append("#### By Severity\n")
        out.append(md_table(
            ["Severity", "Count"],
            [[severity_badge(r["severity"]), r["cnt"]] for r in breach_stats]
        ))

        breach_names = fetch(conn, """
            SELECT breach_name, severity, COUNT(*) as cnt,
                   GROUP_CONCAT(DISTINCT data_classes) as classes
            FROM email_breaches
            WHERE breach_name IS NOT NULL
            GROUP BY breach_name, severity ORDER BY cnt DESC
        """)
        if breach_names:
            out.append("\n#### Named Breaches\n")
            out.append(md_table(
                ["Breach", "Severity", "Affected", "Data Classes"],
                [
                    [r["breach_name"], severity_badge(r["severity"]), r["cnt"], r["classes"]]
                    for r in breach_names
                ]
            ))

        credential_leaks = fetch(conn, """
            SELECT email, combo_line, breach_date, total_stealers
            FROM email_breaches
            WHERE combo_line IS NOT NULL AND combo_line != ''
            ORDER BY severity LIMIT 50
        """)
        if credential_leaks:
            out.append("\n#### Credential Leaks (up to 50)\n")
            out.append(md_table(
                ["Email", "Combo", "Date", "Stealers"],
                [
                    [r["email"], r["combo_line"], r["breach_date"], r["total_stealers"]]
                    for r in credential_leaks
                ]
            ))

        domain_emails = fetch(conn, """
            SELECT DISTINCT email FROM email_breaches
            WHERE email IS NOT NULL AND email != ''
            ORDER BY email
        """)
        if domain_emails:
            out.append(f"\n#### All Exposed Emails ({len(domain_emails)})\n")
            out.append(md_table(
                ["Email"],
                [[r["email"]] for r in domain_emails]
            ))

    payload = fetch(conn, "SELECT domain, payload FROM email_results_payload ORDER BY id DESC LIMIT 1")
    if payload:
        out.append(f"\n### Email Result Payload ({payload[0].get('domain')})\n")
        parsed = parse_json_field(payload[0].get("payload"))
        out.append(f"```json\n{json.dumps(parsed, indent=2, ensure_ascii=False, default=str)}\n```\n")

    return "\n".join(out) + "\n"


def build_report(conn: sqlite3.Connection, modules: list) -> str:
    domain = get_domain(conn)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Recon Report: {domain}\n",
        f"**Generated:** {now}  \n",
        f"**Modules:** {', '.join(modules)}\n",
        "\n---\n",
        "## Table of Contents\n",
    ]
    toc_map = {
        "metadata": ("Scan Metadata", "scan-metadata"),
        "dns": ("DNS", "dns"),
        "tls": ("TLS / SSL", "tls--ssl"),
        "whois": ("WHOIS", "whois"),
        "headers": ("HTTP Security Headers", "http-security-headers"),
        "tech": ("Technology Fingerprinting", "technology-fingerprinting"),
        "social": ("Social & Metadata", "social--metadata"),
        "subdomains": ("Subdomain Enumeration", "subdomain-enumeration"),
        "wayback": ("Wayback Machine", "wayback-machine"),
        "email": ("Email Security", "email-security"),
    }
    ordered = ["metadata", "dns", "tls", "whois", "headers", "tech", "social", "subdomains", "wayback", "email"]
    for key in ordered:
        if key in modules:
            label, anchor = toc_map[key]
            lines.append(f"- [{label}](#{anchor})\n")
    lines.append("\n---\n\n")

    module_funcs = {
        "metadata": section_metadata,
        "dns": section_dns,
        "tls": section_tls,
        "whois": section_whois,
        "headers": section_headers,
        "tech": section_tech,
        "social": section_social,
        "subdomains": section_subdomains,
        "wayback": section_wayback,
        "email": section_email,
    }
    for key in ordered:
        if key in modules:
            lines.append(module_funcs[key](conn))
            lines.append("\n---\n\n")

    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Convert a recon SQLite database to a Markdown report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --db scan.db --all
  %(prog)s --db scan.db --dns --tls --whois
  %(prog)s --db scan.db --email --headers --output report.md
        """,
    )
    parser.add_argument("--db", required=True, metavar="PATH", help="Path to the SQLite database file")
    parser.add_argument("--output", "-o", metavar="PATH", help="Output Markdown file (default: <domain>_report.md)")

    parser.add_argument("--all", action="store_true", help="Include all modules")
    parser.add_argument("--metadata", action="store_true", help="Scan metadata")
    parser.add_argument("--dns", action="store_true", help="DNS records and analysis")
    parser.add_argument("--tls", action="store_true", help="TLS/SSL analysis")
    parser.add_argument("--whois", action="store_true", help="WHOIS and IP info")
    parser.add_argument("--headers", action="store_true", help="HTTP security headers")
    parser.add_argument("--tech", action="store_true", help="Technology fingerprinting")
    parser.add_argument("--social", action="store_true", help="Social profiles and metadata")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    parser.add_argument("--wayback", action="store_true", help="Wayback Machine results")
    parser.add_argument("--email", action="store_true", help="Email security analysis")

    args = parser.parse_args()

    all_modules = ["metadata", "dns", "tls", "whois", "headers", "tech", "social", "subdomains", "wayback", "email"]

    if args.all:
        selected = all_modules
    else:
        selected = [m for m in all_modules if getattr(args, m, False)]

    if not selected:
        parser.print_help()
        print("\n[ERROR] No module selected. Use --all or specify at least one module flag.", file=sys.stderr)
        sys.exit(1)

    conn = db_connect(args.db)
    domain = get_domain(conn)

    output_path = args.output or f"{domain}_report.md"

    print(f"[*] Database:  {args.db}")
    print(f"[*] Domain:    {domain}")
    print(f"[*] Modules:   {', '.join(selected)}")
    print(f"[*] Output:    {output_path}")

    report = build_report(conn, selected)
    conn.close()

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    size_kb = Path(output_path).stat().st_size / 1024
    print(f"[✓] Report written: {output_path} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()