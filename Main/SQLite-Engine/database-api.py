from __future__ import annotations

import argparse
import json
import logging
import signal
import sqlite3
import sys
import time
from pathlib import Path

from flask import Flask, g, jsonify, request

try:
    from setproctitle import setproctitle
    setproctitle("DNS:DB Server")
except ImportError:
    pass

PARENT_TABLES: dict[str, dict[str, str]] = {
    "scans":                 {"label": "Scans",                  "name_col": "target"},
    "dns_records":           {"label": "DNS Records",            "name_col": "record_type"},
    "dns_axfr":              {"label": "Zone Transfers",         "name_col": "vulnerable"},
    "dns_reverse":           {"label": "Reverse DNS",            "name_col": "ip"},
    "dns_dangling":          {"label": "Dangling DNS",           "name_col": "subdomain"},
    "dns_mail":              {"label": "Mail Security",          "name_col": "spf"},
    "dns_spf_flatten":       {"label": "SPF Flattening",         "name_col": "cidr"},
    "dns_origin_ip":         {"label": "Origin IP",              "name_col": "ip"},
    "dns_doh":               {"label": "DNS over HTTPS",         "name_col": "provider"},
    "dns_dot":               {"label": "DNS over TLS",           "name_col": "provider"},
    "dns_dnssec":            {"label": "DNSSEC",                 "name_col": "chain_valid"},
    "dns_open_resolver":     {"label": "Open Resolvers",         "name_col": "nameserver"},
    "dns_ttl_anomalies":     {"label": "TTL Anomalies",          "name_col": "name"},
    "dns_module_results":    {"label": "Complete DNS Results",   "name_col": "module"},
    "subdomains":            {"label": "Subdomains",             "name_col": "name"},
    "subdomain_sources":     {"label": "Subdomain Sources",      "name_col": "source_name"},
    "social_profiles":       {"label": "Social Profiles",        "name_col": "url"},
    "social_emails":         {"label": "Social Emails",          "name_col": "address"},
    "social_html_meta":      {"label": "HTML Meta Tags",         "name_col": "name"},
    "social_docs":           {"label": "Document OSINT",         "name_col": "url"},
    "whois_scans":           {"label": "WHOIS Scans",            "name_col": "domain"},
    "whois_results_payload": {"label": "Complete WHOIS Results", "name_col": "scan_id"},
    "whois_info":            {"label": "WHOIS Info",             "name_col": "registrar"},
    "whois_contacts":        {"label": "WHOIS Contacts",         "name_col": "role"},
    "whois_dns":             {"label": "WHOIS DNS",              "name_col": "a"},
    "whois_ips":             {"label": "WHOIS IPs",              "name_col": "ip"},
    "whois_cdn":             {"label": "WHOIS CDN",              "name_col": "behind_cdn"},
    "whois_cdn_advanced":    {"label": "WHOIS CDN Advanced",     "name_col": "behind_cdn"},
    "whois_http":            {"label": "WHOIS HTTP",             "name_col": "url"},
    "whois_errors":          {"label": "WHOIS Errors",           "name_col": "error"},
    "whois_blacklist":       {"label": "WHOIS Blacklist",        "name_col": "risk"},
    "whois_blacklist_hits":  {"label": "WHOIS Blacklist Hits",   "name_col": "list_name"},
    "whois_cross_search":    {"label": "WHOIS Cross-Search",     "name_col": "domain"},
    "whois_related_domains": {"label": "WHOIS Related Domains",  "name_col": "domain"},
    "whois_historical":      {"label": "WHOIS Historical",       "name_col": "domain"},
    "whois_rdap_events":     {"label": "WHOIS RDAP Events",      "name_col": "action"},
    "whois_snapshots":       {"label": "WHOIS Snapshots",        "name_col": "date"},
    "tech_technologies":     {"label": "Technologies",           "name_col": "name"},
    "tech_favicon":          {"label": "Favicon Recon",          "name_col": "favicon_url"},
    "tech_vulnerabilities":  {"label": "JS Vulnerabilities",     "name_col": "library"},
    "tech_waf":              {"label": "WAF Detection",          "name_col": "waf_detected"},
    "tech_headers":          {"label": "Security Headers",       "name_col": "name"},
    "tech_cms":              {"label": "CMS Detection",          "name_col": "cms_name"},
    "tech_retire_js":        {"label": "Retire.js Findings",     "name_col": "library"},
    "wayback_scans":         {"label": "Wayback Scans",          "name_col": "tool"},
    "wayback_urls":          {"label": "Wayback URLs",           "name_col": "url"},
    "wayback_subdomains":    {"label": "Wayback Subdomains",     "name_col": "url"},
    "wayback_critical_patterns": {"label": "Wayback Critical Patterns", "name_col": "pattern_name"},
    "wayback_files":         {"label": "Wayback Files",          "name_col": "url"},
    "wayback_parameters":    {"label": "Wayback Parameters",     "name_col": "param_name"},
    "email_harvest_recon":   {"label": "Email Harvest Recon",    "name_col": "scan_id"},
    "email_dns_sec":         {"label": "Email DNS Sec",          "name_col": "scan_id"},
    "email_provider_gateways":{"label": "Email Providers",       "name_col": "scan_id"},
    "email_service_config":  {"label": "Email Service Config",   "name_col": "scan_id"},
    "email_breaches":        {"label": "Email Breaches",         "name_col": "email"},
    "email_results_payload":{"label": "Complete Email Results",  "name_col": "domain"},
    "headers_scans":         {"label": "Headers Scans",          "name_col": "url"},
    "headers_findings":      {"label": "Headers Findings",       "name_col": "header"},
    "headers_metadata":      {"label": "Headers Metadata",       "name_col": "key"},
    "headers_entries":       {"label": "Headers Entries",        "name_col": "url"},
    "headers_summary":       {"label": "Headers Summary",        "name_col": "header"},
    "headers_websocket":     {"label": "Headers WebSocket",      "name_col": "handshakes"},
    "headers_cookies":       {"label": "Headers Cookies",        "name_col": "name"},
    "headers_cookie_findings": {"label": "Headers Cookie Findings", "name_col": "header"},
    "headers_results_payload": {"label": "Complete Headers Results", "name_col": "scan_id"},
    # ── TLS Scanner ───────────────────────────────────────────────────────
    "tls_scans":             {"label": "TLS Scans",              "name_col": "target"},
    "tls_cert_chain":        {"label": "TLS Certificate Chain",  "name_col": "subject_cn"},
    "tls_ct_entries":        {"label": "CT Log Entries",         "name_col": "common_name"},
    "tls_ocsp":              {"label": "OCSP Status",            "name_col": "status"},
    "tls_cert_assessment":   {"label": "Cert Assessment",        "name_col": "grade"},
    "tls_protocols":         {"label": "TLS Protocols",          "name_col": "version"},
    "tls_handshake":         {"label": "TLS Handshake",          "name_col": "negotiated_version"},
    "tls_alpn":              {"label": "ALPN",                   "name_col": "supported_protocols"},
    "tls_proto_assessment":  {"label": "Protocol Assessment",    "name_col": "grade"},
    "tls_ciphers":           {"label": "Cipher Suites",          "name_col": "name"},
    "tls_cipher_assessment": {"label": "Cipher Assessment",      "name_col": "grade"},
    "tls_cipher_preference": {"label": "Cipher Preference",      "name_col": "preference_known"},
    "tls_pfs_support":       {"label": "PFS Support",            "name_col": "pfs_available"},
    "tls_ecdh_curves":       {"label": "ECDH Curves",            "name_col": "supported_curves"},
    "tls_pfs_groups":        {"label": "PFS Groups",             "name_col": "name"},
    "tls_pfs_assessment":    {"label": "PFS Assessment",         "name_col": "grade"},
    "tls_session_resumption":{"label": "Session Resumption",     "name_col": "resumption_mode"},
    "tls_headers":           {"label": "TLS Headers",            "name_col": "hsts_present"},
    "tls_fallback":          {"label": "TLS Fallback Vulns",     "name_col": "vuln_name"},
    "tls_fallback_assessment":{"label": "Fallback Assessment",   "name_col": "grade"},
    "tls_network_caa":       {"label": "CAA Records",            "name_col": "tag"},
    "tls_network_dane":      {"label": "DANE",                   "name_col": "services"},
    "tls_network_mta_sts":   {"label": "MTA-STS",               "name_col": "dns_record"},
    "tls_network_assessment":{"label": "Network Assessment",     "name_col": "grade"},
}

STANDALONE_CANDIDATES = list(PARENT_TABLES.keys())

DB_PATH: Path | None = None

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()

def _safe_ident(name: str) -> str:
    if not all(c.isalnum() or c == "_" for c in name):
        raise ValueError(f"Invalid identifier: {name!r}")
    return name

def _maybe_parse_json(value):
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("[", "{")):
            try:
                return json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                return value
    return value

def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: _maybe_parse_json(row[k]) for k in row.keys()}

def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r["name"] for r in rows]

def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f'PRAGMA table_info("{_safe_ident(table)}")').fetchall()
    return [r["name"] for r in rows]

def row_count(conn: sqlite3.Connection, table: str) -> int:
    return conn.execute(
        f'SELECT COUNT(*) AS c FROM "{_safe_ident(table)}"'
    ).fetchone()["c"]

app = Flask(__name__)
app.teardown_appcontext(close_db)

@app.before_request
def _log_start():
    g._req_started_at = time.monotonic()

@app.after_request
def _log_done(resp):
    started    = getattr(g, "_req_started_at", None)
    elapsed_ms = f"{(time.monotonic() - started) * 1000:.1f}ms" if started else "?"
    qs = f"?{request.query_string.decode()}" if request.query_string else ""
    logging.info(
        "%s %s%s -> %s (%s) [%s]",
        request.method, request.path, qs,
        resp.status_code, elapsed_ms, request.remote_addr,
    )
    return resp

@app.after_request
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

@app.errorhandler(400)
def err_400(e): return jsonify({"error": "Bad Request",           "detail": str(e)}), 400

@app.errorhandler(404)
def err_404(e): return jsonify({"error": "Not Found",             "detail": str(e)}), 404

@app.errorhandler(405)
def err_405(e): return jsonify({"error": "Method Not Allowed",    "detail": str(e)}), 405

@app.errorhandler(500)
def err_500(e): return jsonify({"error": "Internal Server Error", "detail": str(e)}), 500

@app.route("/api/health")
def api_health():
    try:
        conn   = get_db()
        tables = list_tables(conn)
        return jsonify({
            "status":      "ok",
            "db_path":     str(DB_PATH),
            "table_count": len(tables),
        })
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 500

@app.route("/api/reload", methods=["POST"])
def api_reload():
    if DB_PATH is None:
        return jsonify({"success": False, "error": "DB path not configured"}), 500
    if not DB_PATH.is_file():
        return jsonify({"success": False, "error": f"DB file not found: {DB_PATH}"}), 404
    try:
        probe  = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        tables = [
            r[0] for r in probe.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        probe.close()
    except sqlite3.Error as exc:
        return jsonify({"success": False, "error": f"DB not readable: {exc}"}), 500
    logging.info("api/reload: %d table(s) in %s", len(tables), DB_PATH)
    return jsonify({"success": True, "db_path": str(DB_PATH), "table_count": len(tables), "tables": tables})

@app.route("/api/tables")
def api_tables():
    conn       = get_db()
    all_tables = list_tables(conn)
    counts     = {t: row_count(conn, t) for t in all_tables}
    known      = set(PARENT_TABLES)
    other      = [t for t in all_tables if t not in known]
    return jsonify({
        "db_path": str(DB_PATH),
        "counts":  counts,
        "tables": [
            {"table": t, "label": PARENT_TABLES[t]["label"], "count": counts.get(t, 0)}
            for t in PARENT_TABLES if t in all_tables
        ],
        "other": [{"table": t, "count": counts.get(t, 0)} for t in other],
    })

@app.route("/api/scans")
def api_scans():
    conn = get_db()
    if "scans" not in list_tables(conn):
        return jsonify({"error": "scans table not found"}), 404
    rows = conn.execute(
        'SELECT *, rowid AS rowid FROM "scans" ORDER BY id DESC'
    ).fetchall()
    return jsonify({
        "success": True,
        "count":   len(rows),
        "scans":   [row_to_dict(r) for r in rows],
    })

@app.route("/api/list/<table>")
def api_list(table: str):
    conn = get_db()
    if table not in list_tables(conn):
        return jsonify({"error": f"Table not found: {table}"}), 404
    cols      = table_columns(conn, table)
    q         = request.args.get("q", "").strip()
    scan_id   = request.args.get("scan_id", "").strip()
    offset    = max(int(request.args.get("offset", 0)), 0)
    limit     = min(max(int(request.args.get("limit", 2000)), 1), 500_000)
    order_col = request.args.get("order", "id" if "id" in cols else cols[0])
    direction = "DESC" if request.args.get("dir", "asc").lower() == "desc" else "ASC"
    if order_col not in cols:
        order_col = "id" if "id" in cols else cols[0]
    where_clauses: list[str] = []
    params: list = []
    if scan_id:
        where_clauses.append('"scan_id" = ?')
        params.append(int(scan_id))
    if q:
        where_clauses.append(
            "(" + " OR ".join(f'"{_safe_ident(c)}" LIKE ?' for c in cols) + ")"
        )
        params.extend([f"%{q}%"] * len(cols))
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    total = conn.execute(
        f'SELECT COUNT(*) AS c FROM "{_safe_ident(table)}" {where_sql}', params
    ).fetchone()["c"]
    rows = conn.execute(
        f'SELECT *, rowid FROM "{_safe_ident(table)}" {where_sql} '
        f'ORDER BY "{_safe_ident(order_col)}" {direction} LIMIT ? OFFSET ?',
        (*params, limit, offset),
    ).fetchall()
    return jsonify({
        "table":   table,
        "columns": cols,
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "rows":    [row_to_dict(r) for r in rows],
    })

@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id: int):
    conn = get_db()
    scan_row = conn.execute(
        'SELECT * FROM "scans" WHERE id = ?', (scan_id,)
    ).fetchone()
    if scan_row is None:
        return jsonify({"error": "Scan not found"}), 404
    result = {"scan": row_to_dict(scan_row), "modules": {}}
    module_tables = [t for t in PARENT_TABLES if t != "scans"]
    existing      = set(list_tables(conn))
    for table in module_tables:
        if table not in existing:
            continue
        try:
            rows = conn.execute(
                f'SELECT * FROM "{_safe_ident(table)}" WHERE "scan_id" = ? ORDER BY id',
                (scan_id,),
            ).fetchall()
            result["modules"][table] = {
                "label": PARENT_TABLES[table]["label"],
                "rows":  [row_to_dict(r) for r in rows],
            }
            if table == "dns_ttl_anomalies":
                result["modules"][table]["findings"] = result["modules"][table]["rows"]
                result["modules"][table]["rows"] = _ttl_anomaly_rows(conn, scan_id)
        except sqlite3.OperationalError:
            continue
    return jsonify(result)

@app.route("/api/query", methods=["POST"])
def api_query():
    body = request.get_json(silent=True) or {}
    sql  = (body.get("sql") or "").strip()
    if not sql:
        return jsonify({"error": "Empty query"}), 400
    lowered = sql.lower()
    if not lowered.startswith("select"):
        return jsonify({"error": "Only SELECT statements are allowed"}), 400
    forbidden = ["insert", "update", "delete", "drop", "attach", "pragma",
                 "alter", "create", "replace", "vacuum", ";"]
    if any(tok in lowered for tok in forbidden):
        return jsonify({"error": "Query contains a forbidden keyword"}), 400
    conn = get_db()
    try:
        cur  = conn.execute(sql)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        return jsonify({
            "columns":   cols,
            "rows":      [row_to_dict(r) for r in rows],
            "row_count": len(rows),
        })
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc)}), 400

_TTL_FINDING_TYPES = {"negative_ttl": "SOA", "fast_flux": "A", "caa_missing": "CAA"}

def _ttl_anomaly_label(ttl):
    if ttl is None:
        return "UNKNOWN"
    if ttl < 60:
        return "FAST_FLUX"
    if ttl < 300:
        return "LOW_TTL"
    return "NORMAL"

def _ttl_anomaly_rows(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    existing = set(list_tables(conn))
    scan_row = conn.execute('SELECT target FROM "scans" WHERE id = ?', (scan_id,)).fetchone()
    target = scan_row["target"] if scan_row is not None else ""
    rows: list[dict] = []
    if "dns_records" in existing:
        records = conn.execute(
            'SELECT record_type, ttl, value FROM "dns_records" WHERE "scan_id" = ? ORDER BY id',
            (scan_id,),
        ).fetchall()
        for rec in records:
            rows.append({
                "id":      len(rows) + 1,
                "scan_id": scan_id,
                "name":    target,
                "type":    rec["record_type"],
                "ttl":     rec["ttl"],
                "value":   rec["value"] if rec["value"] is not None else "",
                "anomaly": _ttl_anomaly_label(rec["ttl"]),
            })
    if rows or "dns_ttl_anomalies" not in existing:
        return rows
    findings = conn.execute(
        'SELECT name, ttl, value, anomaly FROM "dns_ttl_anomalies" WHERE "scan_id" = ? ORDER BY id',
        (scan_id,),
    ).fetchall()
    for f in findings:
        check = f["name"] or ""
        rows.append({
            "id":      len(rows) + 1,
            "scan_id": scan_id,
            "name":    target,
            "type":    _TTL_FINDING_TYPES.get(check, "-"),
            "ttl":     f["ttl"],
            "value":   f["value"] if f["value"] is not None else check.replace("_", " "),
            "anomaly": f["anomaly"] or check,
        })
    return rows

def _module_response(table: str):
    conn = get_db()
    if table not in list_tables(conn):
        return jsonify({"success": False, "error": f"Table '{table}' not found"}), 404
    rows = conn.execute(f'SELECT * FROM "{_safe_ident(table)}" ORDER BY id').fetchall()
    return jsonify({
        "success": True,
        "table":   table,
        "count":   len(rows),
        "rows":    [row_to_dict(r) for r in rows],
        "meta":    {"db_path": str(DB_PATH)},
    })

@app.route("/api/records")
def api_records():       return _module_response("dns_records")

@app.route("/api/axfr")
def api_axfr():
    conn  = get_db()
    table = "dns_axfr"
    if table not in list_tables(conn):
        return jsonify({"success": False, "error": f"Table '{table}' not found"}), 404
    rows = conn.execute(f'SELECT * FROM "{_safe_ident(table)}" ORDER BY id').fetchall()
    result_rows = []
    for r in rows:
        d = row_to_dict(r)
        # Parse JSON-stored fields into proper structures
        for field in ("any_records", "soa_info", "zone_records", "notify_sources"):
            v = d.get(field)
            if isinstance(v, str):
                try:
                    d[field] = json.loads(v)
                except (json.JSONDecodeError, ValueError):
                    pass
        result_rows.append(d)
    return jsonify({
        "success": True,
        "table":   table,
        "count":   len(result_rows),
        "rows":    result_rows,
        "meta":    {"db_path": str(DB_PATH)},
    })

@app.route("/api/reverse")
def api_reverse():       return _module_response("dns_reverse")

@app.route("/api/dangling")
def api_dangling():      return _module_response("dns_dangling")

@app.route("/api/mail")
def api_mail():          return _module_response("dns_mail")

@app.route("/api/spf-flatten")
def api_spf_flatten():   return _module_response("dns_spf_flatten")

@app.route("/api/origin-ip")
def api_origin_ip():     return _module_response("dns_origin_ip")

@app.route("/api/doh")
def api_doh():           return _module_response("dns_doh")

@app.route("/api/dot")
def api_dot():           return _module_response("dns_dot")

@app.route("/api/dnssec")
def api_dnssec():        return _module_response("dns_dnssec")

@app.route("/api/open-resolver")
def api_open_resolver(): return _module_response("dns_open_resolver")

@app.route("/api/ttl-anomalies")
def api_ttl_anomalies():
    conn  = get_db()
    table = "dns_ttl_anomalies"
    if table not in list_tables(conn):
        return jsonify({"success": False, "error": f"Table '{table}' not found"}), 404
    scan_ids = [
        r["scan_id"]
        for r in conn.execute(f'SELECT DISTINCT "scan_id" FROM "{table}" ORDER BY "scan_id"').fetchall()
    ]
    rows: list[dict] = []
    for sid in scan_ids:
        for row in _ttl_anomaly_rows(conn, sid):
            row["id"] = len(rows) + 1
            rows.append(row)
    return jsonify({
        "success": True,
        "table":   table,
        "count":   len(rows),
        "rows":    rows,
        "meta":    {"db_path": str(DB_PATH)},
    })

@app.route("/api/subdomains")
def api_subdomains():
    return api_list("subdomains")

@app.route("/api/social/profiles")
def api_social_profiles():
    return api_list("social_profiles")

@app.route("/api/social/emails")
def api_social_emails():
    return api_list("social_emails")

@app.route("/api/social/html-meta")
def api_social_html_meta():
    return api_list("social_html_meta")

@app.route("/api/social/docs")
def api_social_docs():
    return api_list("social_docs")

@app.route("/api/social/summary")
def api_social_summary():
    conn    = get_db()
    tables  = set(list_tables(conn))
    scan_id = request.args.get("scan_id", "").strip()
    if scan_id:
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            return jsonify({"error": "scan_id must be an integer"}), 400
    else:
        scan_id_int = None
        for tbl in ("social_profiles", "social_emails", "social_html_meta", "social_docs"):
            if tbl in tables:
                row = conn.execute(
                    f'SELECT MAX(scan_id) AS s FROM "{_safe_ident(tbl)}"'
                ).fetchone()
                if row and row["s"] is not None:
                    scan_id_int = row["s"]
                    break
    if scan_id_int is None:
        return jsonify({"success": False, "error": "No social scan data found"}), 404
    def _count(tbl: str, extra_where: str = "", params: list | None = None) -> int:
        if tbl not in tables:
            return 0
        where = f'WHERE "scan_id" = ?' + (f" AND {extra_where}" if extra_where else "")
        return conn.execute(
            f'SELECT COUNT(*) AS c FROM "{_safe_ident(tbl)}" {where}',
            [scan_id_int, *(params or [])],
        ).fetchone()["c"]
    def _rows(tbl: str, extra_where: str = "", params: list | None = None) -> list:
        if tbl not in tables:
            return []
        where = f'WHERE "scan_id" = ?' + (f" AND {extra_where}" if extra_where else "")
        rows  = conn.execute(
            f'SELECT * FROM "{_safe_ident(tbl)}" {where} ORDER BY id',
            [scan_id_int, *(params or [])],
        ).fetchall()
        return [row_to_dict(r) for r in rows]
    profile_rows = _rows("social_profiles")
    platforms    = {}
    high_conf    = 0
    for p in profile_rows:
        platforms[p.get("platform", "Other")] = platforms.get(p.get("platform", "Other"), 0) + 1
        if p.get("confidence") == "high":
            high_conf += 1
    email_rows     = _rows("social_emails")
    unique_domains = len({e["address"].split("@")[1] for e in email_rows if "@" in (e.get("address") or "")})
    src_counts: dict = {}
    for e in email_rows:
        s = e.get("source") or "web"
        src_counts[s] = src_counts.get(s, 0) + 1
    meta_rows   = _rows("social_html_meta")
    meta_by_src: dict = {}
    for m in meta_rows:
        s = m.get("source") or "unknown"
        meta_by_src[s] = meta_by_src.get(s, 0) + 1
    doc_rows = [
        {
            "id":       r.get("id"),
            "category": r.get("category") or "Other",
            "type":     (r.get("file_type") or "").lower(),
            "url":      r.get("url") or "",
            "source":   r.get("source") or "",
        }
        for r in _rows("social_docs")
        if r.get("url")
    ]
    doc_by_cat: dict = {}
    doc_by_type: dict = {}
    for d in doc_rows:
        doc_by_cat[d["category"]] = doc_by_cat.get(d["category"], 0) + 1
        key = d["type"] or "unknown"
        doc_by_type[key] = doc_by_type.get(key, 0) + 1
    scan_row = None
    if "scans" in tables:
        r = conn.execute('SELECT * FROM "scans" WHERE id = ?', (scan_id_int,)).fetchone()
        if r:
            scan_row = row_to_dict(r)
    return jsonify({
        "success":  True,
        "scan_id":  scan_id_int,
        "scan":     scan_row,
        "profiles": {
            "total":           len(profile_rows),
            "platforms":       platforms,
            "high_confidence": high_conf,
            "low_confidence":  len(profile_rows) - high_conf,
            "rows":            profile_rows,
        },
        "emails": {
            "total":          len(email_rows),
            "unique_domains": unique_domains,
            "by_source":      src_counts,
            "rows":           email_rows,
        },
        "html_meta": {
            "total":     len(meta_rows),
            "by_source": meta_by_src,
            "rows":      meta_rows,
        },
        "documents": {
            "total":            len(doc_rows),
            "by_category":      doc_by_cat,
            "by_type":          doc_by_type,
            "requests_scanned": None,
            "bodies_scanned":   None,
            "rows":             doc_rows,
        },
    })

@app.route("/api/whois/load", methods=["GET"])
def api_whois_load():
    json_path = (
        Path(__file__).resolve().parent.parent
        / "Scan-Results" / "whois_results.json"
    )
    if not json_path.is_file():
        return jsonify({"success": False, "error": "whois_results.json not found"}), 404
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return jsonify({"success": True, "data": data})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

@app.route("/api/whois/results", methods=["GET"])
def api_whois_results():
    conn   = get_db()
    tables = set(list_tables(conn))
    if "whois_scans" in tables:
        scan_id_param = request.args.get("scan_id", "").strip()
        if scan_id_param:
            try:
                scan_id = int(scan_id_param)
            except ValueError:
                return jsonify({"success": False, "error": "scan_id must be an integer"}), 400
        else:
            row = conn.execute(
                'SELECT id FROM "whois_scans" ORDER BY id DESC LIMIT 1'
            ).fetchone()
            if row is None:
                return jsonify({"success": False, "error": "No whois scans found in database"}), 404
            scan_id = row["id"]
        scan_row = conn.execute(
            'SELECT * FROM "whois_scans" WHERE id = ?', (scan_id,)
        ).fetchone()
        if scan_row is None:
            return jsonify({"success": False, "error": f"Scan {scan_id} not found"}), 404
        if "whois_results_payload" in tables:
            payload_row = conn.execute(
                'SELECT payload FROM "whois_results_payload" WHERE scan_id = ? '
                'ORDER BY id DESC LIMIT 1',
                (scan_id,),
            ).fetchone()
            if payload_row and payload_row["payload"]:
                try:
                    complete_data = json.loads(payload_row["payload"])
                    return jsonify({
                        "success": True,
                        "source":  "db",
                        "scan_id": scan_id,
                        "data":    complete_data,
                    })
                except (TypeError, json.JSONDecodeError) as exc:
                    logging.warning("Invalid WHOIS payload for scan %s: %s", scan_id, exc)
        def _qrows(tbl):
            if tbl not in tables:
                return []
            rows = conn.execute(
                f'SELECT * FROM "{_safe_ident(tbl)}" WHERE "scan_id" = ? ORDER BY id',
                (scan_id,),
            ).fetchall()
            return [row_to_dict(r) for r in rows]
        info_rows    = _qrows("whois_info")
        contact_rows = _qrows("whois_contacts")
        dns_rows     = _qrows("whois_dns")
        ip_rows      = _qrows("whois_ips")
        cdn_rows     = _qrows("whois_cdn")
        http_rows    = _qrows("whois_http")
        error_rows   = _qrows("whois_errors")
        info    = info_rows[0] if info_rows else {}
        dns_rec = dns_rows[0]  if dns_rows  else {}
        cdn_rec = cdn_rows[0]  if cdn_rows  else {}
        contacts = {}
        for c in contact_rows:
            role = c.pop("role", None)
            c.pop("id", None); c.pop("scan_id", None)
            if role:
                contacts[role] = c
        whois_data: dict | None = None
        if info:
            def _jload(v):
                if isinstance(v, str):
                    try:
                        return json.loads(v)
                    except Exception:
                        return v
                return v
            whois_data = {
                "created":           info.get("created"),
                "updated":           info.get("updated"),
                "expires":           info.get("expires"),
                "days_until_expiry": info.get("days_until_expiry"),
                "expiry_warning":    bool(info.get("expiry_warning")),
                "status":            _jload(info.get("status")),
                "registrar":         info.get("registrar"),
                "registrar_iana_id": info.get("registrar_iana_id"),
                "name_servers":      _jload(info.get("name_servers")),
                "dnssec":            info.get("dnssec"),
                "sources":           _jload(info.get("sources")),
                "contacts":          contacts,
                "raw":               info.get("raw") or "",
            }
        privacy_data: dict | None = None
        if info:
            privacy_data = {
                "enabled":    bool(info.get("privacy_enabled")),
                "note":       info.get("privacy_note") or "",
                "indicators": _jload(info.get("privacy_indicators")),
            }
        def _jload_row(row, *keys):
            out = {}
            for k in keys:
                v = row.get(k)
                if isinstance(v, str):
                    try:
                        v = json.loads(v)
                    except Exception:
                        pass
                out[k] = v
            return out
        dns_data = None
        if dns_rec:
            dns_data = _jload_row(dns_rec, "a", "aaaa", "ns", "mx", "cname", "txt")
            dns_data["resolver"] = dns_rec.get("resolver")
        ip_intel = None
        ips_list = []
        for ip in ip_rows:
            src = ip.get("source")
            if isinstance(src, str):
                try:
                    src = json.loads(src)
                except Exception:
                    pass
            ips_list.append({**ip, "source": src,
                             "hosting":      bool(ip.get("hosting")),
                             "proxy_or_vpn": bool(ip.get("proxy_or_vpn"))})
        if ips_list:
            ip_intel = ips_list[0]
        cdn_data = None
        if cdn_rec:
            cdn_data = {
                "behind_cdn": bool(cdn_rec.get("behind_cdn")),
                "vendors":    cdn_rec.get("vendors") if isinstance(cdn_rec.get("vendors"), list)
                              else (json.loads(cdn_rec["vendors"]) if cdn_rec.get("vendors") else []),
                "note":       cdn_rec.get("note"),
                "evidence":   cdn_rec.get("evidence") if isinstance(cdn_rec.get("evidence"), dict)
                              else (json.loads(cdn_rec["evidence"]) if cdn_rec.get("evidence") else {}),
            }
        meta = row_to_dict(scan_row)
        return jsonify({
            "success":  True,
            "source":   "db",
            "scan_id":  scan_id,
            "data": {
                "tool":       meta.get("tool"),
                "version":    meta.get("version"),
                "queried_at": meta.get("queried_at"),
                "domain":     meta.get("domain"),
                "tld":        meta.get("tld"),
                "whois":      whois_data,
                "privacy":    privacy_data,
                "dns":        dns_data,
                "ips":        ips_list,
                "ip_intel":   ip_intel,
                "cdn":        cdn_data,
                "http":       http_rows,
                "errors":     [e.get("error") for e in error_rows],
            },
        })
    json_path = (
        Path(__file__).resolve().parent.parent
        / "Scan-Results" / "whois_results.json"
    )
    if not json_path.is_file():
        return jsonify({"success": False, "error": "No whois data found (DB or JSON)"}), 404
    try:
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        return jsonify({"success": True, "source": "json_file", "data": raw})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

@app.route("/api/whois/scans", methods=["GET"])
def api_whois_scans():
    conn = get_db()
    if "whois_scans" not in list_tables(conn):
        return jsonify({"success": False, "error": "whois_scans table not found"}), 404
    rows = conn.execute(
        'SELECT * FROM "whois_scans" ORDER BY id DESC'
    ).fetchall()
    return jsonify({"success": True, "count": len(rows), "scans": [row_to_dict(r) for r in rows]})

@app.route("/api/whois/cdn-advanced")
def api_whois_cdn_advanced():
    return api_list("whois_cdn_advanced")

@app.route("/api/whois/blacklist")
def api_whois_blacklist():
    return api_list("whois_blacklist")

@app.route("/api/whois/blacklist/hits")
def api_whois_blacklist_hits():
    return api_list("whois_blacklist_hits")

@app.route("/api/whois/cross-search")
def api_whois_cross_search():
    return api_list("whois_cross_search")

@app.route("/api/whois/related-domains")
def api_whois_related_domains():
    return api_list("whois_related_domains")

@app.route("/api/whois/historical")
def api_whois_historical():
    return api_list("whois_historical")

@app.route("/api/whois/rdap-events")
def api_whois_rdap_events():
    return api_list("whois_rdap_events")

@app.route("/api/whois/snapshots")
def api_whois_snapshots():
    return api_list("whois_snapshots")

@app.route("/api/tech/technologies")
def api_tech_technologies():
    return api_list("tech_technologies")

@app.route("/api/tech/favicon")
def api_tech_favicon():
    return api_list("tech_favicon")

@app.route("/api/tech/vulnerabilities")
def api_tech_vulnerabilities():
    return api_list("tech_vulnerabilities")

@app.route("/api/tech/waf")
def api_tech_waf():
    return api_list("tech_waf")

@app.route("/api/tech/headers")
def api_tech_headers():
    return api_list("tech_headers")

@app.route("/api/tech/cms")
def api_tech_cms():
    return api_list("tech_cms")

@app.route("/api/tech/retire-js")
def api_tech_retire_js():
    return api_list("tech_retire_js")

@app.route("/api/tech/summary")
def api_tech_summary():
    conn    = get_db()
    tables  = list_tables(conn)
    scan_id = request.args.get("scan_id")
    result = {}
    tech_table_map = {
        "tech_technologies":    "technologies",
        "tech_favicon":         "favicon",
        "tech_vulnerabilities": "vulnerabilities",
        "tech_waf":             "waf",
        "tech_headers":         "headers",
        "tech_cms":             "cms",
        "tech_retire_js":       "retire_js",
    }
    for table, key in tech_table_map.items():
        if table not in tables:
            result[key] = []
            continue
        try:
            q = f'SELECT * FROM "{_safe_ident(table)}"'
            params = []
            if scan_id:
                q += " WHERE scan_id = ?"
                params.append(scan_id)
            rows = conn.execute(q, params).fetchall()
            result[key] = [row_to_dict(r) for r in rows]
        except Exception as exc:
            result[key] = {"error": str(exc)}
    scan_row = None
    if "scans" in tables and scan_id:
        try:
            row = conn.execute(
                'SELECT * FROM "scans" WHERE id = ?', (scan_id,)
            ).fetchone()
            if row:
                scan_row = row_to_dict(row)
        except Exception:
            pass
    return jsonify({"success": True, "scan": scan_row, "data": result})

@app.route("/api/wayback/scans")
def api_wayback_scans():
    conn = get_db()
    if "wayback_scans" not in list_tables(conn):
        return jsonify({"success": False, "error": "wayback_scans table not found"}), 404
    rows = conn.execute('SELECT * FROM "wayback_scans" ORDER BY id DESC').fetchall()
    return jsonify({"success": True, "count": len(rows), "scans": [row_to_dict(r) for r in rows]})

@app.route("/api/wayback/urls")
def api_wayback_urls():
    return api_list("wayback_urls")

@app.route("/api/wayback/subdomains")
def api_wayback_subdomains():
    return api_list("wayback_subdomains")

@app.route("/api/wayback/critical-patterns")
def api_wayback_critical_patterns():
    return api_list("wayback_critical_patterns")

@app.route("/api/wayback/files")
def api_wayback_files():
    return api_list("wayback_files")

@app.route("/api/wayback/parameters")
def api_wayback_parameters():
    return api_list("wayback_parameters")

@app.route("/api/wayback/summary")
def api_wayback_summary():
    conn    = get_db()
    tables  = set(list_tables(conn))
    scan_id = request.args.get("scan_id", "").strip()
    if scan_id:
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            return jsonify({"error": "scan_id must be an integer"}), 400
    else:
        scan_id_int = None
        if "wayback_urls" in tables:
            row = conn.execute('SELECT MAX(scan_id) AS s FROM "wayback_urls"').fetchone()
            if row and row["s"] is not None:
                scan_id_int = row["s"]
    if scan_id_int is None:
        return jsonify({"success": False, "error": "No wayback scan data found"}), 404
    def _fetch(tbl: str, extra_where: str = "", params: list | None = None) -> list:
        if tbl not in tables:
            return []
        where = f'WHERE "scan_id" = ?' + (f" AND {extra_where}" if extra_where else "")
        rows  = conn.execute(
            f'SELECT * FROM "{_safe_ident(tbl)}" {where} ORDER BY id',
            [scan_id_int, *(params or [])],
        ).fetchall()
        return [row_to_dict(r) for r in rows]
    url_rows      = _fetch("wayback_urls")
    subdomain_rows = _fetch("wayback_subdomains")
    pattern_rows  = _fetch("wayback_critical_patterns")
    file_rows     = _fetch("wayback_files")
    param_rows    = _fetch("wayback_parameters")
    patterns_by_name: dict = {}
    for p in pattern_rows:
        name = p.get("pattern_name", "unknown")
        patterns_by_name.setdefault(name, []).append(p.get("url"))
    sensitive_params = [p for p in param_rows if p.get("is_sensitive")]
    scan_meta = None
    if "wayback_scans" in tables:
        row = conn.execute('SELECT * FROM "wayback_scans" WHERE id = ?', (scan_id_int,)).fetchone()
        if row:
            scan_meta = row_to_dict(row)
    return jsonify({
        "success":  True,
        "scan_id":  scan_id_int,
        "scan":     scan_meta,
        "urls": {
            "total": len(url_rows),
            "rows":  url_rows,
        },
        "subdomains": {
            "total": len(subdomain_rows),
            "rows":  subdomain_rows,
        },
        "critical_patterns": {
            "total":      len(pattern_rows),
            "by_pattern": patterns_by_name,
        },
        "files": {
            "total": len(file_rows),
            "rows":  file_rows,
        },
        "parameters": {
            "total":            len(param_rows),
            "sensitive_count":  len(sensitive_params),
            "sensitive":        sensitive_params,
            "rows":             param_rows,
        },
    })

@app.route("/api/email/summary")
def api_email_summary():
    conn    = get_db()
    tables  = set(list_tables(conn))
    scan_id = request.args.get("scan_id", "").strip()
    if scan_id:
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            return jsonify({"error": "scan_id must be an integer"}), 400
    else:
        scan_id_int = None
        for tbl in ("email_dns_sec", "email_harvest_recon", "email_service_config"):
            if tbl in tables:
                row = conn.execute(f'SELECT MAX(scan_id) AS s FROM "{_safe_ident(tbl)}"').fetchone()
                if row and row["s"] is not None:
                    scan_id_int = row["s"]
                    break
    if scan_id_int is None:
        return jsonify({"success": False, "error": "No email scan data found"}), 404
    scan_row = None
    domain_name = "unknown"
    if "scans" in tables:
        r = conn.execute('SELECT * FROM "scans" WHERE id = ?', (scan_id_int,)).fetchone()
        if r:
            scan_row = row_to_dict(r)
            domain_name = scan_row.get("target", "unknown")
    payload = None
    if "email_results_payload" in tables:
        payload_row = conn.execute(
            'SELECT payload FROM "email_results_payload" WHERE "scan_id" = ? ORDER BY id DESC LIMIT 1',
            (scan_id_int,),
        ).fetchone()
        if payload_row and payload_row["payload"]:
            try:
                payload = json.loads(payload_row["payload"])
            except (TypeError, json.JSONDecodeError):
                payload = None
    def _fetch_one(tbl: str):
        if tbl not in tables: return {}
        row = conn.execute(f'SELECT * FROM "{_safe_ident(tbl)}" WHERE "scan_id" = ? ORDER BY id DESC LIMIT 1', (scan_id_int,)).fetchone()
        if not row: return {}
        d = row_to_dict(row)
        d.pop("id", None)
        d.pop("scan_id", None)
        return d
    def _fetch_all(tbl: str):
        if tbl not in tables: return []
        rows = conn.execute(f'SELECT * FROM "{_safe_ident(tbl)}" WHERE "scan_id" = ? ORDER BY id', (scan_id_int,)).fetchall()
        out = []
        for r in rows:
            d = row_to_dict(r)
            d.pop("id", None)
            d.pop("scan_id", None)
            out.append(d)
        return out
    harvest_recon = _fetch_one("email_harvest_recon")
    dns_sec = _fetch_one("email_dns_sec")
    service_config = _fetch_one("email_service_config")
    provider_gateways = _fetch_one("email_provider_gateways")
    breaches_rows = _fetch_all("email_breaches")
    known_email_tables = {
        "email_harvest_recon", "email_dns_sec", "email_service_config",
        "email_provider_gateways", "email_breaches",
    }
    extra_categories: dict = {}
    for tbl in sorted(t for t in tables if t.startswith("email_") and t not in known_email_tables):
        row = _fetch_one(tbl)
        if not row:
            continue
        extra_categories[tbl[len("email_"):]] = row["data"] if set(row) == {"data"} else row
    response_results = payload if isinstance(payload, dict) else {
        **extra_categories,
        "harvest_recon": harvest_recon,
        "dns_sec": dns_sec,
        "service_config": service_config,
        "provider_gateways": provider_gateways,
        "breaches": {
            "findings": breaches_rows
        }
    }
    return jsonify({
        "success": True,
        "scan_id": scan_id_int,
        "scan": scan_row,
        "results": {
            domain_name: response_results
        }
    })

HEADERS_JSON_CANDIDATES = ("headers_results.json", "headers.json")

def _headers_scan_id(conn: sqlite3.Connection, tables: set):
    raw = request.args.get("scan_id", "").strip()
    if raw:
        try:
            return int(raw), None
        except ValueError:
            return None, (jsonify({"success": False, "error": "scan_id must be an integer"}), 400)
    if "headers_scans" not in tables:
        return None, None
    row = None
    domain = request.args.get("domain", "").strip()
    if domain:
        row = conn.execute(
            'SELECT MAX(id) AS s FROM "headers_scans" WHERE "domain" = ?', (domain,)
        ).fetchone()
    if row is None or row["s"] is None:
        row = conn.execute('SELECT MAX(id) AS s FROM "headers_scans"').fetchone()
    if row and row["s"] is not None:
        return row["s"], None
    return None, None

def _headers_rows(conn: sqlite3.Connection, tables: set, table: str, scan_id: int) -> list[dict]:
    if table not in tables:
        return []
    rows = conn.execute(
        f'SELECT * FROM "{_safe_ident(table)}" WHERE "scan_id" = ? ORDER BY id',
        (scan_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows]

def _headers_scan_row(conn: sqlite3.Connection, tables: set, scan_id: int):
    if "headers_scans" not in tables:
        return None
    row = conn.execute('SELECT * FROM "headers_scans" WHERE id = ?', (scan_id,)).fetchone()
    return row_to_dict(row) if row else None

def _headers_cookie_report(conn: sqlite3.Connection, tables: set, scan_id: int):
    cookie_rows = _headers_rows(conn, tables, "headers_cookies", scan_id)
    finding_rows = _headers_rows(conn, tables, "headers_cookie_findings", scan_id)
    if not cookie_rows and not finding_rows:
        return None
    per_cookie: dict[tuple, list] = {}
    general: list[dict] = []
    for row in finding_rows:
        item = {
            "severity": row.get("severity"),
            "header":   row.get("header"),
            "detail":   row.get("detail"),
            "count":    row.get("count") or 1,
        }
        if row.get("cookie"):
            per_cookie.setdefault((row.get("host"), row.get("cookie")), []).append(item)
        else:
            general.append(item)
    cookies = []
    category_counts: dict[str, int] = {}
    for row in cookie_rows:
        category = row.get("category")
        label = category or "uncategorized"
        category_counts[label] = category_counts.get(label, 0) + 1
        attribute_sets = row.get("attribute_sets") or []
        if not isinstance(attribute_sets, list):
            attribute_sets = []
        cookies.append({
            "name":            row.get("name"),
            "host":            row.get("host"),
            "fingerprint":     row.get("fingerprint"),
            "category":        category,
            "sensitive":       bool(row.get("sensitive")),
            "value_type":      row.get("value_type"),
            "layers":          row.get("layers") or [],
            "decoded":         json.dumps(row["decoded"], separators=(",", ":")) if isinstance(row.get("decoded"), (dict, list)) else row.get("decoded"),
            "entropy":         row.get("entropy"),
            "hash_candidates": row.get("hash_candidates") or [],
            "provider_tokens": row.get("provider_tokens") or [],
            "issued_total":    row.get("issued_total") or 0,
            "sent_total":      row.get("sent_total") or 0,
            "issued_in":       row.get("issued_in") or [],
            "sent_in":         row.get("sent_in") or [],
            "distinct_values": row.get("distinct_values") or 0,
            "values":          row.get("values") or [],
            "attribute_sets":  attribute_sets,
            "findings":        per_cookie.get((row.get("host"), row.get("name")), []),
            "jwt": {
                "is_jwt":   bool(row.get("is_jwt")),
                "alg":      row.get("jwt_alg"),
                "exp":      row.get("jwt_exp"),
                "issuer":   row.get("jwt_issuer"),
                "audience": row.get("jwt_audience"),
            },
        })
    return {"cookies": cookies, "general_findings": general, "category_counts": category_counts}

def _headers_rebuild(conn: sqlite3.Connection, tables: set, scan_id: int, scan_row: dict) -> dict:
    entries: dict[str, dict] = {}
    for row in _headers_rows(conn, tables, "headers_entries", scan_id):
        entries[str(row.get("entry_id"))] = {
            "id":          row.get("entry_id"),
            "source":      row.get("source"),
            "method":      row.get("method"),
            "url":         row.get("url"),
            "status_code": row.get("status_code"),
            "modules":     {},
            "score": {
                "grade":           row.get("grade"),
                "score":           row.get("score"),
                "recommendations": row.get("recommendations") or [],
            },
        }

    def _module(entry: dict, name: str) -> dict:
        return entry["modules"].setdefault(
            name, {"module": name, "findings": [], "metadata": {}, "error": None}
        )

    for row in _headers_rows(conn, tables, "headers_findings", scan_id):
        entry = entries.get(str(row.get("entry_id")))
        if entry is not None:
            _module(entry, row.get("module"))["findings"].append({
                "severity": row.get("severity"),
                "header":   row.get("header"),
                "detail":   row.get("detail"),
            })
    for row in _headers_rows(conn, tables, "headers_metadata", scan_id):
        entry = entries.get(str(row.get("entry_id")))
        if entry is not None:
            _module(entry, row.get("module"))["metadata"][row.get("key")] = row.get("value")
    summary = [
        {
            "module":    row.get("module"),
            "severity":  row.get("severity"),
            "header":    row.get("header"),
            "detail":    row.get("detail"),
            "count":     row.get("count"),
            "entry_ids": row.get("entry_ids") or [],
        }
        for row in _headers_rows(conn, tables, "headers_summary", scan_id)
    ]
    ws_rows = _headers_rows(conn, tables, "headers_websocket", scan_id)
    ws = ws_rows[0] if ws_rows else {}
    cookie_report = _headers_cookie_report(conn, tables, scan_id)
    rebuilt = {
        "domain":             scan_row.get("domain"),
        "intercept_files":    scan_row.get("intercept_files") or [],
        "timestamp":          scan_row.get("timestamp"),
        "elapsed_ms":         scan_row.get("elapsed_ms"),
        "records_read":       scan_row.get("records_read"),
        "responses_analyzed": scan_row.get("responses_analyzed"),
        "entries":            list(entries.values()),
        "summary":            summary,
        "websocket": {
            "totals": {
                "handshakes":     ws.get("handshakes", 0),
                "accepted":       ws.get("accepted", 0),
                "rejected":       ws.get("rejected", 0),
                "other_upgrades": ws.get("other_upgrades", 0),
            },
            "endpoints": ws.get("endpoints") or [],
            "notes":     ws.get("notes") or [],
        },
    }
    if cookie_report is not None:
        rebuilt["cookie_report"] = cookie_report
    return rebuilt

@app.route("/api/headers/scans")
def api_headers_scans():
    return api_list("headers_scans")

@app.route("/api/headers/entries")
def api_headers_entries():
    return api_list("headers_entries")

@app.route("/api/headers/findings")
def api_headers_findings():
    return api_list("headers_findings")

@app.route("/api/headers/metadata")
def api_headers_metadata():
    return api_list("headers_metadata")

@app.route("/api/headers/aggregate")
def api_headers_aggregate():
    return api_list("headers_summary")

@app.route("/api/headers/websocket")
def api_headers_websocket():
    return api_list("headers_websocket")

@app.route("/api/headers/cookies")
def api_headers_cookies():
    return api_list("headers_cookies")

@app.route("/api/headers/cookie-findings")
def api_headers_cookie_findings():
    return api_list("headers_cookie_findings")

@app.route("/api/headers/cookie-report")
def api_headers_cookie_report():
    conn   = get_db()
    tables = set(list_tables(conn))
    scan_id, err = _headers_scan_id(conn, tables)
    if err:
        return err
    if scan_id is None:
        return jsonify({"success": False, "error": "No headers scan data found"}), 404
    report = _headers_cookie_report(conn, tables, scan_id)
    if report is None:
        return jsonify({"success": False, "error": f"No cookie data stored for scan {scan_id}"}), 404
    return jsonify({"success": True, "scan_id": scan_id, "data": report})

@app.route("/api/headers/results")
def api_headers_results():
    conn   = get_db()
    tables = set(list_tables(conn))
    scan_id, err = _headers_scan_id(conn, tables)
    if err:
        return err
    if scan_id is None:
        return jsonify({"success": False, "error": "No headers scan data found"}), 404
    scan_row = _headers_scan_row(conn, tables, scan_id)
    if scan_row is None:
        return jsonify({"success": False, "error": f"Scan {scan_id} not found"}), 404
    if "headers_results_payload" in tables:
        payload_row = conn.execute(
            'SELECT payload FROM "headers_results_payload" WHERE scan_id = ? '
            'ORDER BY id DESC LIMIT 1',
            (scan_id,),
        ).fetchone()
        if payload_row and payload_row["payload"]:
            try:
                return jsonify({
                    "success": True,
                    "source":  "db",
                    "scan_id": scan_id,
                    "scan":    scan_row,
                    "data":    json.loads(payload_row["payload"]),
                })
            except (TypeError, json.JSONDecodeError) as exc:
                logging.warning("Invalid headers payload for scan %s: %s", scan_id, exc)
    data = _headers_rebuild(conn, tables, scan_id, scan_row)
    if not data["entries"]:
        return jsonify({"success": False, "error": f"No headers entries stored for scan {scan_id}"}), 404
    return jsonify({
        "success": True,
        "source":  "db_tables",
        "scan_id": scan_id,
        "scan":    scan_row,
        "data":    data,
    })

@app.route("/api/headers/load")
def api_headers_load():
    base = Path(__file__).resolve().parent.parent / "Scan-Results"
    for name in HEADERS_JSON_CANDIDATES:
        json_path = base / name
        if not json_path.is_file():
            continue
        try:
            return jsonify({
                "success": True,
                "source":  "json_file",
                "data":    json.loads(json_path.read_text(encoding="utf-8")),
            })
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500
    return jsonify({"success": False, "error": "headers results JSON file not found"}), 404

@app.route("/api/headers/summary")
def api_headers_summary():
    conn   = get_db()
    tables = set(list_tables(conn))
    scan_id, err = _headers_scan_id(conn, tables)
    if err:
        return err
    if scan_id is None:
        return jsonify({"success": False, "error": "No headers scan data found"}), 404
    return jsonify({
        "success":   True,
        "scan_id":   scan_id,
        "scan":      _headers_scan_row(conn, tables, scan_id),
        "entries":   _headers_rows(conn, tables, "headers_entries", scan_id),
        "findings":  _headers_rows(conn, tables, "headers_findings", scan_id),
        "metadata":  _headers_rows(conn, tables, "headers_metadata", scan_id),
        "aggregate": _headers_rows(conn, tables, "headers_summary", scan_id),
        "websocket": _headers_rows(conn, tables, "headers_websocket", scan_id),
        "cookies":   _headers_rows(conn, tables, "headers_cookies", scan_id),
        "cookie_findings": _headers_rows(conn, tables, "headers_cookie_findings", scan_id),
    })

# ═══════════════════════════════════════════════════════════════════════════
# TLS SCANNER ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

def _tls_scan_id(conn: sqlite3.Connection, tables: set, scan_id_param: str) -> tuple[int | None, object]:
    target_param = request.args.get("target", "").strip()
    if scan_id_param:
        try:
            return int(scan_id_param), None
        except ValueError:
            return None, jsonify({"error": "scan_id must be an integer"}), 400
    if "tls_scans" in tables:
        if target_param:
            row = conn.execute(
                'SELECT id AS s FROM "tls_scans" '
                'WHERE target = ? OR target LIKE ? '
                'ORDER BY id DESC LIMIT 1',
                (target_param, f"{target_param}:%"),
            ).fetchone()
        else:
            row = conn.execute('SELECT MAX(id) AS s FROM "tls_scans"').fetchone()
        if row and row["s"] is not None:
            return row["s"], None
    return None, None

def _tls_fetch_one(conn, tables, tbl, scan_id):
    if tbl not in tables:
        return {}
    row = conn.execute(
        f'SELECT * FROM "{_safe_ident(tbl)}" WHERE "scan_id" = ? ORDER BY id DESC LIMIT 1',
        (scan_id,),
    ).fetchone()
    if not row:
        return {}
    d = row_to_dict(row)
    d.pop("id", None); d.pop("scan_id", None)
    return d

def _tls_fetch_all(conn, tables, tbl, scan_id):
    if tbl not in tables:
        return []
    rows = conn.execute(
        f'SELECT * FROM "{_safe_ident(tbl)}" WHERE "scan_id" = ? ORDER BY id',
        (scan_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        d.pop("id", None); d.pop("scan_id", None)
        out.append(d)
    return out

@app.route("/api/tls/scans")
def api_tls_scans():
    conn = get_db()
    if "tls_scans" not in list_tables(conn):
        return jsonify({"success": False, "error": "tls_scans table not found"}), 404
    rows = conn.execute('SELECT * FROM "tls_scans" ORDER BY id DESC').fetchall()
    return jsonify({"success": True, "count": len(rows), "scans": [row_to_dict(r) for r in rows]})

@app.route("/api/tls/cert-chain")
def api_tls_cert_chain():
    return api_list("tls_cert_chain")

@app.route("/api/tls/ct-entries")
def api_tls_ct_entries():
    return api_list("tls_ct_entries")

@app.route("/api/tls/ocsp")
def api_tls_ocsp():
    return api_list("tls_ocsp")

@app.route("/api/tls/protocols")
def api_tls_protocols():
    return api_list("tls_protocols")

@app.route("/api/tls/ciphers")
def api_tls_ciphers():
    return api_list("tls_ciphers")

@app.route("/api/tls/pfs-groups")
def api_tls_pfs_groups():
    return api_list("tls_pfs_groups")

@app.route("/api/tls/fallback")
def api_tls_fallback():
    return api_list("tls_fallback")

@app.route("/api/tls/network-caa")
def api_tls_network_caa():
    return api_list("tls_network_caa")

@app.route("/api/tls/summary")
def api_tls_summary():
    """
    Full TLS scan summary — all tables joined by scan_id.
    Returns exactly the structure tls.js expects for renderAll().
    """
    conn   = get_db()
    tables = set(list_tables(conn))

    scan_id_param = request.args.get("scan_id", "").strip()
    scan_id_int, err = _tls_scan_id(conn, tables, scan_id_param)
    if err:
        return err
    if scan_id_int is None:
        return jsonify({"success": False, "error": "No TLS scan data found"}), 404

    fo  = lambda tbl: _tls_fetch_one(conn, tables, tbl, scan_id_int)
    fa  = lambda tbl: _tls_fetch_all(conn, tables, tbl, scan_id_int)

    # ── scan meta ──────────────────────────────────────────────────────────
    scan_row = None
    if "tls_scans" in tables:
        r = conn.execute('SELECT * FROM "tls_scans" WHERE id = ?', (scan_id_int,)).fetchone()
        if r:
            scan_row = row_to_dict(r)

    # ── certificates block ─────────────────────────────────────────────────
    chain_rows    = fa("tls_cert_chain")
    ct_entries    = fa("tls_ct_entries")
    ocsp          = fo("tls_ocsp")
    cert_assess   = fo("tls_cert_assessment")

    # Reconstruct CT block (queried_domain / source / total_found live on each row)
    ct_block = {}
    if ct_entries:
        first = ct_entries[0]
        ct_block = {
            "queried_domain": first.get("queried_domain"),
            "source":         first.get("source"),
            "total_found":    first.get("total_found"),
            "entries": [
                {k: v for k, v in e.items()
                 if k not in ("queried_domain", "source", "total_found")}
                for e in ct_entries
            ],
        }

    # Reconstruct chain items with nested dicts
    def _rebuild_cert(c: dict) -> dict:
        return {
            "index": c.get("chain_index"),
            "role":  c.get("role"),
            "subject": {"CN": c.get("subject_cn"), "O": c.get("subject_o"),
                        "C":  c.get("subject_c"),  "L": c.get("subject_l")},
            "issuer":  {"CN": c.get("issuer_cn"),  "O": c.get("issuer_o"),
                        "C":  c.get("issuer_c"),   "OU": c.get("issuer_ou")},
            "serial":             c.get("serial"),
            "not_before":         c.get("not_before"),
            "not_after":          c.get("not_after"),
            "days_remaining":     c.get("days_remaining"),
            "expired":            bool(c.get("expired")),
            "not_yet_valid":      bool(c.get("not_yet_valid")),
            "self_signed":        bool(c.get("self_signed")),
            "is_ca":              bool(c.get("is_ca")),
            "key": {"type": c.get("key_type"), "bits": c.get("key_bits"),
                    "weak": bool(c.get("key_weak"))},
            "signature_algorithm": c.get("signature_algorithm"),
            "fingerprints": {"sha256": c.get("fingerprint_sha256"),
                             "sha1":   c.get("fingerprint_sha1")},
            "sct_count":    c.get("sct_count"),
            "basic_constraints": {"ca": bool(c.get("basic_constraints_ca")),
                                  "path_length": c.get("basic_constraints_path_length")},
            "key_usage":          c.get("key_usage"),
            "extended_key_usage": c.get("extended_key_usage"),
            "ocsp_urls":          c.get("ocsp_urls"),
            "ca_issuer_urls":     c.get("ca_issuer_urls"),
            "sans": [{"type": "DNS", "value": v}
                     for v in (c.get("sans") or [])
                     if isinstance(c.get("sans"), list)],
        }

    certificates = {
        "chain":      [_rebuild_cert(c) for c in chain_rows],
        "ocsp":       ocsp,
        "ct":         ct_block,
        "assessment": cert_assess,
    }

    # ── protocols block ────────────────────────────────────────────────────
    proto_rows   = fa("tls_protocols")
    handshake    = fo("tls_handshake")
    alpn         = fo("tls_alpn")
    proto_assess = fo("tls_proto_assessment")

    def _rebuild_proto(p: dict) -> dict:
        cipher = None
        if p.get("cipher_name"):
            cipher = {"name": p["cipher_name"], "bits": p.get("cipher_bits")}
        return {
            "version":          p.get("version"),
            "supported":        bool(p.get("supported")),
            "rating":           p.get("rating"),
            "rating_reason":    p.get("rating_reason"),
            "cipher":           cipher,
            "handshake_time_ms": p.get("handshake_time_ms"),
            "error":            p.get("error"),
        }

    hs_cipher = ({"name": handshake.get("cipher_name"),
                  "bits": handshake.get("cipher_bits")}
                 if handshake.get("cipher_name") else None)

    protocols = {
        "protocols": [_rebuild_proto(p) for p in proto_rows],
        "handshake": {
            "negotiated_version": handshake.get("negotiated_version"),
            "cipher":             hs_cipher,
            "handshake_time_ms":  handshake.get("handshake_time_ms"),
            "session_ticket":     bool(handshake.get("session_ticket")),
        },
        "alpn": {
            "http2_supported":    bool(alpn.get("http2_supported")),
            "http11_supported":   bool(alpn.get("http11_supported")),
            "supported_protocols": alpn.get("supported_protocols"),
        },
        "assessment": proto_assess,
    }

    # ── ciphers block ──────────────────────────────────────────────────────
    cipher_rows   = fa("tls_ciphers")
    cipher_assess = fo("tls_cipher_assessment")
    cipher_pref   = fo("tls_cipher_preference")

    # Rebuild classification map from category column
    cls_map: dict[str, list] = {}
    for c in cipher_rows:
        cat = c.get("category") or "unknown"
        cls_map.setdefault(cat, []).append({
            "name":     c.get("name"),
            "protocol": c.get("protocol"),
            "bits":     c.get("bits"),
            "supported": bool(c.get("supported")),
            "pfs":      bool(c.get("pfs")),
            "strength": c.get("strength"),
            "error":    c.get("error"),
        })

    ciphers = {
        "ciphers":        cipher_rows,
        "classification": cls_map,
        "pfs_analysis": {
            "pfs_count":     cipher_assess.get("pfs_count"),
            "non_pfs_count": cipher_assess.get("non_pfs_count"),
        },
        "cipher_preference": cipher_pref,
        "assessment":     cipher_assess,
    }

    # ── pfs block ──────────────────────────────────────────────────────────
    pfs_support   = fo("tls_pfs_support")
    ecdh_curves   = fo("tls_ecdh_curves")
    session_res   = fo("tls_session_resumption")
    pfs_assess    = fo("tls_pfs_assessment")

    # groups block
    groups_rows   = fa("tls_pfs_groups")
    grp_cls_map: dict[str, list] = {}
    for g in groups_rows:
        cat = g.get("classification") or "unknown"
        grp_cls_map.setdefault(cat, []).append(g)

    pfs = {
        "pfs_support":  pfs_support,
        "ecdh_curves":  ecdh_curves,
        "dhe_params": {
            "custom_dhe_supported": bool(pfs_assess.get("custom_dhe_supported")),
            "dhe_bits":             pfs_assess.get("dhe_bits"),
            "strength":             pfs_assess.get("dhe_strength"),
        },
        "cipher_preference": cipher_pref,
        "session_resumption": session_res,
        "assessment":   pfs_assess,
    }

    groups = {
        "groups":           groups_rows,
        "classification":   grp_cls_map,
        "strength_analysis": {
            "strength_level":       pfs_assess.get("strength_level"),
            "best_ecdhe_group":     pfs_assess.get("best_ecdhe_group"),
            "best_ecdhe_bits":      pfs_assess.get("best_ecdhe_bits"),
            "best_ffdhe_group":     pfs_assess.get("best_ffdhe_group"),
            "best_ffdhe_bits":      pfs_assess.get("best_ffdhe_bits"),
            "ecdhe_strong_count":   pfs_assess.get("ecdhe_strong_count"),
            "ecdhe_obsolete_count": pfs_assess.get("ecdhe_obsolete_count"),
            "ecdhe_weak_count":     pfs_assess.get("ecdhe_weak_count"),
            "ffdhe_strong_count":   pfs_assess.get("ffdhe_strong_count"),
        },
        "dhe_params": {
            "custom_dhe_supported": bool(pfs_assess.get("custom_dhe_supported")),
            "dhe_bits":             pfs_assess.get("dhe_bits"),
            "strength":             pfs_assess.get("dhe_strength"),
        },
        "assessment": pfs_assess,
    }

    # ── headers block ──────────────────────────────────────────────────────
    hdr = fo("tls_headers")
    headers = {
        "raw_headers":  hdr.get("raw_headers"),
        "hsts": {
            "present":            bool(hdr.get("hsts_present")),
            "max_age":            hdr.get("hsts_max_age"),
            "include_subdomains": bool(hdr.get("hsts_include_subdomains")),
            "preload":            bool(hdr.get("hsts_preload")),
            "header":             hdr.get("hsts_header"),
            "error":              hdr.get("hsts_error"),
        },
        "expect_ct": {
            "present":    bool(hdr.get("expect_ct_present")),
            "max_age":    hdr.get("expect_ct_max_age"),
            "enforce":    bool(hdr.get("expect_ct_enforce")),
            "report_uri": hdr.get("expect_ct_report_uri"),
            "header":     hdr.get("expect_ct_header"),
            "error":      hdr.get("expect_ct_error"),
        },
        "hpkp": {
            "present":            bool(hdr.get("hpkp_present")),
            "pins":               hdr.get("hpkp_pins"),
            "max_age":            hdr.get("hpkp_max_age"),
            "include_subdomains": bool(hdr.get("hpkp_include_subdomains")),
            "error":              hdr.get("hpkp_error"),
        },
        "score": {
            "grade":    hdr.get("score_grade"),
            "issues":   hdr.get("score_issues"),
            "warnings": hdr.get("score_warnings"),
            "notes":    hdr.get("score_notes"),
        },
    }

    # ── fallback block ─────────────────────────────────────────────────────
    fallback_rows   = fa("tls_fallback")
    fallback_assess = fo("tls_fallback_assessment")

    vuln_dict: dict = {}
    highest_version = None
    for fb in fallback_rows:
        if not highest_version:
            highest_version = fb.get("highest_version")
        vuln_dict[fb["vuln_name"]] = {
            "vulnerable":          bool(fb.get("vulnerable")),
            "certainty":           fb.get("certainty"),
            "detail":              fb.get("detail"),
            "downgrade_attempted": fb.get("downgrade_attempted"),
            "highest_version":     fb.get("highest_version"),
        }

    fallback = {
        "highest_version":  highest_version,
        "vulnerabilities":  vuln_dict,
        "assessment":       fallback_assess,
    }

    # ── network_checks block ───────────────────────────────────────────────
    caa_rows    = fa("tls_network_caa")
    dane        = fo("tls_network_dane")
    mta_sts     = fo("tls_network_mta_sts")
    net_assess  = fo("tls_network_assessment")

    caa_summary = caa_rows[0].get("summary") if caa_rows else None
    caa_records = [
        {"tag": r.get("tag"), "value": r.get("value"),
         "flags": r.get("flags"), "critical": bool(r.get("critical"))}
        for r in caa_rows
    ]

    network_checks = {
        "caa": {
            "records": caa_records,
            "summary": caa_summary,
        },
        "dane": {
            "services":   dane.get("services"),
            "validation": dane.get("validation"),
        },
        "mta_sts": {
            "dns_record": mta_sts.get("dns_record"),
            "policy":     mta_sts.get("policy"),
            "error":      mta_sts.get("error"),
        },
        "assessment": net_assess,
    }

    # ── overall grades summary ─────────────────────────────────────────────
    grades = {
        "certificates":    cert_assess.get("grade"),
        "protocols":       proto_assess.get("grade"),
        "ciphers":         cipher_assess.get("grade"),
        "pfs":             pfs_assess.get("grade"),
        "fallback":        fallback_assess.get("grade"),
        "network":         net_assess.get("grade"),
        "headers":         hdr.get("score_grade"),
    }

    return jsonify({
        "success": True,
        "scan_id": scan_id_int,
        "scan":    scan_row,
        "grades":  grades,
        "results": {
            "certificates":  certificates,
            "protocols":     protocols,
            "ciphers":       ciphers,
            "pfs":           pfs,
            "groups":        groups,
            "headers":       headers,
            "fallback":      fallback,
            "network_checks": network_checks,
        },
    })

def _setup_logging() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

def _install_signal_handlers() -> None:
    def _shutdown(signum, _frame):
        logging.info("Signal %s received - shutting down.", signum)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

_DEFAULT_DB = (
    Path(__file__).resolve().parent.parent
    / "Scan-Results" / "scan_results.db"
)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dns_reader",
        description="Serve a DNS results SQLite database as a read-only REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python database-api.py
  python database-api.py --port 9000
  python database-api.py --db path/to/custom.db
        """,
    )
    parser.add_argument("--db",   default=str(_DEFAULT_DB),
                        help=f"Path to the .db file (default: {_DEFAULT_DB})")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=30301,
                        help="Bind port (default: 30301)")
    args = parser.parse_args(argv)
    _setup_logging()
    db_path = Path(args.db).resolve()
    if not db_path.is_file():
        logging.info("DB file not found - creating empty database: %s", db_path)
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            init = sqlite3.connect(str(db_path))
            init.execute("PRAGMA journal_mode=WAL")
            init.commit()
            init.close()
        except OSError as exc:
            print(f"ERROR: could not create '{db_path}' ({exc})", file=sys.stderr)
            return 1
    try:
        test = sqlite3.connect(str(db_path))
        test.execute("SELECT name FROM sqlite_master LIMIT 1")
        test.close()
    except sqlite3.Error as exc:
        print(f"ERROR: '{db_path}' is not a valid SQLite file ({exc})", file=sys.stderr)
        return 1
    global DB_PATH
    DB_PATH = db_path
    _install_signal_handlers()
    host = args.host
    sep  = "-" * 40
    logging.info("Oxsium Database API")
    logging.info(sep)
    logging.info("DB port  : %s", args.port)
    logging.info(sep)
    logging.info("http://%s:%s", host, args.port)
    logging.info(sep)
    app.run(host=host, port=args.port, debug=False, threaded=True, use_reloader=False)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())