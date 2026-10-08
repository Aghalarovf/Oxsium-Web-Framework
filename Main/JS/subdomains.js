const SubdomainConfig = (() => {
    const STORAGE_KEY = 'subdomain_hunter_api_keys';

    const FIELDS = [
        { id: 'cfg-key-virustotal',     key: 'virustotal' },
        { id: 'cfg-key-securitytrails', key: 'securitytrails' },
        { id: 'cfg-key-shodan',         key: 'shodan' },
        { id: 'cfg-key-censys-id',      key: 'censys_id' },
        { id: 'cfg-key-censys-secret',  key: 'censys_secret' },
        { id: 'cfg-key-urlscan',        key: 'urlscan' },
        { id: 'cfg-key-otx',            key: 'otx' },
        { id: 'cfg-key-hackertarget',   key: 'hackertarget' },
        { id: 'cfg-key-circl-user',     key: 'circl_user' },
        { id: 'cfg-key-circl-pass',     key: 'circl_pass' },
    ];

    function load() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); }
        catch { return {}; }
    }

    function getKeys() { return load(); }

    function save() {
        const data = {};
        FIELDS.forEach(({ id, key }) => {
            const el = document.getElementById(id);
            if (el && el.value.trim()) data[key] = el.value.trim();
        });
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        const status = document.getElementById('cfg-save-status');
        if (status) {
            status.textContent = 'Saved.';
            status.style.color = 'var(--green)';
            setTimeout(() => { status.textContent = ''; }, 2000);
        }
    }

    function clear() {
        localStorage.removeItem(STORAGE_KEY);
        FIELDS.forEach(({ id }) => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        const status = document.getElementById('cfg-save-status');
        if (status) {
            status.textContent = 'Cleared.';
            status.style.color = 'var(--text-dim)';
            setTimeout(() => { status.textContent = ''; }, 2000);
        }
    }

    function toggleVisibility(id) {
        const el = document.getElementById(id);
        if (!el) return;
        const btn = el.nextElementSibling;
        if (el.type === 'password') {
            el.type = 'text';
            if (btn) btn.textContent = 'hide';
        } else {
            el.type = 'password';
            if (btn) btn.textContent = 'show';
        }
    }

    function init() {
        const saved = load();
        FIELDS.forEach(({ id, key }) => {
            const el = document.getElementById(id);
            if (el && saved[key]) el.value = saved[key];
        });
    }

    return { init, save, clear, getKeys, toggleVisibility };
})();

const Subdomains = (() => {

    /* ── State ──────────────────────────────────────────────── */
    let _allRows      = [];
    let _filterText   = '';
    let _filterStatus = 'all';

    /* ── Shorthand ──────────────────────────────────────────── */
    const $ = id => document.getElementById(id);

    function _showDatabaseUnavailable() {
        const output = document.querySelector('#panel-subdomains .sub-output-wrap');
        if (!output) return;
        let pre = output.querySelector('pre');
        if (!pre) {
            pre = document.createElement('pre');
            pre.style.cssText = 'margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:11px;line-height:1.6;';
            output.innerHTML = '';
            output.appendChild(pre);
        }
        const label = document.createElement('span');
        label.style.cssText = 'color:#ff5c5c;font-weight:600;';
        label.textContent = '[ DATABASE ]';
        const value = document.createElement('span');
        value.style.color = '#d4d4d4';
        value.textContent = ' No usable results returned from the database or the JSON file\n';
        pre.append(label, value);
        output.scrollTop = output.scrollHeight;
        if (typeof UI !== 'undefined' && UI.toast) UI.toast('Database results unavailable', 'error');
    }

    /* ────────────────────────────────────────────────────────
       SOURCE TAG TOGGLES
    ──────────────────────────────────────────────────────── */
    function initSourceTags() {
        document.querySelectorAll('.source-tag').forEach(btn => {
            btn.addEventListener('click', () => btn.classList.toggle('active'));
        });
    }

    /* ────────────────────────────────────────────────────────
       FILTER PILLS & TEXT FILTER
    ──────────────────────────────────────────────────────── */
    function initFilters() {
        const input = $('sub-filter-input');
        if (input) {
            input.addEventListener('input', e => {
                _filterText = e.target.value.toLowerCase();
                renderTable();
            });
        }

        document.querySelectorAll('#sub-status-filters .filter-pill').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('#sub-status-filters .filter-pill')
                    .forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                _filterStatus = btn.dataset.filter;
                renderTable();
            });
        });
    }

    /* ────────────────────────────────────────────────────────
       HELPERS — badges / labels
    ──────────────────────────────────────────────────────── */
    function statusBadge(code) {
        if (!code && code !== 0) return '<span class="status-err">--</span>';
        if (typeof code === 'string') return `<span class="status-err">${code}</span>`;
        const cls = code < 300 ? 'status-2xx'
                  : code < 400 ? 'status-3xx'
                  : code < 500 ? 'status-4xx'
                  :              'status-5xx';
        return `<span class="status-badge ${cls}">${code}</span>`;
    }

    /* ────────────────────────────────────────────────────────
       RENDER — SUMMARY STATS
    ──────────────────────────────────────────────────────── */
    function renderSummary(data) {
        const total    = data.total || 0;
        const resolved = data.resolve_summary?.resolved ?? '--';
        const nxdomain = data.resolve_summary ? (total - data.resolve_summary.resolved) : '--';
        const uniqueIPs= data.resolve_summary?.unique_ips?.length ?? '--';
        const alive    = data.status_summary?.alive ?? '--';
        const sources  = Object.values(data.sources || {}).filter(s => s.count > 0).length;

        const set = (id, val) => { const el = $(id); if (el) el.textContent = val; };
        set('sub-stat-total',      total);
        set('sub-stat-resolved',   resolved);
        set('sub-stat-dead',       nxdomain);
        set('sub-stat-alive',      alive);
        set('sub-stat-unique-ips', uniqueIPs);
        set('sub-stat-sources',    sources);

        const badge = $('sub-summary-badge');
        if (badge) {
            badge.textContent = total;
            badge.className   = total > 0 ? 'dns-section-badge ok' : 'dns-section-badge dim';
        }

        /* per-source breakdown grid */
        const grid = $('sub-source-grid');
        if (!grid || !data.sources) return;

        grid.innerHTML = Object.entries(data.sources)
            .sort(([, a], [, b]) => (b.count || 0) - (a.count || 0))
            .map(([name, src]) => {
                const hasErr = !!src.error;
                return `<div class="source-item">
                    <span class="source-item-name">${name}</span>
                    ${hasErr
                        ? `<span class="source-item-err" title="${src.error}">ERR</span>`
                        : `<span class="source-item-count">${src.count || 0}</span>`}
                </div>`;
            }).join('');
    }

    /* ────────────────────────────────────────────────────────
       RENDER — SUBDOMAIN TABLE
    ──────────────────────────────────────────────────────── */
    function renderTable() {
        const body  = $('sub-table-body');
        const badge = $('sub-table-badge');
        if (!body) return;

        let rows = _allRows;

        /* text filter */
        if (_filterText) {
            rows = rows.filter(r =>
                r.subdomain.toLowerCase().includes(_filterText) ||
                (r.ips || []).some(ip => ip.includes(_filterText))
            );
        }

        /* status filter */
        if (_filterStatus === 'resolved') {
            rows = rows.filter(r => r.ips && r.ips.length > 0);
        } else if (_filterStatus === 'alive') {
            rows = rows.filter(r => r.https !== null || r.http !== null);
        } else if (_filterStatus === 'nxdomain') {
            rows = rows.filter(r => !r.ips || r.ips.length === 0);
        }

        /* sort: 2xx → 3xx → 4xx → 5xx → ERR → null (–) */
        function bestCode(r) {
            const https = r.https, http = r.http;
            if (https === null && http === null) return null;
            if (https === null) return http;
            if (http  === null) return https;
            function rank(c) {
                if (typeof c === 'string') return 9000;
                if (c < 300) return c;
                if (c < 400) return 1000 + c;
                if (c < 500) return 2000 + c;
                return 3000 + c;
            }
            return rank(https) <= rank(http) ? https : http;
        }
        function sortKey(r) {
            const c = bestCode(r);
            if (c === null) {
                /* no HTTP status code: IP-resolved subdomains float above NXDOMAIN */
                return (r.ips && r.ips.length > 0) ? 99999 : 999999;
            }
            if (typeof c === 'string') return 9000;
            if (c < 300) return c;
            if (c < 400) return 1000 + c;
            if (c < 500) return 2000 + c;
            return 3000 + c;
        }
        rows = rows.slice().sort((a, b) => sortKey(a) - sortKey(b));

        if (badge) {
            badge.textContent = rows.length;
            badge.className   = rows.length > 0 ? 'dns-section-badge ok' : 'dns-section-badge dim';
        }

        if (!rows.length) {
            body.innerHTML = `<div class="data-empty">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18">
                  <rect x="2" y="3" width="20" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/>
                  <path d="M5 3v10M2 7h20" stroke="currentColor" stroke-width="1.3"/>
                </svg>
                <span>No results match the current filter</span>
            </div>`;
            return;
        }

        body.innerHTML = rows.map(r => {
            /* ── IP Address: max 2 IPs, comma separated ── */
            let ipLabel;
            if (r.ips?.length) {
                const shown   = r.ips.slice(0, 2).join(', ');
                const extra   = r.ips.length > 2 ? ` <span style="color:var(--text-dim);font-size:9px;">+${r.ips.length - 2}</span>` : '';
                ipLabel = `<span style="font-family:var(--mono);font-size:11px;">${shown}</span>${extra}`;
            } else {
                ipLabel = `<span style="color:var(--text-dim);opacity:.6;">${r.dns_error || 'NXDOMAIN'}</span>`;
            }

            function codeRank(c) {
                if (c === null || c === undefined) return 99;
                if (typeof c === 'string')          return 90;
                if (c < 300) return 1;
                if (c < 400) return 2;
                if (c < 500) return 3;
                return 4;
            }
            const https = r.https;
            const http  = r.http;
            let bc;
            if (https === null && http === null) {
                bc = null;
            } else if (https === null) {
                bc = http;
            } else if (http === null) {
                bc = https;
            } else {
                bc = codeRank(https) <= codeRank(http) ? https : http;
            }

            const statusCell = statusBadge(bc);

            return `<div class="sub-row">
                <div class="sub-cell sub-cell-name" style="flex:2.2;min-width:0;">${r.subdomain}</div>
                <div class="sub-cell sub-cell-ip"   style="flex:1.5;min-width:0;">${ipLabel}</div>
                <div class="sub-cell sub-cell-status" style="width:130px;flex-shrink:0;display:flex;justify-content:center;">${statusCell}</div>
            </div>`;
        }).join('');
    }

    /* ────────────────────────────────────────────────────────
       LOAD DATA  (called after scan completes or from external module)
    ──────────────────────────────────────────────────────── */
    function loadFromData(data) {
        renderSummary(data);

        _allRows = (data.subdomains || []).map(sub => {
            const h       = data.hosts?.[sub];
            const checks  = h?.checks || [];
            const httpsChk = checks.find(c => c.scheme === 'https');
            const httpChk  = checks.find(c => c.scheme === 'http');

            const sources = Object.entries(data.sources || {})
                .filter(([, s]) => (s.subdomains || []).includes(sub))
                .map(([name]) => name);

            return {
                subdomain       : sub,
                ips             : h?.ips       || [],
                dns_error       : h?.dns_error || null,
                https           : httpsChk?.status ?? (httpsChk?.error ? httpsChk.error : null),
                http            : httpChk?.status  ?? (httpChk?.error  ? httpChk.error  : null),
                https_final_url : httpsChk?.final_url || null,
                http_final_url  : httpChk?.final_url  || null,
                cname_chain     : h?.cname_chain || [],
                takeover_provider: null,
                sources,
            };
        });

        renderTable();
        if (typeof DomainMap !== 'undefined') DomainMap.render(_allRows);
    }

    /* ────────────────────────────────────────────────────────
       LOAD FROM DATABASE API
    ──────────────────────────────────────────────────────── */
    async function loadFromDB(scanId) {
        const DB_API_BASE = 'http://127.0.0.1:30301';
        const body = $('sub-table-body');
        if (body) {
            body.innerHTML = `<div class="data-empty">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" opacity=".4" style="animation:spin 1s linear infinite;">
                  <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.5" stroke-dasharray="30 10"/>
                </svg>
                <span>Loading from database...</span>
            </div>`;
        }

        try {
            const qsSub = scanId ? `?scan_id=${scanId}&limit=50000` : '?limit=50000';
            const subRes  = await fetch(`${DB_API_BASE}/api/subdomains${qsSub}`);
            const subData = await subRes.json();

            if (!subData.rows || !subData.rows.length) {
                if (body) body.innerHTML = `<div class="data-empty"><span>No subdomain data found in database</span></div>`;
                _showDatabaseUnavailable();
                return false;
            }

            let sourcesMap = {};
            try {
                const sid = scanId || (subData.rows[0]?.scan_id);
                if (sid) {
                    const srcRes  = await fetch(`${DB_API_BASE}/api/list/subdomain_sources?scan_id=${sid}&limit=1000`);
                    const srcData = await srcRes.json();
                    if (srcData.rows) {
                        srcData.rows.forEach(s => {
                            sourcesMap[s.source_name] = { count: s.sub_count, error: s.error };
                        });
                    }
                }
            } catch (_) {}

            function safeArr(v) {
                if (Array.isArray(v)) return v;
                if (typeof v === 'string' && v.trim().startsWith('[')) {
                    try { return JSON.parse(v); } catch (_) {}
                }
                return [];
            }

            const rows     = subData.rows;
            const resolved = rows.filter(r => safeArr(r.ips).length > 0).length;
            const nxdomain = rows.filter(r => safeArr(r.ips).length === 0).length;
            const alive    = rows.filter(r => r.https_status !== null || r.http_status !== null).length;

            const allIps = new Set();
            rows.forEach(r => safeArr(r.ips).forEach(ip => allIps.add(ip)));

            const set = (id, val) => { const el = $(id); if (el) el.textContent = val; };
            set('sub-stat-total',      rows.length);
            set('sub-stat-resolved',   resolved);
            set('sub-stat-dead',       nxdomain);
            set('sub-stat-alive',      alive);
            set('sub-stat-unique-ips', allIps.size);
            set('sub-stat-sources',    Object.values(sourcesMap).filter(s => (s.count || 0) > 0).length);

            const summaryBadge = $('sub-summary-badge');
            if (summaryBadge) {
                summaryBadge.textContent = rows.length;
                summaryBadge.className   = rows.length > 0 ? 'dns-section-badge ok' : 'dns-section-badge dim';
            }

            const grid = $('sub-source-grid');
            if (grid && Object.keys(sourcesMap).length) {
                grid.innerHTML = Object.entries(sourcesMap)
                    .sort(([, a], [, b]) => (b.count || 0) - (a.count || 0))
                    .map(([name, src]) => {
                        const hasErr = !!src.error;
                        return `<div class="source-item">
                            <span class="source-item-name">${name}</span>
                            ${hasErr
                                ? `<span class="source-item-err" title="${src.error}">ERR</span>`
                                : `<span class="source-item-count">${src.count || 0}</span>`}
                        </div>`;
                    }).join('');
            }

            _allRows = rows.map(r => ({
                subdomain        : r.name,
                ips              : safeArr(r.ips),
                dns_error        : r.dns_error        || null,
                https            : r.https_status,
                http             : r.http_status,
                https_final_url  : r.https_final_url  || null,
                http_final_url   : r.http_final_url   || null,
                https_error      : r.https_error      || null,
                http_error       : r.http_error       || null,
                cname_chain      : safeArr(r.cname_chain),
                takeover_provider: r.takeover_provider || null,
                takeover_cname   : r.takeover_cname   || null,
                sources          : [],
            }));

            renderTable();
            if (typeof DomainMap !== 'undefined') DomainMap.render(_allRows);
            window.markPanelComplete?.('panel-subdomains', 'Subdomains');
            return true;

        } catch (err) {
            if (body) body.innerHTML = '<div class="data-empty"><span style="color:var(--red,#f87171);">Database results unavailable</span></div>';
            _showDatabaseUnavailable();
            console.error('[Subdomains.loadFromDB]', err);
            return false;
        }
    }

    /* ────────────────────────────────────────────────────────
       EXPORT / COPY
    ──────────────────────────────────────────────────────── */
    function exportResults() {
        if (!_allRows.length) return;
        const lines = _allRows.map(r =>
            `${r.subdomain}\t${(r.ips || []).join(',') || r.dns_error || 'NXDOMAIN'}`
        );
        const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
        const a    = Object.assign(document.createElement('a'), {
            href     : URL.createObjectURL(blob),
            download : 'subdomains.txt',
        });
        a.click();
    }

    function copyAll() {
        if (!_allRows.length) return;
        navigator.clipboard.writeText(_allRows.map(r => r.subdomain).join('\n'));
    }

    async function _populateScanSelector(currentScanId) {
        const DB_API_BASE = 'http://127.0.0.1:30301';
        const sel         = $('sub-scan-selector');
        const placeholder = $('sub-scan-selector-placeholder');
        if (!sel) return;
        try {
            const res  = await fetch(`${DB_API_BASE}/api/scans`);
            const data = await res.json();
            if (!data.scans || !data.scans.length) {
                if (placeholder) placeholder.textContent = 'No scans found in DB';
                return;
            }
            sel.innerHTML = data.scans
                .filter(s => s.id !== undefined)
                .map(s => {
                    const ts = (s.timestamp || '').slice(0,16).replace('T',' ');
                    return `<option value="${s.id}" ${s.id == currentScanId ? 'selected' : ''}>#${s.id} ${s.target} — ${ts}</option>`;
                })
                .join('');
            sel.style.display = '';
            if (placeholder) placeholder.style.display = 'none';
        } catch (_) {
            if (placeholder) placeholder.textContent = 'DB API offline (port 30301)';
        }
    }

    /* ────────────────────────────────────────────────────────
       RESET — clear leftover results before a new scan starts
    ──────────────────────────────────────────────────────── */
    function reset() {
        _allRows      = [];
        _filterText   = '';
        _filterStatus = 'all';

        const filterInput = $('sub-filter-input');
        if (filterInput) filterInput.value = '';
        document.querySelectorAll('#sub-status-filters .filter-pill').forEach(b => b.classList.remove('active'));
        document.querySelector('#sub-status-filters .filter-pill[data-filter="all"]')?.classList.add('active');

        const set = (id, val) => { const el = $(id); if (el) el.textContent = val; };
        set('sub-stat-total',      '--');
        set('sub-stat-resolved',   '--');
        set('sub-stat-dead',       '--');
        set('sub-stat-alive',      '--');
        set('sub-stat-unique-ips', '--');
        set('sub-stat-sources',    '--');

        const summaryBadge = $('sub-summary-badge');
        if (summaryBadge) { summaryBadge.textContent = '--'; summaryBadge.className = 'dns-section-badge dim'; }

        const sourceGrid = $('sub-source-grid');
        if (sourceGrid) {
            sourceGrid.innerHTML = `<div class="data-empty" style="grid-column:1/-1;padding:16px 0;">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18"><rect x="2" y="3" width="20" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/><path d="M5 7h14M5 12h10M5 17h6" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
                <span>Run enumeration to see per-source results</span>
            </div>`;
        }

        const tableBadge = $('sub-table-badge');
        if (tableBadge) { tableBadge.textContent = '--'; tableBadge.className = 'dns-section-badge dim'; }

        const tableBody = $('sub-table-body');
        if (tableBody) {
            tableBody.innerHTML = `<div class="data-empty">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18"><rect x="2" y="3" width="20" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/><path d="M5 3v10M2 7h20" stroke="currentColor" stroke-width="1.3"/></svg>
                <span>No subdomains found yet — run enumeration</span>
            </div>`;
        }

        if (typeof DomainMap !== 'undefined') DomainMap.render([]);
    }

    /* ────────────────────────────────────────────────────────
       INIT
    ──────────────────────────────────────────────────────── */
    const DEFAULT_SUB_TAB = 'sub-panel-subdomains';

    function _activateSubTab(tabId) {
        const bar    = document.getElementById('subdomain-subtab-bar');
        const target = document.getElementById(tabId);
        if (!bar || !target) return;
        document.querySelectorAll('#panel-subdomains .tls-sub-panel').forEach(p => p.classList.remove('active'));
        bar.querySelectorAll('.tls-subtab-btn').forEach(b =>
            b.classList.toggle('active', b.getAttribute('data-subtab') === tabId));
        target.classList.add('active');
    }

    function showDefaultTab() {
        _activateSubTab(DEFAULT_SUB_TAB);
        const summary = document.getElementById('sec-sub-summary');
        if (summary) summary.classList.remove('collapsed');
    }

    function init() {
        SubdomainConfig.init();
        initSourceTags();
        initFilters();

        $('sub-export-btn')?.addEventListener('click', exportResults);
        $('sub-copy-btn')  ?.addEventListener('click', copyAll);

        const sel = $('sub-scan-selector');
        if (sel) {
            sel.addEventListener('change', () => {
                const sid = parseInt(sel.value);
                if (sid) loadFromDB(sid);
            });
        }

        const dbBtn = $('sub-load-db-btn');
        if (dbBtn) {
            dbBtn.addEventListener('click', async () => {
                dbBtn.disabled = true;
                try {
                    const sel2 = $('sub-scan-selector');
                    const sid = sel2 ? parseInt(sel2.value) : null;
                    await loadFromDB(sid || null);
                } finally {
                    dbBtn.disabled = false;
                }
            });
        }

        document.addEventListener('click', function(e) {
            const subtabBtn = e.target.closest('#subdomain-subtab-bar .tls-subtab-btn');
            if (!subtabBtn) return;
            const tabId = subtabBtn.getAttribute('data-subtab');
            if (tabId) _activateSubTab(tabId);
        });

        showDefaultTab();
    }

    return { init, loadFromData, loadFromDB, reset, showDefaultTab };

})();


/* ═══════════════════════════════════════════════════════════════
   SubdomainScanController
   ──────────────────────────────────────────────────────────────
   Flow:
     1. GUI → START SCAN  (sub-start-btn)
     2. /api/target/set   (connection.py :30300)
     3. /api/subdomain/scan (connection.py :30300) → background job
        a. subdomain-hunter.py → .json file
        b. database-manager.py → .db file
        c. database-api.py /api/reload signal
        d. job.status = 'done', job.db_ready = true
     4. /api/subdomain/job/<job_id> polling
     5. On status='done':
        • db_ready=true  → fetch from database-api.py (:30301) and render
        • db_ready=false → show error (no fallback — same as DNS-enum)
═══════════════════════════════════════════════════════════════ */
const SubdomainScanController = (() => {

    const API_BASE      = 'http://127.0.0.1:30300';
    const POLL_INTERVAL = 2000;
    const POLL_TIMEOUT  = 1800000;

    let _scanning   = false;
    let _pollTimer  = null;
    let _pollStart  = 0;
    let _currentJob = null;
    let _aborted    = false;

    const $ = id => document.getElementById(id);

    const OUT_GREEN = '#3ddc84';
    const OUT_RED   = '#ff4d4d';
    const OUT_VALUE = '#d4d4d4';

    // ─────────────────────────── Output console ───────────────

    function _outputEl() {
        return document.querySelector('#panel-subdomains .sub-output-wrap');
    }

    function _outputPre() {
        const el = _outputEl();
        if (!el) return null;
        let pre = el.querySelector('pre');
        if (!pre) {
            pre = document.createElement('pre');
            pre.style.cssText = 'margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:11px;line-height:1.6;';
            el.innerHTML = '';
            el.appendChild(pre);
        }
        return pre;
    }

    function _appendLine(text, color) {
        const pre = _outputPre();
        if (!pre) return;
        const span = document.createElement('span');
        span.style.color = color || 'var(--text-sec)';
        span.textContent = text + '\n';
        pre.appendChild(span);
        _outputEl().scrollTop = _outputEl().scrollHeight;
    }

    function _appendLabeled(label, value, labelColor) {
        const pre = _outputPre();
        if (!pre) return;
        const tag = document.createElement('span');
        tag.style.color = labelColor;
        tag.style.fontWeight = '600';
        tag.textContent = `[ ${label} ]`;
        const val = document.createElement('span');
        val.style.color = OUT_VALUE;
        val.textContent = ` ${value}\n`;
        pre.appendChild(tag);
        pre.appendChild(val);
        _outputEl().scrollTop = _outputEl().scrollHeight;
    }

    function _appendScanResult(ok, text) {
        _appendLabeled('SCAN', text, ok ? OUT_GREEN : OUT_RED);
    }

    function _appendSummary(items) {
        const pre = _outputPre();
        if (!pre) return;
        const width = Math.max(...items.map(i => i[0].length));
        const head = document.createElement('span');
        head.style.color = OUT_GREEN;
        head.style.fontWeight = '600';
        head.textContent = '[ DATABASE ]';
        const headText = document.createElement('span');
        headText.style.color = OUT_VALUE;
        headText.textContent = ' Loaded from database\n';
        pre.appendChild(head);
        pre.appendChild(headText);
        items.forEach((item, idx) => {
            const last = idx === items.length - 1;
            const branch = document.createElement('span');
            branch.style.color = 'var(--text-dim)';
            branch.textContent = `  ${last ? '└─' : '├─'} ${item[0].padEnd(width)}  `;
            const count = document.createElement('span');
            count.style.color = item[1] > 0 ? OUT_GREEN : 'var(--text-dim)';
            count.textContent = `${String(item[1]).padStart(4)}\n`;
            pre.appendChild(branch);
            pre.appendChild(count);
        });
        _outputEl().scrollTop = _outputEl().scrollHeight;
    }

    function _clearOutput() {
        const el = _outputEl();
        if (el) el.innerHTML = '<span class="output-placeholder">// Output will appear here when scan is running...</span>';
    }

    function _setSidebarCompletion(completed) {
        const item = document.querySelector('.nav-item[data-panel="panel-subdomains"]');
        const count = item?.querySelector('.nav-count');
        if (!count) return;
        count.textContent = completed ? '✓' : '--';
        count.classList.toggle('dns-enum-complete', completed);
        count.setAttribute('aria-label', completed ? 'Subdomains completed' : 'Subdomains not completed');
    }

    function _toast(msg, type) {
        if (typeof UI !== 'undefined' && UI.toast) { UI.toast(msg, type); return; }
        console.log(`[${type}] ${msg}`);
    }

    // ─────────────────────────── Button state ────────────────

    function _setBtnState(scanning) {
        const scanningHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite">
                 <circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6"
                         stroke-dasharray="10 6" stroke-linecap="round"/>
               </svg> SCANNING…`;
        const idleHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none">
                 <circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.4"/>
                 <path d="M11 11l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
               </svg> Scan Subdomains`;

        [$('sub-start-btn'), $('sub-scan-btn')].forEach(btn => {
            if (!btn) return;
            btn.disabled      = scanning;
            btn.style.opacity = scanning ? '0.55' : '';
            btn.innerHTML     = scanning ? scanningHTML : idleHTML;
        });
        const stopBtn = $('sub-stop-btn');
        if (stopBtn) stopBtn.disabled = !scanning;
    }

    // ─────────────────────────── Form inputs ─────────────────

    function _collectInputs() {
        const v = id => ($(`${id}`)?.value?.trim() || '');
        const domain  = v('sub-input-domain') || v('input-domain');
        const proxy   = v('input-proxy');
        const activeBtn = document.querySelector('#sub-workers-group .dns-thread-btn-active');
        const workers = activeBtn ? parseInt(activeBtn.dataset.val) : 10;
        const takeover   = document.getElementById('sub-opt-takeover')?.checked   === true;
        const resolve    = document.getElementById('sub-opt-resolve')?.checked    === true;
        const checkLive  = document.getElementById('sub-opt-check-live')?.checked === true;
        const wildcardFilterEl = document.getElementById('sub-opt-wildcard-filter');
        const wildcardFilter   = wildcardFilterEl ? wildcardFilterEl.checked === true : true;
        return { domain, proxy, workers, takeover, resolve, checkLive, wildcardFilter };
    }

    function _buildTargetPayload(vals) {
        const raw = vals.domain;
        if (!raw) return null;
        const url     = raw.startsWith('http') ? raw : `https://${raw}`;
        const payload = { url };
        if (vals.proxy) payload.proxy = vals.proxy;
        return payload;
    }

    function _buildScanPayload(vals) {
        return {
            workers:         vals.workers,
            takeover:        vals.takeover,
            resolve_dns:     vals.resolve,
            check_live:      vals.checkLive,
            wildcard_filter: vals.wildcardFilter,
        };
    }

    // ─────────────────────────── Module tracker ──────────────

    const KNOWN_MODULES = [
        { id: 'crtsh',          label: 'crt.sh'           },
        { id: 'alienvault',     label: 'AlienVault OTX'   },
        { id: 'rapiddns',       label: 'RapidDNS'         },
        { id: 'circl',          label: 'CIRCL Passive DNS' },
        { id: 'virustotal',     label: 'VirusTotal'        },
        { id: 'securitytrails', label: 'SecurityTrails'    },
        { id: 'shodan',         label: 'Shodan'            },
        { id: 'censys',         label: 'Censys'            },
        { id: 'urlscan',        label: 'urlscan.io'        },
        { id: 'resolve',        label: 'DNS Resolution'    },
        { id: 'http_probe',     label: 'HTTP Probe'        },
        { id: 'takeover',       label: 'Takeover Check'    },
    ];

    let _trackerBuilt = false;

    function _buildTracker() {
        const grid = $('sub-tracker-grid');
        if (!grid) return;
        grid.innerHTML = '';
        KNOWN_MODULES.forEach(m => {
            const el = document.createElement('div');
            el.className = 'tracker-module';
            el.id        = `sub-tmod-${m.id}`;
            el.innerHTML = `
                <div class="tracker-dot"></div>
                <span class="tracker-module-name">${m.label}</span>
                <span class="tracker-check">✔</span>
            `;
            grid.appendChild(el);
        });
        _trackerBuilt = true;
    }

    function _updateTracker(modulesDone, status) {
        const tracker = $('sub-module-tracker');
        if (!tracker) return;

        if (!_trackerBuilt) _buildTracker();
        tracker.classList.add('visible');

        const doneSet   = new Set(modulesDone || []);
        let lastDoneIdx = -1;
        KNOWN_MODULES.forEach((m, i) => { if (doneSet.has(m.id)) lastDoneIdx = i; });

        KNOWN_MODULES.forEach((m, i) => {
            const el = $(`sub-tmod-${m.id}`);
            if (!el) return;
            el.classList.remove('done', 'running');
            if (doneSet.has(m.id)) {
                el.classList.add('done');
            } else if (status === 'running' && i === lastDoneIdx + 1) {
                el.classList.add('running');
            }
        });

        const countEl = $('sub-tracker-count');
        if (countEl) countEl.textContent = `${doneSet.size} / ${KNOWN_MODULES.length} completed`;
    }

    function _resetTracker() {
        _trackerBuilt = false;
        const tracker = $('sub-module-tracker');
        if (tracker) tracker.classList.remove('visible');
        const grid = $('sub-tracker-grid');
        if (grid) grid.innerHTML = '';
    }

    // ─────────────────────────── DB render ───────────────────

    async function _fetchAndRenderFromDB(domain) {
        try {
            await Subdomains.loadFromDB(null);
            const count = id => parseInt(($(id)?.textContent || '').trim(), 10) || 0;
            const items = [
                ['Total Found',  count('sub-stat-total')],
                ['DNS Resolved', count('sub-stat-resolved')],
                ['NXDOMAIN',     count('sub-stat-dead')],
                ['HTTP Alive',   count('sub-stat-alive')],
                ['Unique IPs',   count('sub-stat-unique-ips')],
                ['Sources Hit',  count('sub-stat-sources')],
            ];
            if (items[0][1] === 0) {
                window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
                return false;
            }
            _appendSummary(items);
            return true;
        } catch (err) {
            window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
            return false;
        }
    }

    // ─────────────────────────── Poll loop ───────────────────

    function _stopPolling() {
        if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    }

    async function _poll(jobId) {
        if (_aborted) { _onScanEnd(); return; }

        if (Date.now() - _pollStart > POLL_TIMEOUT) {
            _appendScanResult(false, 'Scan timed out (30 minutes).');
            _onScanEnd();
            return;
        }

        try {
            const resp = await fetch(`${API_BASE}/api/subdomain/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));

            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

            const status = data.status;

            _updateTracker(data.modules_done || [], status);

            /* Stream stderr lines to output console */
            if (data.stderr) {
                _outputEl()?.querySelector('pre') || _appendLine('', '');
                const pre = _outputEl()?.querySelector('pre');
                if (pre) {
                    const shown   = pre.dataset.shownLen || '0';
                    const newText = data.stderr.slice(parseInt(shown));
                    if (newText) {
                        newText.split('\n').forEach(line => {
                            if (!line) return;
                            const span = document.createElement('span');
                            span.style.color = line.startsWith('  ✔') ? 'var(--green)'
                                             : line.startsWith('  ✘') ? '#c07820'
                                             : line.startsWith('  ⚠') ? '#d09030'
                                             : 'var(--text-sec)';
                            span.textContent = line + '\n';
                            pre.appendChild(span);
                        });
                        pre.dataset.shownLen = String(data.stderr.length);
                        _outputEl().scrollTop = _outputEl().scrollHeight;
                    }
                }
            }

            if (status === 'done') {
                const allIds = KNOWN_MODULES.map(m => m.id);
                _updateTracker(allIds, 'done');

                if (!data.db_ready) {
                    _appendScanResult(false, 'Database is not ready. database-manager.py may have failed or is missing.');
                    _toast('Scan failed: database not ready', 'error');
                    _onScanEnd();
                    return;
                }

                _appendScanResult(true, data.output_file || 'Completed');
                await _fetchAndRenderFromDB(data.domain);
                _setSidebarCompletion(true);
                _toast(`Subdomain scan completed: ${data.domain}`, 'ok');
                _onScanEnd();
                return;
            }

            if (status === 'error') {
                _appendScanResult(false, data.stderr || 'unknown error');
                _toast('Subdomain scan ended with an error', 'error');
                _onScanEnd();
                return;
            }

            _pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);

        } catch (err) {
            _appendScanResult(false, `Poll error: ${err.message}`);
            _onScanEnd();
        }
    }

    // ─────────────────────────── Scan lifecycle ──────────────

    function _onScanEnd() {
        _stopPolling();
        _scanning   = false;
        _aborted    = false;
        _currentJob = null;
        _setBtnState(false);
    }

    async function startScan() {
        if (_scanning) return;

        const vals          = _collectInputs();
        const targetPayload = _buildTargetPayload(vals);

        if (!targetPayload) {
            _toast('Please enter a domain name', 'warn');
            return;
        }

        // Wipe any leftover results from a previous scan and drop the
        // panel back into its empty state before the new scan begins.
        if (typeof Subdomains !== 'undefined') Subdomains.reset();

        _scanning = true;
        _aborted  = false;
        _setBtnState(true);
        _clearOutput();
        _resetTracker();
        _setSidebarCompletion(false);

        const domain  = vals.domain;
        const apiKeys = SubdomainConfig.getKeys();

        _appendLabeled('TARGET', domain, OUT_GREEN);
        let previewCmd = `python3 subdomain-hunter.py -d ${domain}`;
        if (vals.checkLive) previewCmd += ' -c';
        if (vals.takeover)  previewCmd += ' --takeover';
        if (!vals.resolve)  previewCmd += ' --no-resolve';
        if (!vals.wildcardFilter) previewCmd += ' --no-wildcard-filter';


        try {
            // ── 1. Register target
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(targetPayload),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);

            // ── 2. Start subdomain scan in background
            const scanPayload = _buildScanPayload(vals);
            scanPayload.domain   = domain;
            scanPayload.api_keys = apiKeys;

            const sResp = await fetch(`${API_BASE}/api/subdomain/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(scanPayload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `subdomain/scan: ${sResp.status}`);

            _currentJob = sData.job_id;
            _appendLabeled('COMMAND', sData.cmd || previewCmd, OUT_GREEN);
            _appendLabeled('JOB ID', _currentJob, OUT_GREEN);

            // ── 3. Start status polling
            _pollStart = Date.now();
            _poll(_currentJob);

        } catch (err) {
            _appendScanResult(false, err.message);
            _appendLine('Is the API backend running?  →  python3 connection.py', 'var(--text-dim)');
            _toast(`Error: ${err.message}`, 'error');
            _onScanEnd();
        }
    }

    function stopScan() {
        if (!_scanning) return;
        _aborted = true;
        _appendScanResult(false, 'Stopped by user.');
        _toast('Subdomain scan stopped', 'warn');
        _onScanEnd();
    }

    function resetAll() {
        // If a scan is running, stop it first so polling doesn't repopulate
        // the table right after we've just cleared it.
        if (_scanning) {
            _aborted = true;
            _onScanEnd();
        }
        _clearOutput();
        _resetTracker();
        _setSidebarCompletion(false);
        if (typeof Subdomains !== 'undefined') {
            Subdomains.reset();
            Subdomains.showDefaultTab();
        }
        _toast('Subdomain results cleared', 'info');
    }

    // ─────────────────────────── Init ────────────────────────

    function init() {
        if (!document.getElementById('_sub_sc_style')) {
            const s = document.createElement('style');
            s.id          = '_sub_sc_style';
            s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
            document.head.appendChild(s);
        }

        $('sub-start-btn')?.addEventListener('click', startScan);
        $('sub-scan-btn') ?.addEventListener('click', startScan);
        $('sub-reset-btn')?.addEventListener('click', resetAll);
        $('sub-stop-btn') ?.addEventListener('click', stopScan);

        const paramsHead = $('sub-target-params-head');
        if (paramsHead) paramsHead.addEventListener('click', () => {
            paramsHead.closest('.dns-section').classList.toggle('collapsed');
        });

        // Workers button group
        document.querySelectorAll('#sub-workers-group .dns-thread-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                document.querySelectorAll('#sub-workers-group .dns-thread-btn')
                    .forEach(b => b.classList.remove('dns-thread-btn-active'));
                btn.classList.add('dns-thread-btn-active');
            });
        });

        // Domain Map
        if (typeof DomainMap !== 'undefined') DomainMap.init();
    }

    return { init, startScan, stopScan, resetAll };
})();
/* ═══════════════════════════════════════════════════════════
   DomainMap  —  D3.js left-to-right tree layout
   Root domain: far left center. Children expand rightward,
   symmetrically spaced top-to-bottom.
   ═══════════════════════════════════════════════════════════ */
const DomainMap = (() => {

    const $ = id => document.getElementById(id);
    let _svgSel  = null;
    let _zoomBeh = null;
    let _cachedRows = [];

    /* ── Build hierarchical data from flat subdomain list ── */
    function _buildHierarchy(rows) {
        // Lookup for attaching each node's own scan result (status/ips), if any
        const rowMap = new Map();
        rows.forEach(r => rowMap.set(r.subdomain, r));

        // Collect all unique domain names (subdomains + all their suffixes)
        const allNames = new Set();
        rows.forEach(r => {
            const parts = r.subdomain.split('.');
            for (let i = 0; i < parts.length; i++) {
                allNames.add(parts.slice(i).join('.'));
            }
        });

        // Find the root: the name with the fewest parts (e.g. "socar.az")
        let rootName = null;
        let minParts = Infinity;
        allNames.forEach(n => {
            const c = n.split('.').length;
            if (c < minParts) { minParts = c; rootName = n; }
        });
        if (!rootName) return null;

        // Build child map
        const childMap = new Map();
        allNames.forEach(n => { childMap.set(n, []); });

        allNames.forEach(n => {
            const parts = n.split('.');
            if (parts.length <= minParts) return; // it's the root or TLD
            const parent = parts.slice(1).join('.');
            if (childMap.has(parent)) {
                childMap.get(parent).push(n);
            }
        });

        // Recursive build
        function buildNode(name) {
            return {
                name,
                label: name.split('.')[0], // leftmost label only
                row: rowMap.get(name) || null,
                children: (childMap.get(name) || [])
                    .sort()
                    .map(c => buildNode(c))
            };
        }

        return buildNode(rootName);
    }

    /* ── Status-based node color ──
       200      → green
       30x      → blue
       40x/50x  → red
       IP only, no HTTP status → pink
       NXDOMAIN (no IP, no status) → gray
       No scan data for this node (purely structural) → null (use default styling) */
    const COLOR_OK       = '#22c55e';
    const COLOR_REDIRECT = '#3b82f6';
    const COLOR_ERROR    = '#ef4444';
    const COLOR_IP_ONLY  = '#ec4899';
    const COLOR_NXDOMAIN = '#6b7280';

    function _statusColor(row) {
        if (!row) return null;

        const https = row.https, http = row.http;
        const isNum = c => typeof c === 'number';
        let code = null;
        if (isNum(https)) code = https;
        else if (isNum(http)) code = http;

        if (code !== null) {
            if (code < 300) return COLOR_OK;
            if (code < 400) return COLOR_REDIRECT;
            return COLOR_ERROR; // 4xx and 5xx
        }

        if (row.ips && row.ips.length > 0) return COLOR_IP_ONLY;
        return COLOR_NXDOMAIN;
    }

    /* ── Main render ── */
    function render(rows) {
        const svgEl = $('sub-domain-map-svg');
        const empty = $('sub-map-empty');
        const badge = $('sub-map-badge');
        if (!svgEl) return;

        _cachedRows = rows || [];

        if (!rows || !rows.length) {
            svgEl.style.display = 'none';
            if (empty) empty.style.display = 'flex';
            return;
        }

        if (empty) empty.style.display = 'none';
        svgEl.style.display = 'block';

        if (typeof d3 === 'undefined') {
            const s = document.createElement('script');
            s.src = 'https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js';
            s.onload = () => _draw(svgEl, rows, badge);
            document.head.appendChild(s);
        } else {
            _draw(svgEl, rows, badge);
        }
    }

    function _draw(svgEl, rows, badge) {
        const root = _buildHierarchy(rows);
        if (!root) return;

        const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()   || '#f0c030';
        const sec    = getComputedStyle(document.documentElement).getPropertyValue('--text-sec').trim() || '#a0aec0';
        const dim    = getComputedStyle(document.documentElement).getPropertyValue('--text-dim').trim() || '#6b7280';
        const border = getComputedStyle(document.documentElement).getPropertyValue('--border').trim()   || '#333';

        svgEl.innerHTML = '';

        const W = svgEl.clientWidth  || 800;
        const H = svgEl.clientHeight || 520;

        // Node spacing
        const NODE_H = 22;   // vertical gap per node
        const NODE_W = 220;  // horizontal gap per depth level

        // Build D3 hierarchy & tree layout
        const hier = d3.hierarchy(root);
        const nodeCount = hier.leaves().length;
        const treeH = Math.max(H, nodeCount * NODE_H + 60);

        const treeLayout = d3.tree()
            .size([treeH, (hier.height) * NODE_W])
            .separation((a, b) => a.parent === b.parent ? 1 : 1.2);

        treeLayout(hier);

        // Flip: d3.tree gives x=vertical, y=horizontal
        // We want root at left (y=0 → x=margin), children expand right
        const PAD_LEFT = 100;

        if (badge) {
            badge.textContent = hier.descendants().length;
            badge.className   = 'dns-section-badge ok';
        }

        const svg = d3.select(svgEl);

        // Zoom
        const zoomG = svg.append('g');
        _zoomBeh = d3.zoom()
            .scaleExtent([0.05, 3])
            .on('zoom', e => zoomG.attr('transform', e.transform));
        svg.call(_zoomBeh);

        // Initial transform: center vertically, pad left
        const initX = PAD_LEFT;
        const initY = H / 2 - treeH / 2;
        zoomG.attr('transform', `translate(${initX},${initY})`);

        // Links — curved bezier
        zoomG.append('g').attr('class', 'dm-links')
          .selectAll('path')
          .data(hier.links())
          .join('path')
            .attr('fill', 'none')
            .attr('stroke', border)
            .attr('stroke-width', 1.2)
            .attr('stroke-opacity', 0.7)
            .attr('d', d => {
                const sx = d.source.y, sy = d.source.x;
                const tx = d.target.y, ty = d.target.x;
                const mx = (sx + tx) / 2;
                return `M${sx},${sy} C${mx},${sy} ${mx},${ty} ${tx},${ty}`;
            });

        // Nodes
        const node = zoomG.append('g').attr('class', 'dm-nodes')
          .selectAll('g')
          .data(hier.descendants())
          .join('g')
            .attr('transform', d => `translate(${d.y},${d.x})`);

        // Status-based styling (falls back to the original depth-based
        // look for nodes with no scan data of their own, e.g. purely
        // structural parent domains)
        node.append('circle')
            .attr('r', d => d.depth === 0 ? 9 : d.children ? 6 : 4)
            .attr('fill', d => {
                if (d.depth === 0) return accent;
                const statusFill = _statusColor(d.data.row);
                if (statusFill) return statusFill;
                if (d.children) return d3.interpolateRgb(accent, '#3a4a5a')(d.depth * 0.18);
                return '#2a3a4a';
            })
            .attr('stroke', d => d.depth === 0 ? accent : (_statusColor(d.data.row) || border))
            .attr('stroke-width', d => d.depth === 0 ? 2 : 1)
            .attr('stroke-opacity', 0.8);

        // Labels — root on left side, others on right
        node.append('text')
            .attr('dy', '0.32em')
            .attr('x', d => d.depth === 0 ? -14 : (d.children ? -10 : 10))
            .attr('text-anchor', d => d.depth === 0 ? 'end' : (d.children ? 'end' : 'start'))
            .attr('font-family', 'var(--mono, monospace)')
            .attr('font-size', d => d.depth === 0 ? 12 : 10)
            .attr('fill', d => d.depth === 0 ? accent : (d.children ? sec : dim))
            .attr('pointer-events', 'none')
            .text(d => d.depth === 0 ? d.data.name : d.data.name);

        // Full domain tooltip (includes status/IP info when available)
        node.append('title').text(d => {
            const row = d.data.row;
            if (!row) return d.data.name;
            const parts = [d.data.name];
            if (row.ips && row.ips.length) parts.push(`IP: ${row.ips.join(', ')}`);
            if (typeof row.https === 'number') parts.push(`HTTPS: ${row.https}`);
            if (typeof row.http  === 'number') parts.push(`HTTP: ${row.http}`);
            if (!row.ips?.length) parts.push(row.dns_error || 'NXDOMAIN');
            return parts.join('\n');
        });

        _svgSel = svg;
    }

    function fitView() {
        const svgEl = $('sub-domain-map-svg');
        if (!svgEl || !_zoomBeh || !_svgSel) return;
        const W = svgEl.clientWidth  || 800;
        const H = svgEl.clientHeight || 520;
        _svgSel.transition().duration(400)
            .call(_zoomBeh.transform, d3.zoomIdentity.translate(100, H / 2).scale(0.8));
    }

    function resetZoom() {
        if (!_svgSel || !_zoomBeh) return;
        _svgSel.transition().duration(400).call(_zoomBeh.transform, d3.zoomIdentity);
    }

    function init() {
        const fitBtn   = $('sub-map-fit-btn');
        const resetBtn = $('sub-map-reset-btn');
        if (fitBtn)   fitBtn.addEventListener('click',   fitView);
        if (resetBtn) resetBtn.addEventListener('click', resetZoom);
    }

    return { init, render };
})();