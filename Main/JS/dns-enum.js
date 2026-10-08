const DnsEnum = (() => {

    const RECORD_LABELS = {
        A:     'IPv4 Address Records',
        AAAA:  'IPv6 Address Records',
        MX:    'Mail Exchange Records',
        NS:    'Nameserver Records',
        TXT:   'Text Records',
        CNAME: 'Canonical Name Records',
        SOA:   'Start of Authority',
        PTR:   'Pointer Records',
    };

    let allRecords   = [];
    let activeFilter = 'ALL';

    function initTabs()         {}
    function initRecordFilter() {}

    function ttlClass(ttl) {
        if (ttl === null || ttl === undefined) return 'dim';
        if (ttl < 60)  return 'vlow';
        if (ttl < 300) return 'low';
        return '';
    }

    function ttlLabel(ttl) {
        if (ttl === null || ttl === undefined) return '--';
        return `${ttl}s`;
    }

    function valueClass(type) {
        const m = { TXT: 'txt-val', CNAME: 'cname-val', MX: 'mx-val', NS: 'ns-val', SOA: 'soa-val' };
        return m[type] || '';
    }

    function renderRecords(records) {
        const grid  = document.getElementById('dns-record-grid');
        const empty = document.getElementById('dns-record-empty');
        const badge = document.getElementById('records-badge');

        if (!records.length) {
            grid.innerHTML = '';
            grid.appendChild(empty);
            empty.style.display = 'flex';
            if (badge) { badge.textContent = '0'; badge.className = 'dns-section-badge dim'; }
            return;
        }

        if (badge) { badge.textContent = records.length; badge.className = 'dns-section-badge ok'; }

        const byType = {};
        records.forEach(r => { (byType[r.type] = byType[r.type] || []).push(r); });

        grid.innerHTML = '';
        Object.entries(byType).forEach(([type, rows]) => {
            const group = document.createElement('div');
            group.className = 'dns-rtype-group';
            group.innerHTML = `
                <div class="dns-rtype-group-head">
                    <span class="dns-rtype-badge ${type}">${type}</span>
                    <span class="dns-rtype-name">${RECORD_LABELS[type] || type}</span>
                    <span class="dns-rtype-count">${rows.length}</span>
                    <svg class="dns-rtype-chevron" width="12" height="12" viewBox="0 0 16 16" fill="none">
                        <path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <div class="dns-rtype-rows">
                    ${rows.map(r => `
                    <div class="dns-record-row">
                        <div class="dns-rec-name">${r.name}</div>
                        <div class="dns-rec-ttl ${ttlClass(r.ttl)}">${ttlLabel(r.ttl)}</div>
                        <div class="dns-rec-value ${valueClass(type)}">${r.value}</div>
                        ${r.priority !== undefined ? `<div class="dns-rec-priority">${r.priority}</div>` : ''}
                    </div>`).join('')}
                </div>`;

            group.querySelector('.dns-rtype-group-head').addEventListener('click', () => {
                group.classList.toggle('collapsed');
            });
            grid.appendChild(group);
        });
    }

    function renderAnomalyTable(records) {
        const body  = document.getElementById('anomaly-table-body');
        const known = records.filter(r => r.ttl !== null && r.ttl !== undefined);
        const low   = known.filter(r => r.ttl < 300);
        const vlow  = known.filter(r => r.ttl < 60);
        const score = vlow.length > 0 ? 'HIGH'
                    : low.length  > 2 ? 'MEDIUM'
                    :                   'LOW';

        document.getElementById('anom-total').textContent = known.length;

        const lowEl  = document.getElementById('anom-low');
        const vlowEl = document.getElementById('anom-vlow');
        const fluxEl = document.getElementById('anom-flux');

        lowEl.textContent  = low.length;
        vlowEl.textContent = vlow.length;
        fluxEl.textContent = score;

        lowEl.className  = 'anomaly-stat-val' + (low.length  > 0           ? ' warn'   : '');
        vlowEl.className = 'anomaly-stat-val' + (vlow.length > 0           ? ' danger' : '');
        fluxEl.className = 'anomaly-stat-val' + (score === 'HIGH'   ? ' danger'
                                                : score === 'MEDIUM' ? ' warn' : '');

        if (!records.length) return;

        body.innerHTML = records.map(r => {
            const tc   = ttlClass(r.ttl);
            const anom = tc === 'vlow' ? '<span class="badge red">FAST-FLUX</span>'
                       : tc === 'low'  ? '<span class="badge amber">LOW TTL</span>'
                       :                 '<span class="badge dim">NORMAL</span>';
            return `<div class="data-row">
                <div class="data-cell flex1"  style="color:var(--text-sec)">${r.name}</div>
                <div class="data-cell w90"    style="text-align:center"><span class="dns-rtype-badge ${r.type}">${r.type}</span></div>
                <div class="data-cell w90"    style="color:${tc==='vlow'?'#ff4444':tc==='low'?'#c07820':'var(--text-dim)'}">${r.ttl}</div>
                <div class="data-cell flex1s" style="color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;">${r.value}</div>
                <div class="data-cell w110">${anom}</div>
            </div>`;
        }).join('');
    }

    function init() {
        initTabs();
        initRecordFilter();
    }

    return { init, renderRecords, renderAnomalyTable };
})();

const ScanController = (() => {

    const API_BASE      = 'http://127.0.0.1:30300';
    const DB_API_BASE   = 'http://127.0.0.1:30301';
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

    function _outputEl() { return document.querySelector('#panel-dns-enum .output-wrap'); }

    function _expandDnsSections() {
        document.querySelectorAll('#panel-dns-enum .dns-section:not(#sec-target-params)')
            .forEach(section => section.classList.remove('collapsed'));
    }

    function _setDnsSectionState(sectionId, hasResults) {
        const section = $(sectionId);
        if (sectionId === 'sec-records') { if (section) section.classList.remove('collapsed'); return; }
        if (section) section.classList.toggle('collapsed', !hasResults);
    }

    const DEFAULT_DNS_TAB = 'dns-sub-records';

    function _activateDnsTab(tabId) {
        const bar = document.getElementById('dns-subtab-bar');
        const target = document.getElementById(tabId);
        if (!bar || !target) return;
        document.querySelectorAll('.tls-sub-panel[id^="dns-sub-"]').forEach(p => p.classList.remove('active'));
        bar.querySelectorAll('.tls-subtab-btn').forEach(b =>
            b.classList.toggle('active', b.getAttribute('data-dnstab') === tabId));
        target.classList.add('active');
    }

    function _showDefaultDnsTab() {
        _activateDnsTab(DEFAULT_DNS_TAB);
        const rec = document.getElementById('sec-records');
        if (rec) rec.classList.remove('collapsed');
    }

    function _setOutput(html) {
        const el = _outputEl();
        if (el) el.innerHTML = html;
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
        const item = document.querySelector('.nav-item[data-panel="panel-dns-enum"]');
        const count = item?.querySelector('.nav-count');
        if (!count) return;
        count.textContent = completed ? '✓' : '--';
        count.classList.toggle('dns-enum-complete', completed);
        count.setAttribute('aria-label', completed ? 'DNS Enum completed' : 'DNS Enum not completed');
    }

    function _esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    function _toast(msg, type) {
        if (typeof UI !== 'undefined' && UI.toast) { UI.toast(msg, type); return; }
        console.log(`[${type}] ${msg}`);
    }

    function _setBtnState(scanning) {
        const scanningHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite">
                 <circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6"
                         stroke-dasharray="10 6" stroke-linecap="round"/>
               </svg> SCANNING…`;
        const idleHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none">
                 <circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.4"/>
                 <path d="M11 11l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
               </svg> Start`;
        [document.getElementById('ts-start-btn'), document.getElementById('dns-scan-btn')].forEach(btn => {
            if (!btn) return;
            btn.disabled      = scanning;
            btn.style.opacity = scanning ? '0.55' : '';
            btn.innerHTML     = scanning ? scanningHTML : idleHTML;
        });
    }

    function _collectInputs() {
        const v = id => ($(id)?.value?.trim() || '');
        const dnsDomain = v('dns-input-domain') || v('input-domain');
        const dnsNS     = v('dns-input-nameserver');
        const dnsPanel  = document.getElementById('panel-dns-enum') || document;
        const activeBtn = dnsPanel.querySelector('#dns-threads-group .dns-thread-btn-active');
        const dnsThreads = activeBtn ? parseInt(activeBtn.dataset.val) : 3;
        return {
            domain:     dnsDomain,
            url:        dnsDomain ? (dnsDomain.startsWith('http') ? dnsDomain : 'https://' + dnsDomain) : v('input-target-url'),
            vhost:      v('input-vhost'),
            port:       v('input-port'),
            headers:    v('input-headers'),
            nameserver: dnsNS,
            threads:    dnsThreads,
        };
    }

    function _buildTargetPayload(vals) {
        const raw = vals.domain || vals.url;
        if (!raw) return null;
        const url     = raw.startsWith('http') ? raw : `https://${raw}`;
        const payload = { url };
        if (vals.port)    payload.port    = parseInt(vals.port) || undefined;
        if (vals.vhost)   payload.vhost   = vals.vhost;
        if (vals.headers) payload.headers = vals.headers;
        return payload;
    }

    function _buildScanPayload(vals) {
        const payload = {};
        if (vals.nameserver) payload.nameserver = vals.nameserver;
        if (vals.threads)    payload.threads    = vals.threads;
        return payload;
    }

    async function _fetchAndRenderFromDB(domain) {
        try {
            const normDomain = String(domain || '').toLowerCase();
            async function _getModuleRows(modulesObj, tableName, scanId) {
                const directRows = modulesObj?.[tableName]?.rows;
                if (Array.isArray(directRows)) return directRows;
                try {
                    const listResp = await fetch(
                        `${DB_API_BASE}/api/list/${tableName}?scan_id=${encodeURIComponent(scanId)}&limit=500000`
                    );
                    if (!listResp.ok) return [];
                    const listData = await listResp.json().catch(() => ({}));
                    return Array.isArray(listData.rows) ? listData.rows : [];
                } catch (_e) {
                    return [];
                }
            }

            const scansResp = await fetch(`${DB_API_BASE}/api/scans`);
            if (!scansResp.ok) throw new Error(`/api/scans: ${scansResp.status}`);
            const scansData = await scansResp.json().catch(() => ({}));

            if (!scansData.success || !scansData.scans?.length) {
                throw new Error('No scan found in database');
            }

            const normaliseTarget = value => {
                const raw = String(value || '').trim().toLowerCase();
                try { return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname; }
                catch (_) { return raw.replace(/^https?:\/\//, '').split('/')[0]; }
            };
            const matchingScans = scansData.scans
                .filter(s => normaliseTarget(s.target) === normaliseTarget(normDomain))
                .sort((a, b) => Number(String(b.source_file || '').includes('dns')) - Number(String(a.source_file || '').includes('dns')));
            const candidates = [...matchingScans, ...scansData.scans.filter(s => !matchingScans.includes(s))];
            let latestScanId = null;
            let modules = {};
            for (const scan of candidates) {
                const scanResp = await fetch(`${DB_API_BASE}/api/scan/${scan.id}`);
                if (!scanResp.ok) continue;
                const scanData = await scanResp.json().catch(() => ({}));
                const candidateModules = scanData.modules || scanData.data?.modules || {};
                const hasDnsRows = ['dns_records', 'dns_module_results', 'dns_dangling',
                    'dns_ttl_anomalies', 'dns_reverse', 'dns_dnssec', 'dns_axfr']
                    .some(name => Array.isArray(candidateModules?.[name]?.rows) && candidateModules[name].rows.length);
                if (hasDnsRows) {
                    latestScanId = scan.id;
                    modules = candidateModules;
                    break;
                }
            }
            if (!latestScanId) throw new Error('No DNS results found in database');

            const rawRows = await _getModuleRows(modules, 'dns_module_results', latestScanId);
            const rawBadge = $('module-results-badge');
            const rawBody = $('module-results-body');
            if (rawBadge) {
                rawBadge.textContent = rawRows.length || '0';
                rawBadge.className = 'dns-section-badge ' + (rawRows.length ? 'ok' : 'dim');
            }
            if (rawBody) {
                rawBody.innerHTML = '';
                if (!rawRows.length) {
                    rawBody.innerHTML = '<div class="data-empty"><span>No complete module payloads found</span></div>';
                } else {
                    rawRows.forEach(row => {
                        const section = document.createElement('div');
                        section.className = 'dns-sub-group';
                        const title = document.createElement('div');
                        title.className = 'dns-sub-group-title';
                        title.textContent = row.module || 'unknown';
                        const pre = document.createElement('pre');
                        pre.style.cssText = 'margin:0;padding:10px 14px;max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:11px/1.55 var(--mono);color:var(--text-dim);';
                        let payload = row.result;
                        if (typeof payload === 'string') {
                            try { payload = JSON.parse(payload); } catch (_) {}
                        }
                        pre.textContent = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
                        section.append(title, pre);
                        rawBody.appendChild(section);
                    });
                }
            }

            const recRows = await _getModuleRows(modules, 'dns_records', latestScanId);
            if (recRows.length && typeof DnsEnum !== 'undefined') {
                const flat = recRows.map(r => ({
                    type:  r.record_type,
                    name:  domain,
                    ttl:   (r.ttl !== null && r.ttl !== undefined) ? Number(r.ttl) : null,
                    value: r.value,
                }));
                DnsEnum.renderRecords(flat);
                DnsEnum.renderAnomalyTable(flat);
            }

            const ttlRows = await _getModuleRows(modules, 'dns_ttl_anomalies', latestScanId);
            if (ttlRows.length && typeof DnsEnum !== 'undefined') {
                DnsEnum.renderAnomalyTable(ttlRows);
            }

            const dangRows = await _getModuleRows(modules, 'dns_dangling', latestScanId);
            const dangBadge = $('dangling-badge');
            if (dangBadge) {
                dangBadge.textContent = dangRows.length || '0';
                dangBadge.className   = 'dns-section-badge ' + (dangRows.length ? 'danger' : 'ok');
            }
            const dangBody = $('dangling-table-body');
            if (dangBody) {
                if (!dangRows.length) {
                    dangBody.innerHTML = `
                        <div class="data-empty">
                            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18">
                                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="currentColor" stroke-width="1.3"/>
                                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="currentColor" stroke-width="1.3"/>
                            </svg>
                            <span>No dangling records detected</span>
                        </div>`;
                } else {
                    dangBody.innerHTML = dangRows.map(r => {
                        const service  = r.service || '--';
                        const highRisk = ['GitHub Pages','Heroku','Netlify','Vercel','AWS S3','Firebase','Surge.sh','Bitbucket'].some(s => service.includes(s));
                        const riskCls  = highRisk ? 'badge red' : 'badge amber';
                        const riskLbl  = highRisk ? 'HIGH'      : 'MEDIUM';
                        return `<div class="data-row">
                            <div class="data-cell" style="flex:1.2;color:var(--accent);font-family:var(--mono);font-size:11px;">${r.subdomain || '--'}</div>
                            <div class="data-cell" style="flex:1;color:var(--text-dim);font-family:var(--mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;">${r.cname || '--'}</div>
                            <div class="data-cell" style="width:110px;color:var(--text-sec)">${service}</div>
                            <div class="data-cell" style="width:100px;"><span class="badge amber">UNCLAIMED</span></div>
                            <div class="data-cell" style="width:90px;"><span class="${riskCls}">${riskLbl}</span></div>
                        </div>`;
                    }).join('');
                }
            }

            const axfrRows = await _getModuleRows(modules, 'dns_axfr', latestScanId);
            const axfrVulnerable = axfrRows.some(row => row.vulnerable === 1 || row.vulnerable === true || String(row.vulnerable).toLowerCase() === 'true');
            if (axfrRows.length) {
                const vuln = axfrVulnerable;
                const _el  = (id, txt, cls) => { const e = $(id); if (e) { e.textContent = txt; e.className = cls; } };
                _el('axfr-result-val', vuln ? 'VULN' : 'SECURE', 'dns-section-badge ' + (vuln ? 'danger' : 'ok'));
                _el('axfr-status-val', vuln ? 'VULNERABLE' : 'REFUSED', 'axfr-status-val ' + (vuln ? 'danger' : 'ok'));
                _el('axfr-vuln-val',   vuln ? 'YES' : 'NO', 'axfr-status-val ' + (vuln ? 'danger' : 'ok'));

                // ── Zone Transfer (ANY) records ───────────────────────────
                const axfrAnyBody  = $('axfr-any-body');
                const axfrAnyBadge = $('axfr-any-badge');
                let anyRecords = [];
                // collect any_records from all axfr rows
                axfrRows.forEach(row => {
                    const parsed = typeof row.any_records === 'string'
                        ? (() => { try { return JSON.parse(row.any_records); } catch(_){return [];} })()
                        : (Array.isArray(row.any_records) ? row.any_records : []);
                    anyRecords = anyRecords.concat(parsed);
                });

                if (axfrAnyBadge) {
                    axfrAnyBadge.textContent = anyRecords.length || '0';
                    axfrAnyBadge.className   = 'dns-section-badge ' + (anyRecords.length ? 'ok' : 'dim');
                }
                if (axfrAnyBody) {
                    if (!anyRecords.length) {
                        axfrAnyBody.innerHTML = `<div class="data-empty"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18"><rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/></svg><span>No ANY records found</span></div>`;
                    } else {
                        // Parse raw "name TTL IN TYPE value" lines
                        axfrAnyBody.innerHTML = anyRecords.map(raw => {
                            // split on multiple lines within one record string
                            return raw.split('\n').filter(Boolean).map(line => {
                                // e.g. "google.com. 300 IN A 192.178.24.46"
                                const parts   = line.trim().split(/\s+/);
                                const recName = parts[0] || '--';
                                const recTtl  = parts[1] || '--';
                                const recCls  = parts[2] || 'IN';
                                const recType = parts[3] || '--';
                                const recVal  = parts.slice(4).join(' ') || '--';
                                const ttlNum  = parseInt(recTtl, 10);
                                const ttlCls  = isNaN(ttlNum) ? '' : ttlNum < 60 ? 'color:#ff4444' : ttlNum < 300 ? 'color:#c07820' : 'color:var(--text-sec)';
                                return `<div class="data-row">
                                    <div class="data-cell" style="flex:1.4;color:var(--accent);font-family:var(--mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;">${_esc(recName)}</div>
                                    <div class="data-cell" style="width:80px;${ttlCls};font-family:var(--mono);font-size:11px;">${_esc(recTtl)}</div>
                                    <div class="data-cell" style="width:70px;color:var(--text-dim);font-size:11px;">${_esc(recCls)}</div>
                                    <div class="data-cell" style="width:80px;text-align:center;"><span class="dns-rtype-badge ${recType}">${_esc(recType)}</span></div>
                                    <div class="data-cell" style="flex:2;color:var(--text-dim);font-family:var(--mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;">${_esc(recVal)}</div>
                                </div>`;
                            }).join('');
                        }).join('');
                    }
                }

                // Expand ANY section if records exist
                const secAny = $('sec-axfr-any');
                if (secAny && anyRecords.length) secAny.classList.remove('collapsed');

                // ── Zone Records into AXFR output ─────────────────────────
                const axfrOutput = $('axfr-output');
                if (axfrOutput) {
                    let zoneLines = [];
                    axfrRows.forEach(row => {
                        const parsed = typeof row.zone_records === 'string'
                            ? (() => { try { return JSON.parse(row.zone_records); } catch(_){return [];} })()
                            : (Array.isArray(row.zone_records) ? row.zone_records : []);
                        zoneLines = zoneLines.concat(parsed);
                    });
                    if (zoneLines.length) {
                        const pre = document.createElement('pre');
                        pre.style.cssText = 'margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:11px;line-height:1.6;';
                        pre.textContent = zoneLines.join('\n');
                        axfrOutput.innerHTML = '';
                        axfrOutput.appendChild(pre);
                    }
                }

                // ── SOA Info ──────────────────────────────────────────────
                const soaBody  = $('soa-info-body');
                const soaBadge = $('soa-info-badge');
                let soaInfo = {};
                axfrRows.forEach(row => {
                    const parsed = typeof row.soa_info === 'string'
                        ? (() => { try { return JSON.parse(row.soa_info); } catch(_){return {};} })()
                        : (row.soa_info && typeof row.soa_info === 'object' ? row.soa_info : {});
                    Object.assign(soaInfo, parsed);
                });

                const soaEntries = Object.entries(soaInfo);
                if (soaBadge) {
                    soaBadge.textContent = soaEntries.length || '0';
                    soaBadge.className   = 'dns-section-badge ' + (soaEntries.length ? 'ok' : 'dim');
                }
                if (soaBody) {
                    if (!soaEntries.length) {
                        soaBody.innerHTML = `<div class="data-empty"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.3"/></svg><span>No SOA info found</span></div>`;
                    } else {
                        soaBody.innerHTML = soaEntries.map(([ns, info]) => {
                            const serial  = info.serial      ?? '--';
                            const negTtl  = info.negative_ttl ?? '--';
                            const admin   = info.admin_email  || '--';
                            return `<div class="data-row">
                                <div class="data-cell" style="flex:1.2;color:var(--accent);font-family:var(--mono);font-size:11px;">${_esc(ns)}</div>
                                <div class="data-cell" style="width:100px;color:var(--text-sec);font-family:var(--mono);font-size:11px;">${_esc(String(serial))}</div>
                                <div class="data-cell" style="width:100px;color:var(--text-dim);font-family:var(--mono);font-size:11px;">${_esc(String(negTtl))}s</div>
                                <div class="data-cell" style="flex:1.4;color:var(--text-dim);font-family:var(--mono);font-size:11px;">${_esc(admin)}</div>
                            </div>`;
                        }).join('');
                    }
                }
                if (soaEntries.length) {
                    const secSoa = $('sec-soa-info');
                    if (secSoa) secSoa.classList.remove('collapsed');
                }

                // ── IXFR section — status derived from axfr data ───────────
                const ixfrStatusVal  = $('ixfr-status-val');
                const ixfrTypeVal    = $('ixfr-type-val');
                const ixfrChangesVal = $('ixfr-changes-val');
                const ixfrVulnVal    = $('ixfr-vuln-val');
                const ixfrBadge      = $('ixfr-badge');
                const ixfrOutput     = $('ixfr-output');

                if (ixfrStatusVal)  { ixfrStatusVal.textContent  = vuln ? 'ACCEPTED' : 'REFUSED'; ixfrStatusVal.className = 'axfr-status-val ' + (vuln ? 'danger' : 'ok'); }
                if (ixfrTypeVal)    { ixfrTypeVal.textContent    = vuln ? 'FULL (fallback to AXFR)' : 'N/A'; ixfrTypeVal.className = 'axfr-status-val dim'; }
                if (ixfrChangesVal) { ixfrChangesVal.textContent = '--'; ixfrChangesVal.className = 'axfr-status-val dim'; }
                if (ixfrVulnVal)    { ixfrVulnVal.textContent    = vuln ? 'YES' : 'NO'; ixfrVulnVal.className = 'axfr-status-val ' + (vuln ? 'danger' : 'ok'); }
                if (ixfrBadge)      { ixfrBadge.textContent      = vuln ? 'VULN' : 'SECURE'; ixfrBadge.className = 'dns-section-badge ' + (vuln ? 'danger' : 'ok'); }
                if (ixfrOutput)     {
                    ixfrOutput.innerHTML = `<pre style="margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:11px;line-height:1.6;"><span style="color:var(--text-dim)">// IXFR probes the same nameservers as AXFR.\n// Server ${vuln ? 'accepted zone transfer — incremental changes may also be accessible.' : 'refused zone transfers — IXFR also refused.'}</span></pre>`;
                }
            }

            const mailRows = await _getModuleRows(modules, 'dns_mail', latestScanId);
            if (mailRows.length) {
                const m   = mailRows[0];
                const _s  = (id, txt) => { const e = $(id); if (e) e.textContent = txt; };
                const _b  = (id, valid) => {
                    const e = $(id);
                    if (e) { e.textContent = valid ? 'VALID' : 'MISSING'; e.className = 'badge ' + (valid ? 'ok' : 'danger'); }
                };
                const spfOk   = !!m.spf   && m.spf   !== 'null';
                const dmarcOk = !!m.dmarc && m.dmarc !== 'null';
                _s('spf-raw',   m.spf   || '(none)');
                _s('dmarc-raw', m.dmarc || '(none)');
                _b('spf-badge',   spfOk);
                _b('dmarc-badge', dmarcOk);
                const mb = $('mail-badge');
                if (mb) { mb.textContent = 'DONE'; mb.className = 'dns-section-badge ok'; }
            }

            // ── DNSSEC ──────────────────────────────────────────────────
            const dnssecRows = await _getModuleRows(modules, 'dns_dnssec', latestScanId);
            
            const dnssecChainBadge = $('dnssec-chain-badge');
            const dnssecRrsigBadge = $('dnssec-rrsig-badge');
            const dnssecNsecBadge  = $('dnssec-nsec-badge');
            const dnssecNsec3Badge = $('dnssec-nsec3-badge');
            const dnssecSshfpBadge = $('dnssec-sshfp-badge');
            const dnssecTlsaBadge  = $('dnssec-tlsa-badge');

            const parseJsonValue = (value, fallback) => {
                if (value === null || value === undefined) return fallback;
                if (typeof value === 'object') return value;
                try { return JSON.parse(value); } catch (_) { return fallback; }
            };
            const rawDnssec = rawRows.find(row => row.module === 'dnssec');
            const rawDnssecData = parseJsonValue(rawDnssec?.result, {});

            if (dnssecRows.length || rawDnssec) {
                const d = { ...rawDnssecData, ...dnssecRows[0] };
                const _dv = (id, val, cls) => { const e = $(id); if (e) { e.textContent = val; e.className = 'dcr-val ' + (cls || 'dim'); } };
                const boolVal = (v) => v ? ['YES', 'ok'] : ['NO', 'danger'];

                // 1. Chain of Trust
                const [dnskeyTxt, dnskeyCs] = boolVal(d.dnskey);
                const [dsTxt,     dsCs]     = boolVal(d.ds);
                const [rrsigTxt,  rrsigCs]  = boolVal(d.rrsig);
                const [nsecTxt,   nsecCs]   = boolVal(d.nsec);
                const [chainTxt,  chainCs]  = boolVal(d.chain_valid);
                
                _dv('dnssec-dnskey', dnskeyTxt, dnskeyCs);
                _dv('dnssec-ds',     dsTxt,     dsCs);
                _dv('dnssec-rrsig',  rrsigTxt,  rrsigCs);
                _dv('dnssec-nsec',   nsecTxt,   nsecCs);
                _dv('dnssec-chain',  chainTxt,  chainCs);

                if (dnssecChainBadge) {
                    dnssecChainBadge.textContent = d.chain_valid ? 'VALID' : 'INVALID';
                    dnssecChainBadge.className   = 'dns-section-badge ' + (d.chain_valid ? 'ok' : 'danger');
                }

                // 2. RRSIG Expiry
                const rrsigExpiry = parseJsonValue(d.rrsig_expiry, []);
                const rrsigBody   = $('rrsig-expiry-body');
                if (rrsigBody) {
                    if (!rrsigExpiry.length) {
                        rrsigBody.innerHTML = `<div class="data-empty"><span>No RRSIG records found</span></div>`;
                    } else {
                        rrsigBody.innerHTML = rrsigExpiry.map(r => {
                            const cls = r.days_left < 0 ? 'badge red' : r.days_left < 3 ? 'badge red' : r.days_left < 7 ? 'badge amber' : 'badge ok';
                            const lbl = r.days_left < 0 ? 'EXPIRED' : r.days_left < 3 ? 'CRITICAL' : r.days_left < 7 ? 'WARNING' : 'OK';
                            return `<div class="data-row">
                                <div class="data-cell" style="flex:1;color:var(--text-hi);font-family:var(--mono);font-size:11px;">${r.type_covered || '--'}</div>
                                <div class="data-cell" style="flex:1.4;color:var(--text-dim);font-size:10.5px;">${r.expires || '--'}</div>
                                <div class="data-cell" style="width:100px;color:var(--text-sec);">${r.days_left ?? '--'}d</div>
                                <div class="data-cell" style="width:90px;"><span class="${cls}">${lbl}</span></div>
                            </div>`;
                        }).join('');
                    }
                }
                if (dnssecRrsigBadge) {
                    dnssecRrsigBadge.textContent = rrsigExpiry.length || '0';
                    dnssecRrsigBadge.className = 'dns-section-badge ' + (rrsigExpiry.length ? 'ok' : 'dim');
                }

                // 3. NSEC Zone Walking
                const nsecWalk     = parseJsonValue(d.nsec_walk, []);
                const nsecWalkBody = $('nsec-walk-body');
                _dv('nsec-present',  d.nsec  ? 'YES' : 'NO',  d.nsec  ? 'warn' : 'ok');
                _dv('nsec-walkable', nsecWalk.length ? 'POSSIBLE' : 'NO', nsecWalk.length ? 'danger' : 'ok');
                _dv('nsec-count',    nsecWalk.length || '0', nsecWalk.length ? 'warn' : 'dim');
                
                if (nsecWalkBody) {
                    if (!nsecWalk.length) {
                        nsecWalkBody.innerHTML = `<div class="data-empty"><span>Zone walking not possible or no names discovered</span></div>`;
                    } else {
                        nsecWalkBody.innerHTML = nsecWalk.map((name, i) => {
                            const next = nsecWalk[i + 1] || '(end)';
                            return `<div class="data-row">
                                <div class="data-cell" style="flex:1;color:var(--accent);font-family:var(--mono);font-size:11px;">${name}</div>
                                <div class="data-cell" style="flex:1;color:var(--text-dim);font-family:var(--mono);font-size:11px;">${next}</div>
                            </div>`;
                        }).join('');
                    }
                }
                if (dnssecNsecBadge) {
                    dnssecNsecBadge.textContent = d.nsec ? 'FOUND' : 'NONE';
                    dnssecNsecBadge.className   = 'dns-section-badge ' + (d.nsec ? 'warn' : 'dim');
                }

                // 4. NSEC3 Parameters
                const nsec3 = parseJsonValue(d.nsec3_optout, {});
                const hasNsec3 = Object.keys(nsec3).length > 0;
                
                if (hasNsec3) {
                    _dv('nsec3-optout',     nsec3.opt_out ? 'ENABLED' : 'DISABLED', nsec3.opt_out ? 'danger' : 'ok');
                    _dv('nsec3-flags',      nsec3.flags ?? '--', 'dim');
                    _dv('nsec3-iterations', nsec3.iterations != null ? `${nsec3.iterations}` : '--', nsec3.iterations === 0 ? 'danger' : nsec3.iterations < 100 ? 'warn' : 'ok');
                } else {
                    _dv('nsec3-optout',     'N/A', 'dim');
                    _dv('nsec3-flags',      'N/A', 'dim');
                    _dv('nsec3-iterations', 'N/A', 'dim');
                }
                if (dnssecNsec3Badge) {
                    dnssecNsec3Badge.textContent = hasNsec3 ? 'FOUND' : 'NONE';
                    dnssecNsec3Badge.className   = 'dns-section-badge ' + (hasNsec3 ? 'warn' : 'dim');
                }

                // 5. SSHFP
                const sshfp = parseJsonValue(d.sshfp, []);
                const sshfpBody = $('sshfp-body');
                _dv('sshfp-dnssec-state', d.chain_valid ? 'VALID — SSHFP protected' : 'INVALID — MITM risk', d.chain_valid ? 'ok' : 'danger');
                if (sshfpBody) {
                    if (!sshfp.length) {
                        sshfpBody.innerHTML = `<div class="data-empty"><span>No SSHFP records found</span></div>`;
                    } else {
                        sshfpBody.innerHTML = sshfp.map(r => {
                            const isWeak = (r.fingerprint_type || '').includes('SHA-1');
                            return `<div class="data-row">
                                <div class="data-cell" style="flex:0.8;color:var(--text-sec);">${r.algorithm || '--'}</div>
                                <div class="data-cell" style="width:90px;color:${isWeak ? '#d09030' : 'var(--text-sec)'};">${r.fingerprint_type || '--'}</div>
                                <div class="data-cell" style="flex:2;color:var(--text-dim);font-family:var(--mono);font-size:10px;overflow:hidden;text-overflow:ellipsis;">${r.fingerprint || '--'}</div>
                                <div class="data-cell" style="width:80px;"><span class="${isWeak ? 'badge amber' : 'badge ok'}">${isWeak ? 'WEAK' : 'OK'}</span></div>
                            </div>`;
                        }).join('');
                    }
                }
                if (dnssecSshfpBadge) {
                    dnssecSshfpBadge.textContent = sshfp.length || '0';
                    dnssecSshfpBadge.className = 'dns-section-badge ' + (sshfp.length ? 'ok' : 'dim');
                }

                // 6. TLSA
                const tlsa = parseJsonValue(d.tlsa, []);
                const tlsaBody = $('tlsa-body');
                if (tlsaBody) {
                    if (!tlsa.length) {
                        tlsaBody.innerHTML = `<div class="data-empty"><span>No TLSA/DANE records found</span></div>`;
                    } else {
                        tlsaBody.innerHTML = tlsa.map(r => {
                            const dnssecWarn = !d.chain_valid;
                            return `<div class="data-row">
                                <div class="data-cell" style="width:80px;color:var(--text-sec);">${r.service || '--'}</div>
                                <div class="data-cell" style="flex:1.4;color:var(--accent);font-family:var(--mono);font-size:10px;overflow:hidden;text-overflow:ellipsis;">${r.name || '--'}</div>
                                <div class="data-cell" style="width:60px;color:var(--text-dim);text-align:center;">${r.usage ?? '--'}</div>
                                <div class="data-cell" style="width:70px;color:var(--text-dim);text-align:center;">${r.selector ?? '--'}</div>
                                <div class="data-cell" style="width:60px;color:var(--text-dim);text-align:center;">${r.mtype ?? '--'}</div>
                                <div class="data-cell" style="flex:1.2;color:var(--text-dim);font-family:var(--mono);font-size:10px;overflow:hidden;text-overflow:ellipsis;">${(r.cert_hash || '--').slice(0, 20)}…</div>
                                <div class="data-cell" style="width:80px;"><span class="${dnssecWarn ? 'badge red' : 'badge ok'}">${dnssecWarn ? 'RISK' : 'OK'}</span></div>
                            </div>`;
                        }).join('');
                    }
                }
                if (dnssecTlsaBadge) {
                    dnssecTlsaBadge.textContent = tlsa.length || '0';
                    dnssecTlsaBadge.className = 'dns-section-badge ' + (tlsa.length ? 'ok' : 'dim');
                }

            } else {
                if (dnssecChainBadge) { dnssecChainBadge.textContent = '--'; dnssecChainBadge.className = 'dns-section-badge dim'; }
                if (dnssecRrsigBadge) { dnssecRrsigBadge.textContent = '--'; dnssecRrsigBadge.className = 'dns-section-badge dim'; }
                if (dnssecNsecBadge)  { dnssecNsecBadge.textContent = '--'; dnssecNsecBadge.className = 'dns-section-badge dim'; }
                if (dnssecNsec3Badge) { dnssecNsec3Badge.textContent = '--'; dnssecNsec3Badge.className = 'dns-section-badge dim'; }
                if (dnssecSshfpBadge) { dnssecSshfpBadge.textContent = '--'; dnssecSshfpBadge.className = 'dns-section-badge dim'; }
                if (dnssecTlsaBadge)  { dnssecTlsaBadge.textContent = '--'; dnssecTlsaBadge.className = 'dns-section-badge dim'; }
            }

            const hasDnssecData = dnssecRows.length > 0 || Boolean(rawDnssec);
            _setDnsSectionState('sec-records', recRows.length > 0);
            _setDnsSectionState('sec-axfr', axfrVulnerable);
            _setDnsSectionState('sec-dangling', dangRows.length > 0);
            _setDnsSectionState('sec-dnssec-chain', hasDnssecData);
            _setDnsSectionState('sec-dnssec-rrsig', hasDnssecData);
            _setDnsSectionState('sec-dnssec-nsec',  hasDnssecData);
            _setDnsSectionState('sec-dnssec-nsec3', hasDnssecData);
            _setDnsSectionState('sec-dnssec-sshfp', hasDnssecData);
            _setDnsSectionState('sec-dnssec-tlsa',  hasDnssecData);
            _setDnsSectionState('sec-anomaly', recRows.length > 0 || ttlRows.length > 0);
            _setDnsSectionState('sec-module-results', rawRows.length > 0);

            _appendSummary([
                ['Records',         recRows.length],
                ['Dangling DNS',    dangRows.length],
                ['TTL Anomalies',   ttlRows.length],
                ['Zone Transfer',   axfrRows.length],
                ['Mail Security',   mailRows.length],
                ['DNSSEC',          dnssecRows.length],
                ['Module Payloads', rawRows.length],
            ]);
            window.markPanelComplete?.('panel-dns-enum', 'DNS Enumeration');
            return true;
        } catch (err) {
            window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
            return false;
        }
    }

    function _stopPolling() {
        if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    }

    const KNOWN_MODULES = [
        { id: 'records',       label: 'DNS Records'   },
        { id: 'axfr',          label: 'Zone Transfer' },
        { id: 'reverse',       label: 'Reverse DNS'   },
        { id: 'dangling',      label: 'Dangling DNS'  },
        { id: 'mail',          label: 'Mail Security' },
        { id: 'dnssec',        label: 'DNSSEC'        },
        { id: 'ttl_anomalies', label: 'TTL Anomaly'   },
    ];

    let _trackerBuilt = false;
    let _seenModules  = new Set();

    function _buildTracker() {
        const grid = document.getElementById('tracker-grid');
        if (!grid) return;
        grid.innerHTML = '';
        KNOWN_MODULES.forEach(m => {
            const el = document.createElement('div');
            el.className = 'tracker-module';
            el.id        = `tmod-${m.id}`;
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
        const tracker = document.getElementById('module-tracker');
        if (!tracker) return;

        if (!_trackerBuilt) _buildTracker();
        tracker.classList.add('visible');

        const doneSet = new Set(modulesDone || []);
        let lastDoneIdx = -1;
        KNOWN_MODULES.forEach((m, i) => { if (doneSet.has(m.id)) lastDoneIdx = i; });

        KNOWN_MODULES.forEach((m, i) => {
            const el = document.getElementById(`tmod-${m.id}`);
            if (!el) return;
            el.classList.remove('done', 'running');
            if (doneSet.has(m.id)) {
                el.classList.add('done');
            } else if (status === 'running' && i === lastDoneIdx + 1) {
                el.classList.add('running');
            }
        });

        const countEl = document.getElementById('tracker-count');
        if (countEl) countEl.textContent = `${doneSet.size} / ${KNOWN_MODULES.length} completed`;
    }

    function _resetTracker() {
        _trackerBuilt = false;
        _seenModules  = new Set();
        const tracker = document.getElementById('module-tracker');
        if (tracker) tracker.classList.remove('visible');
        const grid = document.getElementById('tracker-grid');
        if (grid) grid.innerHTML = '';
    }

    async function _poll(jobId) {
        if (_aborted) { _onScanEnd(); return; }

        if (Date.now() - _pollStart > POLL_TIMEOUT) {
            _appendScanResult(false, 'Scan timed out (30 minutes).');
            _onScanEnd();
            return;
        }

        try {
            const resp = await fetch(`${API_BASE}/api/dns/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));

            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

            const status = data.status;

            _updateTracker(data.modules_done || [], status);

            if (data.stdout) {
                _outputEl().querySelector('pre') || _appendLine('', '');
                const pre = _outputEl().querySelector('pre');
                if (pre) {
                    const shown = pre.dataset.shownLen || '0';
                    const newText = data.stdout.slice(parseInt(shown));
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
                        pre.dataset.shownLen = String(data.stdout.length);
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

                _appendScanResult(true, data.output_file);
                await _fetchAndRenderFromDB(data.domain);
                _setSidebarCompletion(true);
                _toast(`DNS scan completed: ${data.domain}`, 'ok');
                _onScanEnd();
                return;
            }

            if (status === 'error') {
                _appendScanResult(false, data.stderr || 'unknown error');
                _toast('Scan ended with an error', 'error');
                _onScanEnd();
                return;
            }

            _pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);

        } catch (err) {
            _appendScanResult(false, `Poll error: ${err.message}`);
            _onScanEnd();
        }
    }

    function _onScanEnd() {
        _stopPolling();
        _scanning   = false;
        _aborted    = false;
        _currentJob = null;
        _setBtnState(false);
    }

    async function startScan() {
        if (_scanning) return;

        const vals = _collectInputs();
        const targetPayload = _buildTargetPayload(vals);

        if (!targetPayload) {
            _toast('Please enter a domain name or target URL', 'warn');
            return;
        }

        _scanning = true;
        _aborted  = false;
        _setBtnState(true);
        _clearOutput();
        _resetTracker();
        _expandDnsSections();
        _setSidebarCompletion(false);

        (function() {
            var rg = document.getElementById('dns-record-grid');
            if (rg) rg.innerHTML = '<div class="dns-record-empty" id="dns-record-empty" style="display:flex;"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" opacity=".18"><rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/><path d="M7 8h10M7 12h10M7 16h5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg><span>Run enumeration to see DNS records</span></div>';
            var rb = document.getElementById('records-badge'); if (rb) { rb.textContent='--'; rb.className='dns-section-badge dim'; }
            var mb = document.getElementById('module-results-body'); if (mb) mb.innerHTML='<div class="data-empty"><span>Run enumeration to load complete module payloads</span></div>';
            var mbadge = document.getElementById('module-results-badge'); if (mbadge) { mbadge.textContent='--'; mbadge.className='dns-section-badge dim'; }
            ['anom-total','anom-low','anom-vlow','anom-flux'].forEach(function(id){var e=document.getElementById(id);if(e)e.textContent='--';});
            var ab = document.getElementById('anomaly-table-body'); if (ab) ab.innerHTML='<div class="data-empty"><span>Run enumeration to analyse TTL anomalies</span></div>';
            var abadge = document.getElementById('anomaly-badge'); if (abadge) { abadge.textContent='--'; abadge.className='dns-section-badge dim'; }
        })();

        const domain = targetPayload.url.replace(/^https?:\/\//, '').split('/')[0];

        _appendLabeled('TARGET', domain, OUT_GREEN);

        try {
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(targetPayload),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);

            const scanPayload = _buildScanPayload(vals);
            const sResp = await fetch(`${API_BASE}/api/dns/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(scanPayload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `dns/scan: ${sResp.status}`);

            _currentJob = sData.job_id;
            _appendLabeled('COMMAND', sData.cmd || '--', OUT_GREEN);
            _appendLabeled('JOB ID', _currentJob, OUT_GREEN);

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
        _toast('Scan stopped', 'warn');
        _onScanEnd();
    }

    function init() {
        if (!document.getElementById('_sc_style')) {
            const s = document.createElement('style');
            s.id          = '_sc_style';
            s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
            document.head.appendChild(s);
        }

        document.addEventListener('click', function(e) {
            const subtabBtn = e.target.closest('#dns-subtab-bar .tls-subtab-btn');
            if (!subtabBtn) return;
            const tabId = subtabBtn.getAttribute('data-dnstab');
            if (tabId) _activateDnsTab(tabId);
        });

        _expandDnsSections();
        _showDefaultDnsTab();

        const startBtn = document.getElementById('ts-start-btn');
        if (startBtn) startBtn.addEventListener('click', startScan);

        const stopBtn = document.getElementById('ts-stop-btn');
        if (stopBtn) stopBtn.addEventListener('click', stopScan);

        const dnsScanBtn = document.getElementById('dns-scan-btn');
        if (dnsScanBtn) dnsScanBtn.addEventListener('click', startScan);

        const dnsLoadBtn = document.getElementById('dns-load-db-btn');
        if (dnsLoadBtn && !dnsLoadBtn._dnsBound) {
            dnsLoadBtn.addEventListener('click', async () => {
                dnsLoadBtn.disabled = true;
                try {
                    const domain = document.getElementById('dns-input-domain')?.value.trim() || '';
                    const loaded = await _fetchAndRenderFromDB(domain);
                    if (!loaded) _setSidebarCompletion(false);
                } catch (err) {
                    window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
                } finally {
                    dnsLoadBtn.disabled = false;
                }
            });
            dnsLoadBtn._dnsBound = true;
        }

        const dnsStopBtn = document.getElementById('dns-stop-btn');
        if (dnsStopBtn) dnsStopBtn.addEventListener('click', stopScan);

        // Event delegation fallback — catches buttons that are injected into
        // the DOM after init() runs (e.g. when the panel is loaded lazily).
        document.addEventListener('click', function _dnsDelegate(e) {
            const btn = e.target.closest('#dns-scan-btn');
            if (btn && btn !== dnsScanBtn) { startScan(); return; }
            const stopB = e.target.closest('#dns-stop-btn');
            if (stopB && stopB !== dnsStopBtn) stopScan();
        });

        const dnsResetBtn = document.getElementById('dns-reset-btn');
        if (dnsResetBtn) dnsResetBtn.addEventListener('click', function() {
            if (_scanning) { _aborted = true; _onScanEnd(); }
            _clearOutput();
            _resetTracker();
            var rg = document.getElementById('dns-record-grid');
            if (rg) rg.innerHTML = '<div class="dns-record-empty" id="dns-record-empty" style="display:flex;"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" opacity=".18"><rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/><path d="M7 8h10M7 12h10M7 16h5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg><span>Run enumeration to see DNS records</span></div>';
            var rb = document.getElementById('records-badge'); if (rb) { rb.textContent='--'; rb.className='dns-section-badge dim'; }
            var mb = document.getElementById('module-results-body'); if (mb) mb.innerHTML='<div class="data-empty"><span>Run enumeration to load complete module payloads</span></div>';
            var mbadge = document.getElementById('module-results-badge'); if (mbadge) { mbadge.textContent='--'; mbadge.className='dns-section-badge dim'; }
            ['anom-total','anom-low','anom-vlow','anom-flux'].forEach(function(id){var e=document.getElementById(id);if(e)e.textContent='--';});
            var ab = document.getElementById('anomaly-table-body'); if (ab) ab.innerHTML='<div class="data-empty"><span>Run enumeration to analyse TTL anomalies</span></div>';
            var abadge = document.getElementById('anomaly-badge'); if (abadge) { abadge.textContent='--'; abadge.className='dns-section-badge dim'; }
            _setSidebarCompletion(false);
            _showDefaultDnsTab();
            _toast('DNS scan results cleared', 'info');
        });

        document.querySelectorAll('#dns-threads-group .dns-thread-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                document.querySelectorAll('#dns-threads-group .dns-thread-btn')
                    .forEach(b => b.classList.remove('dns-thread-btn-active'));
                btn.classList.add('dns-thread-btn-active');
            });
        });
    }

    function _selectThread(btn) {
        document.querySelectorAll('.dns-thread-btn').forEach(b => b.classList.remove('dns-thread-btn-active'));
        btn.classList.add('dns-thread-btn-active');
    }

    return { init, startScan, stopScan, _selectThread };
})();
// ── Auto-initialise ────────────────────────────────────────────────────────
// Supports both:
//   • Classic page load  (DOMContentLoaded)
//   • Lazy / SPA panel injection (MutationObserver watches for dns-scan-btn)
(function () {
    let _initialised = false;

    function _run() {
        if (_initialised) return;
        // Only init when the DNS panel button is actually in the DOM.
        if (!document.getElementById('dns-scan-btn')) return;
        _initialised = true;
        if (typeof DnsEnum !== 'undefined')        DnsEnum.init();
        if (typeof ScanController !== 'undefined') ScanController.init();
    }

    // Try immediately (script loaded after panel HTML) or on DOMContentLoaded.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _run);
    } else {
        _run();
    }

    // MutationObserver: fires when the panel is injected into the DOM later.
    if (!_initialised) {
        const obs = new MutationObserver(function () {
            if (document.getElementById('dns-scan-btn')) {
                obs.disconnect();
                _run();
            }
        });
        obs.observe(document.body || document.documentElement, { childList: true, subtree: true });
    }
})();