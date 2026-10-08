const WaybackModule = (() => {

    const API_BASE      = 'http://127.0.0.1:30300';
    const DB_API_BASE   = 'http://127.0.0.1:30301';
    const POLL_INTERVAL = 2000;
    const POLL_TIMEOUT  = 1800000;

    const KNOWN_MODULES = [
        { id: 'url_discovery',      label: 'URL Discovery' },
        { id: 'critical_pattern',   label: 'Critical Pattern' },
        { id: 'files_documents',    label: 'Files & Docs' },
        { id: 'param_discovery',    label: 'Parameters' },
        { id: 'subdomain_enum',     label: 'Subdomains' },
    ];

    const INTERESTING_PARAMS = ['id','user','token','key','api','secret','auth','pass','pwd','file','path','url','redirect','next','callback','ref','debug','admin'];
    const SENSITIVE_PARAMS   = ['token','secret','api_key','auth','password','pwd','session','cookie','jwt','bearer'];

    let _scanning   = false;
    let _pollTimer  = null;
    let _pollStart  = 0;
    let _currentJob = null;
    let _aborted    = false;
    let _urlData    = [];
    let _urlFilter  = 'all';
    let _requestsData = [];

    const $ = id => document.getElementById(id);

    function _outputEl() { return document.querySelector('.wb-output-wrap'); }

    const OUT_GREEN = '#3ddc84';
    const OUT_RED   = '#ff4d4d';
    const OUT_VALUE = '#d4d4d4';

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

    function _clearOutput() {
        const el = _outputEl();
        if (el) el.innerHTML = '<span class="output-placeholder">// Output will appear here when analysis is running...</span>';
    }

    function _setSidebarCompletion(completed) {
        const item = document.querySelector('.nav-item[data-panel="panel-wayback"]');
        const count = item?.querySelector('.nav-count');
        if (!count) return;
        count.textContent = completed ? '✓' : '--';
        count.classList.toggle('dns-enum-complete', completed);
        count.setAttribute('aria-label', completed ? 'Wayback completed' : 'Wayback not completed');
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

    function _setBtnState(running) {
        const scan = $('wb-scan-btn');
        const stop = $('wb-stop-btn');
        if (scan) {
            scan.disabled = running;
            scan.style.opacity = running ? '.5' : '1';
        }
        if (stop) {
            stop.disabled = !running;
            stop.style.opacity = running ? '1' : '.4';
        }
    }

    function _resetTracker() {
        const grid = $('wb-tracker-grid');
        const tracker = $('wb-module-tracker');
        if (!grid || !tracker) return;
        tracker.classList.add('visible');
        grid.innerHTML = KNOWN_MODULES.map(m => `
            <div class="tracker-module" id="wbt-${m.id}">
                <div class="tracker-dot"></div>
                <span class="tracker-module-name">${m.label}</span>
                <span class="tracker-check">✔</span>
            </div>`).join('');
        _updateTrackerCount(0);
    }

    function _updateTracker(done, status) {
        done.forEach(id => {
            const el = $(`wbt-${id}`);
            if (el && !el.classList.contains('done')) el.classList.add('done');
        });
        KNOWN_MODULES.forEach(m => {
            const el = $(`wbt-${m.id}`);
            if (!el) return;
            if (status === 'running' && !el.classList.contains('done'))
                el.classList.add('running');
            if (el.classList.contains('done'))
                el.classList.remove('running');
        });
        _updateTrackerCount(done.length);
    }

    function _updateTrackerCount(done) {
        const c = $('wb-tracker-count');
        if (c) c.textContent = `${done} / ${KNOWN_MODULES.length} completed`;
    }

    function _getInputs() {
        return {
            url:   ($('wb-input-url')   || {}).value || '',
            proxy: ($('wb-input-proxy') || {}).value || '',
        };
    }

    function _normaliseUrl(raw) {
        raw = raw.trim();
        if (!raw) return null;
        if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
        try { return new URL(raw).hostname; } catch (_) { return raw; }
    }

    function _stopPolling() {
        if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    }

    function _onScanEnd() {
        _stopPolling();
        _scanning   = false;
        _aborted    = false;
        _currentJob = null;
        _setBtnState(false);
    }

    async function _fetchAndRenderFromDB(domain) {
        try {
            const normDomain = String(domain || '').toLowerCase();

            const summaryResp = await fetch(`${DB_API_BASE}/api/wayback/summary`);
            if (!summaryResp.ok) throw new Error(`/api/wayback/summary: ${summaryResp.status}`);
            const summaryData = await summaryResp.json().catch(() => ({}));

            if (!summaryData.success) throw new Error(summaryData.error || 'No wayback data found');

            const scanId = summaryData.scan_id;

            const urlRows      = summaryData.urls?.rows || [];
            const subRows      = summaryData.subdomains?.rows || [];
            const patternData  = summaryData.critical_patterns?.by_pattern || {};
            const fileRows     = summaryData.files?.rows || [];
            const paramRows    = summaryData.parameters?.rows || [];
            const scanMeta     = summaryData.scan || {};

            const mappedUrls = urlRows.map(r => ({
                url:       r.url,
                status:    r.status_code,
                first:     r.first_seen,
                last:      r.last_seen,
                snapshots: r.snapshot_count,
            }));
            _renderUrls(mappedUrls);

            _renderCritical(patternData);

            const fileUrls = fileRows.map(r => r.url).filter(Boolean);
            _renderFiles(fileUrls);

            const mappedParams = paramRows.map(r => ({
                name:     r.param_name,
                type:     r.value_type || 'string',
                example:  r.example_value,
                freq:     r.frequency,
                endpoint: r.endpoint_url,
            }));
            _renderParams(mappedParams);

            _renderRequests(urlRows.map(r => r.url).filter(u => u && /\?[^#]*=/.test(u)));

            const subUrls = subRows.map(r => r.url).filter(Boolean);
            _renderSubdomains(subUrls);

            _appendLabeled(
                'DATABASE',
                `Loaded ${urlRows.length} URLs, ` +
                `${subRows.length} subdomains, ` +
                `${Object.keys(patternData).length} critical pattern categories, ` +
                `${fileRows.length} files, ` +
                `${paramRows.length} parameters`,
                OUT_GREEN
            );

            return true;

        } catch (err) {
            window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
            return false;
        }
    }

    async function _poll(jobId) {
        if (_aborted) return;
        if (Date.now() - _pollStart > POLL_TIMEOUT) {
            _appendScanResult(false, 'Scan timed out.');
            _onScanEnd();
            return;
        }
        try {
            const resp = await fetch(`${API_BASE}/api/wayback/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

            const status = data.status;
            _updateTracker(data.modules_done || [], status);

            if (data.stdout) {
                const el = _outputEl();
                const pre = _outputPre();
                if (pre) {
                    const shown   = parseInt(pre.dataset.shownLen || '0');
                    const newText = data.stdout.slice(shown);
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
                        el.scrollTop = el.scrollHeight;
                    }
                }
            }

            if (status === 'done') {
                _updateTracker(KNOWN_MODULES.map(m => m.id), 'done');

                if (!data.db_ready) {
                    _appendScanResult(false, 'Database is not ready. database-manager.py may have failed or is missing.');
                    _toast('Scan failed: database not ready', 'error');
                    _onScanEnd();
                    return;
                }

                _appendScanResult(true, data.output_file || 'Completed');
                await _fetchAndRenderFromDB(data.domain);
                _setSidebarCompletion(true);
                _toast(`Wayback analysis completed: ${data.domain}`, 'ok');
                _onScanEnd();
                return;
            }

            if (status === 'error') {
                _appendScanResult(false, data.stderr || 'unknown error');
                _toast('Analysis ended with an error', 'error');
                _onScanEnd();
                return;
            }

            _pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);
        } catch (err) {
            _appendScanResult(false, `Poll error: ${err.message}`);
            _onScanEnd();
        }
    }

    async function startScan() {
        if (_scanning) return;

        const urlEl   = $('wb-input-url');
        const proxyEl = $('wb-input-proxy');
        const tfUrl   = document.getElementById('tf-target');
        const tfProxy = document.getElementById('tf-proxy');

        if (urlEl && tfUrl && !urlEl.value.trim() && tfUrl.value.trim())
            urlEl.value = tfUrl.value.trim();
        if (proxyEl && tfProxy && !proxyEl.value.trim() && tfProxy.value.trim())
            proxyEl.value = tfProxy.value.trim();

        const inputs = _getInputs();
        const host   = _normaliseUrl(inputs.url);
        if (!host) { _toast('Please enter a target URL', 'warn'); return; }

        _scanning = true;
        _aborted  = false;
        _setBtnState(true);
        _clearOutput();
        _resetTracker();
        _setSidebarCompletion(false);

        _appendLabeled('TARGET', host, OUT_GREEN);
        const previewCmd = `python3 Wayback-Analyser.py -U ${host} --all`;

        try {
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ url: `https://${host}`, proxy: inputs.proxy || null }),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);
            const payload = {
                domain: host,
                from:   null,
                to:     null,
                proxy:  inputs.proxy || null,
            };
            const sResp = await fetch(`${API_BASE}/api/wayback/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(payload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `wayback/scan: ${sResp.status}`);

            _currentJob = sData.job_id;
            _appendLabeled('COMMAND', sData.cmd || previewCmd, OUT_GREEN);
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
        _toast('Analysis stopped', 'warn');
        _onScanEnd();
    }

    function _extClass(url) {
        const ext = (url.split('?')[0].split('.').pop() || '').toLowerCase();
        if (['js','mjs'].includes(ext))        return 'js';
        if (['php','asp','aspx'].includes(ext)) return 'php';
        if (['html','htm'].includes(ext))       return 'html';
        if (['json'].includes(ext))             return 'json';
        if (['xml','rss'].includes(ext))        return 'xml';
        if (['css'].includes(ext))              return 'css';
        return 'other';
    }

    function _statusClass(code) {
        const c = parseInt(code);
        if (c === 200)           return 's200';
        if (c >= 300 && c < 400) return 's3xx';
        if (c >= 400)            return 's4xx';
        return 'dim';
    }

    function _renderUrls(urls) {
        _urlData = urls;
        _urlFilter = 'all';
        const badge = $('wb-urls-badge');
        if (badge) { badge.textContent = urls.length; badge.className = 'wb-section-badge ok'; }
        _applyUrlFilter();
    }

    function _applyUrlFilter() {
        const search = ($('wb-url-search') || {}).value || '';
        const body   = $('wb-url-table');
        if (!body) return;

        const filtered = _urlData.filter(u => {
            const typeOk   = _urlFilter === 'all' || _extClass(u.url) === _urlFilter;
            const searchOk = !search || u.url.toLowerCase().includes(search.toLowerCase());
            return typeOk && searchOk;
        });

        if (!filtered.length) {
            body.innerHTML = `<div class="data-empty"><span>No URLs match the current filter</span></div>`;
            return;
        }

        body.innerHTML = filtered.map(u => {
            return `<div class="data-row">
                <div class="data-cell flex1" style="font-family:var(--mono);font-size:10px;color:var(--text-sec);word-break:break-all;">
                    <a href="https://web.archive.org/web/*/${_esc(u.url)}" target="_blank" rel="noopener"
                       style="color:var(--accent-dim);text-decoration:none;" title="View in Wayback">
                        ${_esc(u.url)}
                    </a>
                </div>
            </div>`;
        }).join('');
    }

    function _renderParams(params) {
        const badge = $('wb-params-badge');
        if (badge) { badge.textContent = params.length; badge.className = 'wb-section-badge ok'; }

        const interesting = params.filter(p => INTERESTING_PARAMS.includes((p.name || '').toLowerCase())).length;
        const sensitive   = params.filter(p => SENSITIVE_PARAMS.includes((p.name || '').toLowerCase())).length;
        const endpoints   = new Set(params.map(p => p.endpoint)).size;

        [['param-total', params.length, ''], ['param-interesting', interesting, 'ok'],
         ['param-sensitive', sensitive, 'warn'], ['param-endpoints', endpoints, '']].forEach(([id, val, cls]) => {
            const el = $(id);
            if (!el) return;
            el.textContent = val;
            if (cls) el.className = `wb-pstat-val ${cls}`;
        });

        const body = $('wb-param-table');
        if (!body || !params.length) return;
        body.innerHTML = params.map(p => {
            return `<div class="data-row">
                <div class="data-cell flex1" style="font-family:var(--mono);font-size:11px;color:var(--accent);">${_esc(p.name || '--')}</div>
            </div>`;
        }).join('');
    }

    function _renderRequests(urls) {
        _requestsData = Array.from(new Set(urls));
        const badge = $('wb-requests-badge');
        if (badge) { badge.textContent = _requestsData.length; badge.className = 'wb-section-badge ok'; }

        const body = $('wb-requests-table');
        if (!body) return;
        if (!_requestsData.length) {
            body.innerHTML = `<div class="data-empty"><span>No parameterized URLs found</span></div>`;
            return;
        }
        body.innerHTML = _requestsData.map(u => `<div class="data-row">
                <div class="data-cell flex1" style="font-family:var(--mono);font-size:10px;color:var(--text-sec);word-break:break-all;">
                    <a href="https://web.archive.org/web/*/${_esc(u)}" target="_blank" rel="noopener"
                       style="color:var(--accent-dim);text-decoration:none;" title="View in Wayback">
                        ${_esc(u)}
                    </a>
                </div>
            </div>`).join('');
    }

    const HIGH_RISK_PATTERNS = ['admin','login','sap-system','open-redirect','forgot-password','install','log-exposure','upload'];

    function _renderCritical(patterns) {
        const allUrls     = Object.values(patterns).flat();
        const totalUrls   = new Set(allUrls).size;
        const categories  = Object.keys(patterns).length;
        const highRisk    = Object.entries(patterns).filter(([k]) => HIGH_RISK_PATTERNS.includes(k)).reduce((a, [, v]) => a + v.length, 0);

        const badge = $('wb-critical-badge');
        if (badge) { badge.textContent = categories; badge.className = 'wb-section-badge danger'; }

        [['crit-total', allUrls.length, ''], ['crit-categories', categories, ''],
         ['crit-high', highRisk, 'danger'], ['crit-urls', totalUrls, '']].forEach(([id, val, cls]) => {
            const el = $(id);
            if (!el) return;
            el.textContent = val;
            if (cls) el.className = `wb-pstat-val ${cls}`;
        });

        const list = $('wb-critical-list');
        if (!list || !Object.keys(patterns).length) return;

        list.innerHTML = Object.entries(patterns).map(([category, urls]) => {
            const isHigh   = HIGH_RISK_PATTERNS.includes(category);
            const riskClass = isHigh ? 'danger' : 'warn';
            const riskLabel = isHigh ? 'HIGH'   : 'MEDIUM';
            const label     = category.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            return `<div class="wb-critical-group">
                <div class="wb-critical-group-head">
                    <span class="wb-risk-badge ${riskClass}" style="font-size:9px;">${riskLabel}</span>
                    <span class="wb-critical-cat">${_esc(label)}</span>
                    <span class="wb-section-badge ok" style="margin-left:auto;">${urls.length}</span>
                </div>
                <div class="wb-critical-urls">
                    ${urls.map(u => `<div class="wb-critical-url">
                        <a href="${_esc(u)}" target="_blank" rel="noopener" style="color:var(--accent-dim);text-decoration:none;font-family:var(--mono);font-size:10px;word-break:break-all;">${_esc(u)}</a>
                    </div>`).join('')}
                </div>
            </div>`;
        }).join('');
    }

    let _filesData   = [];
    let _filesFilter = 'all';

    function _getFileExt(url) {
        const path = url.split('?')[0].toLowerCase();
        if (path.endsWith('.pdf')) return 'pdf';
        if (path.endsWith('.doc') || path.endsWith('.docx')) return 'doc';
        if (path.endsWith('.txt') || path.includes('robots.txt') || path.includes('llms.txt')) return 'txt';
        if (path.endsWith('.php') || path.endsWith('.asp') || path.endsWith('.aspx')) return 'php';
        return 'other';
    }

    function _getFileRisk(url) {
        const u = url.toLowerCase();
        if (u.includes('install.php') || u.includes('admin') || u.includes('logon')) return ['high', 'HIGH'];
        if (u.endsWith('.pdf') || u.includes('/uploads/')) return ['warn', 'MEDIUM'];
        return ['dim', 'LOW'];
    }

    function _renderFiles(files) {
        _filesData   = files;
        _filesFilter = 'all';
        const badge = $('wb-files-badge');
        if (badge) { badge.textContent = files.length; badge.className = 'wb-section-badge ok'; }
        _applyFilesFilter();

        const filterGroup = $('wb-files-filter');
        if (filterGroup) {
            filterGroup.querySelectorAll('.wb-filter-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    filterGroup.querySelectorAll('.wb-filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    _filesFilter = btn.dataset.filter;
                    _applyFilesFilter();
                });
            });
        }
    }

    function _applyFilesFilter() {
        const body = $('wb-files-table');
        if (!body) return;
        const filtered = _filesData.filter(u => _filesFilter === 'all' || _getFileExt(u) === _filesFilter);
        if (!filtered.length) {
            body.innerHTML = `<div class="data-empty"><span>No files match the current filter</span></div>`;
            return;
        }
        body.innerHTML = filtered.map(u => {
            return `<div class="data-row">
                <div class="data-cell flex1" style="font-family:var(--mono);font-size:10px;color:var(--text-sec);word-break:break-all;">
                    <a href="${_esc(u)}" target="_blank" rel="noopener" style="color:var(--accent-dim);text-decoration:none;">${_esc(u)}</a>
                </div>
            </div>`;
        }).join('');
    }

    let _subdomainData   = [];
    let _subdomainFilter = 'all';

    function _getSubdomainType(url, baseDomain) {
        const host = url.replace(/^https?:\/\//, '').split('/')[0];
        if (host.endsWith('.' + baseDomain) || host === baseDomain) return 'subdomain';
        return 'related';
    }

    function _renderSubdomains(subdomains) {
        _subdomainData   = subdomains;
        _subdomainFilter = 'all';

        const baseDomain = (($('wb-input-url') || {}).value || '').replace(/^https?:\/\//, '').split('/')[0];
        const legacy  = subdomains.filter(u => u.startsWith('http://') && !u.startsWith('https://')).length;
        const subs    = subdomains.filter(u => _getSubdomainType(u, baseDomain) === 'subdomain').length;
        const related = subdomains.length - subs;

        const badge = $('wb-subdomains-badge');
        if (badge) { badge.textContent = subdomains.length; badge.className = 'wb-section-badge ok'; }

        [['sub-total', subdomains.length, 'ok'], ['sub-subdomains', subs, ''],
         ['sub-related', related, 'warn'], ['sub-legacy', legacy, 'danger']].forEach(([id, val, cls]) => {
            const el = $(id);
            if (!el) return;
            el.textContent = val;
            if (cls) el.className = `wb-pstat-val ${cls}`;
        });

        _applySubdomainFilter(baseDomain);

        const filterGroup = $('wb-subdomain-filter');
        if (filterGroup) {
            filterGroup.querySelectorAll('.wb-filter-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    filterGroup.querySelectorAll('.wb-filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    _subdomainFilter = btn.dataset.filter;
                    _applySubdomainFilter(baseDomain);
                });
            });
        }
    }

    function _applySubdomainFilter(baseDomain) {
        const body = $('wb-subdomain-table');
        if (!body) return;
        const filtered = _subdomainData.filter(u => {
            const type     = _getSubdomainType(u, baseDomain || '');
            const isLegacy = u.startsWith('http://') && !u.startsWith('https://');
            if (_subdomainFilter === 'all')       return true;
            if (_subdomainFilter === 'subdomain') return type === 'subdomain';
            if (_subdomainFilter === 'related')   return type === 'related';
            if (_subdomainFilter === 'legacy')    return isLegacy;
            return true;
        });
        if (!filtered.length) {
            body.innerHTML = `<div class="data-empty"><span>No entries match the current filter</span></div>`;
            return;
        }
        body.innerHTML = filtered.map(u => {
            return `<div class="data-row">
                <div class="data-cell flex1" style="font-family:var(--mono);font-size:10px;color:var(--text-sec);word-break:break-all;">
                    <a href="${_esc(u)}" target="_blank" rel="noopener" style="color:var(--accent-dim);text-decoration:none;">${_esc(u)}</a>
                </div>
            </div>`;
        }).join('');
    }

    function _openDefaultView() {
        const firstBtn = document.querySelector('#wb-subtab-bar .wb-subtab-btn[data-wbtab]');
        const tabId = firstBtn && firstBtn.getAttribute('data-wbtab');
        if (!firstBtn || !tabId) return;
        document.querySelectorAll('.wb-sub-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('#wb-subtab-bar .wb-subtab-btn').forEach(b => b.classList.remove('active'));
        firstBtn.classList.add('active');
        const panel = document.getElementById(tabId);
        if (panel) {
            panel.classList.add('active');
            panel.querySelectorAll('.wb-section.collapsed').forEach(sec => sec.classList.remove('collapsed'));
        }
        $('wb-target-head')?.closest('.wb-section')?.classList.remove('collapsed');
    }

    function init() {
        if (!document.getElementById('_wb_sc_style')) {
            const s = document.createElement('style');
            s.id = '_wb_sc_style';
            s.textContent = `
                @keyframes wbFadeIn { from { opacity: 0.3; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
                .wb-sub-panel { display: none !important; }
                .wb-sub-panel.active { display: block !important; animation: wbFadeIn 0.25s ease; }
                #wb-subtab-bar .wb-subtab-btn {
                    background: transparent !important; border: none !important;
                    border-bottom: 2px solid transparent !important; border-radius: 0 !important;
                    color: var(--text-dim) !important; font-family: var(--ui); font-size: 10.5px;
                    font-weight: 500; padding: 5px 12px; cursor: pointer; outline: none;
                    transition: color 0.2s, border-color 0.2s, background 0.2s;
                    letter-spacing: 0.02em; white-space: nowrap;
                }
                #wb-subtab-bar .wb-subtab-btn:hover { color: var(--text-sec) !important; background: rgba(240,192,48,0.04) !important; }
                #wb-subtab-bar .wb-subtab-btn.active { color: var(--accent) !important; border-bottom-color: var(--accent) !important; background: rgba(240,192,48,0.06) !important; }
                #wb-workers-group { display: flex; gap: 4px; flex-wrap: wrap; }
                #wb-workers-group .dns-thread-btn { background: var(--bg-card) !important; border: 1px solid var(--border) !important; border-radius: var(--radius-sm) !important; color: var(--text-dim) !important; font-family: var(--mono); font-size: 11px; padding: 3px 10px; cursor: pointer; transition: all 0.15s; }
                #wb-workers-group .dns-thread-btn:hover { border-color: var(--accent-dim) !important; color: var(--text-sec) !important; }
                #wb-workers-group .dns-thread-btn.dns-thread-btn-active { background: var(--bg-selected) !important; border-color: var(--accent-dim) !important; color: var(--accent) !important; }
            `;
            document.head.appendChild(s);
        }

        const scanBtn = $('wb-scan-btn');
        if (scanBtn) scanBtn.addEventListener('click', startScan);

        const stopBtn = $('wb-stop-btn');
        if (stopBtn) stopBtn.addEventListener('click', stopScan);

        const loadDbBtn = $('wb-load-db-btn');
        if (loadDbBtn) loadDbBtn.addEventListener('click', async () => {
            loadDbBtn.disabled = true;
            try {
                const target = _normaliseUrl(_getInputs().url) || '';
                const loaded = await _fetchAndRenderFromDB(target);
                if (loaded) {
                    window.markPanelComplete?.('panel-wayback', 'Wayback / Archive');
                    _appendLabeled('DATABASE', 'Results loaded and rendered', OUT_GREEN);
                    _toast('Wayback results loaded from database', 'success');
                }
            } catch (err) {
                window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
            } finally {
                loadDbBtn.disabled = false;
            }
        });

        const resetBtn = $('wb-reset-btn');
        if (resetBtn) resetBtn.addEventListener('click', () => {
            if (_scanning) { _aborted = true; }
            _clearOutput();
            _openDefaultView();
        });

        const requestsBtn = $('wb-requests-btn');
        if (requestsBtn) requestsBtn.addEventListener('click', () => {
            const wrap = $('wb-requests-wrap');
            if (!wrap) return;
            const open = wrap.style.display === 'none';
            wrap.style.display = open ? 'block' : 'none';
            requestsBtn.classList.toggle('active', open);
        });

        const targetHead = $('wb-target-head');
        if (targetHead) targetHead.addEventListener('click', () => {
            targetHead.closest('.wb-section').classList.toggle('collapsed');
        });

        document.addEventListener('click', e => {
            const subtabBtn = e.target.closest('#wb-subtab-bar .wb-subtab-btn');
            if (subtabBtn) {
                e.preventDefault();
                const tabId = subtabBtn.getAttribute('data-wbtab');
                if (!tabId) return;
                document.querySelectorAll('.wb-sub-panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('#wb-subtab-bar .wb-subtab-btn').forEach(b => b.classList.remove('active'));
                const target = document.getElementById(tabId);
                if (target) target.classList.add('active');
                subtabBtn.classList.add('active');
                return;
            }
            const workerBtn = e.target.closest('#wb-workers-group .dns-thread-btn');
            if (workerBtn) {
                e.preventDefault();
                document.querySelectorAll('#wb-workers-group .dns-thread-btn').forEach(b => b.classList.remove('dns-thread-btn-active'));
                workerBtn.classList.add('dns-thread-btn-active');
                return;
            }
        });

        const urlFilter = $('wb-url-filter');
        if (urlFilter) {
            urlFilter.querySelectorAll('.wb-filter-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    urlFilter.querySelectorAll('.wb-filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    _urlFilter = btn.dataset.filter;
                    _applyUrlFilter();
                });
            });
        }

        const urlSearch = $('wb-url-search');
        if (urlSearch) urlSearch.addEventListener('input', _applyUrlFilter);

        _setBtnState(false);
        _openDefaultView();
    }

    return { init, startScan, stopScan, loadFromDatabase: _fetchAndRenderFromDB };

})();