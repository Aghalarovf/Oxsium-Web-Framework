const HeaderScan = (() => {
  'use strict';

  const API_BASE      = 'http://127.0.0.1:30300';
  const DB_API_BASE   = 'http://127.0.0.1:30301';
  const POLL_INTERVAL = 2000;
  const POLL_TIMEOUT  = 1800000;
  const DASH          = '—';

  let _scanning   = false;
  let _pollTimer  = null;
  let _pollStart  = 0;
  let _currentJob = null;
  let _aborted    = false;
  let _pickedFile = null;

  const INTERCEPT_EXT_RX = /\.(json|jsonl)$/i;
  const INTERCEPT_HINT   = 'Path to a captured traffic log used for offline header analysis';

  const MODULE = {
    security: 'Security Headers Analyzer',
    leak:     'Information Leak Analyzer',
    cors:     'CORS Misconfiguration Analyzer',
    cache:    'Cache Control Analyzer',
    cookie:   'Cookie & JWT Analyzer',
    redirect: 'Redirect Analyzer',
    rating:   'Security Rating & Grade Calculator'
  };

  const SEVERITY_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, OK: 0 };
  const GRADE_ORDER   = ['A+', 'A', 'B', 'C', 'D', 'E', 'F'];

  const HANDLED_HEADERS = new Set([
    'server', 'x-powered-by', 'x-aspnet-version', 'x-runtime', 'via', 'x-served-by', 'x-generator',
    'retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
    'transfer-encoding', 'content-length', 'connection', 'upgrade',
    'sec-websocket-key', 'sec-websocket-accept', 'sec-websocket-protocol', 'sec-websocket-version'
  ]);

  function _blankSecurity() {
    const simple = () => ({ status: 'none', present: DASH, value: DASH, verdict: DASH });
    return {
      hsts:     { status: 'none', present: DASH, maxAge: DASH, subDomains: DASH, preload: DASH, verdict: DASH },
      csp:      { status: 'none', present: DASH, def: DASH, script: DASH, style: DASH, object: DASH, frame: DASH, report: DASH, unsafe: DASH, verdict: DASH },
      xcto:     simple(),
      xss:      simple(),
      xfo:      { ...simple(), csp: DASH },
      referrer: simple(),
      cors:     { status: 'none', aca: DASH, credentials: DASH, methods: DASH, headers: DASH, expose: DASH, maxage: DASH, wildcard: DASH, verdict: DASH }
    };
  }

  function _defaultState() {
    return {
      status: 'IDLE',
      payload: null,
      summary: { domain: DASH, grade: DASH, score: DASH, responses: 0, findings: 0 },
      security: _blankSecurity(),
      server: {},
      serverRisk: 'LOW',
      cache: {
        'cache-control': { value: DASH, noStore: DASH, noCache: DASH, scope: DASH, maxAge: DASH, sMaxage: DASH },
        verdict: null
      },
      auth: {
        'set-cookie': { count: '0', httponly: 'No', secure: 'No', samesite: DASH, domain: DASH, maxage: DASH, session: DASH, observed: false, ok: false }
      },
      rateLimit: { 'retry-after': DASH, 'x-ratelimit-limit': DASH, 'x-ratelimit-remaining': DASH, 'x-ratelimit-reset': DASH },
      custom: [],
      cookieIntel: [],
      websocket: {},
      score: { ok: 0, warn: 0, fail: 0, total: 0 }
    };
  }

  let _state = _defaultState();

  const REQ_KEYS = ['hsts', 'csp', 'xcto', 'xss', 'xfo', 'referrer', 'cors', 'cc', 'sc', 'rl', 'cat', 'ws', 'server', 'xpb', 'xasp', 'xrt', 'via', 'xsrv', 'xgen', 'ckfp', 'ckcat', 'ckjwt', 'inv'];
  const REQ_HEADER = {
    hsts: 'strict-transport-security',
    csp: 'content-security-policy',
    xcto: 'x-content-type-options',
    xss: 'x-xss-protection',
    xfo: 'x-frame-options',
    referrer: 'referrer-policy',
    cors: 'cors',
    cc: 'cache-control',
    sc: 'set-cookie'
  };
  let _requests = {};
  let _reqFilter = {};

  function _outputEl() { return document.getElementById('hdr-output-wrap'); }

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
    if (el) el.innerHTML = '<span class="output-placeholder">Output will appear here when the scan is running...</span>';
  }

  function _setInfo(t) {
    const el = document.getElementById('hdr-scan-info');
    if (el) el.textContent = t;
  }

  function _toast(msg, type) {
    if (typeof UI !== 'undefined' && UI && typeof UI.toast === 'function') { UI.toast(msg, type); return; }
    console.log(`[${type}] ${msg}`);
  }

  function _esc(value) {
    return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }

  function _setBtnState(scanning) {
    const scanningHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite">
             <circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6"
                     stroke-dasharray="10 6" stroke-linecap="round"/>
           </svg> SCANNING…`;
    const idleHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none">
             <rect x="2" y="3" width="12" height="10" rx="1.5" stroke="currentColor" stroke-width="1.3"/>
             <path d="M2 6h12" stroke="currentColor" stroke-width="1.3"/>
             <path d="M5 9h4M5 11h2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
           </svg> Scan HTTP Headers`;
    const startBtn = document.getElementById('hdr-scan-btn');
    const stopBtn  = document.getElementById('hdr-stop-btn');
    if (startBtn) {
      startBtn.disabled      = scanning;
      startBtn.style.opacity = scanning ? '0.55' : '';
      startBtn.innerHTML     = scanning ? scanningHTML : idleHTML;
    }
    if (stopBtn) {
      stopBtn.disabled = !scanning;
    }
  }

  function _collectInputs() {
    const domainRaw = document.getElementById('hdr-input-domain')?.value?.trim() || '';
    const domain    = domainRaw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
    const intercept = document.getElementById('hdr-input-intercept')?.value?.trim() || '';
    return { domain, intercept };
  }

  function _buildTargetPayload(vals) {
    if (!vals.domain) return null;
    return { url: `https://${vals.domain}` };
  }

  function _formatSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  function _setHint(text, cls) {
    const el = document.getElementById('hdr-intercept-hint');
    if (!el) return;
    el.textContent = text;
    el.className = 'hdr-field-hint' + (cls ? ' ' + cls : '');
  }

  function _validateIntercept() {
    const v = document.getElementById('hdr-input-intercept')?.value?.trim() || '';
    if (!v) { _setHint(INTERCEPT_HINT, ''); return true; }
    if (!INTERCEPT_EXT_RX.test(v)) { _setHint('Unsupported file type — use a .json or .jsonl file', 'err'); return false; }
    if (_pickedFile && v === (_pickedFile.path || _pickedFile.name)) {
      _setHint(`Selected: ${_pickedFile.name} (${_formatSize(_pickedFile.size)})`, 'ok');
    } else {
      _setHint(`Path set: ${v}`, 'ok');
    }
    return true;
  }

  function _onInterceptPicked(file) {
    _pickedFile = file;
    const el = document.getElementById('hdr-input-intercept');
    if (el) el.value = file.path || file.name;
    _validateIntercept();
  }

  async function _fetchResults(domain) {
    const query = domain ? `?domain=${encodeURIComponent(domain)}` : '';
    const resp = await fetch(`${DB_API_BASE}/api/headers/results${query}`);
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok || !body || !body.success || !body.data) {
      throw new Error(body.error || `No HTTP header results found in database${domain ? ` for ${domain}` : ''}`);
    }
    return body;
  }

  async function _fetchAndRenderFromDB(domain) {
    try {
      const body = await _fetchResults(domain);
      const data = body && body.success ? body.data : null;

      if (!data || !Array.isArray(data.entries)) {
        throw new Error(`No usable HTTP header results found in database${domain ? ` for ${domain}` : ''}`);
      }

      _state.payload = data;
      analyzePayload(data);
      renderAll();

      const src = body.source === 'json_file' ? 'JSON file' : 'DB';
      const s   = _state.summary;
      _appendLabeled('DATABASE', `Results rendered (source: ${src})`, OUT_GREEN);
      _appendLabeled('SUMMARY', `${s.responses} responses · ${s.findings} findings · grade ${s.grade} (${s.score}/100)`, OUT_GREEN);
      _setInfo(`Scan complete — ${s.responses} responses analyzed, grade ${s.grade}`);
      window.markPanelComplete?.('panel-headers', 'Headers');
      return true;
    } catch (err) {
      window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
      _setInfo('Database results unavailable');
      return false;
    }
  }

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
      const resp = await fetch(`${API_BASE}/api/headers/job/${jobId}`);
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

      const status = data.status;

      if (data.stderr) {
        let pre = _outputEl()?.querySelector('pre');
        if (!pre) { _appendLine('', ''); pre = _outputEl()?.querySelector('pre'); }
        if (pre) {
          const shownLen = parseInt(pre.dataset.shownLen || '0');
          const newText  = data.stderr.slice(shownLen);
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

        if (!data.db_ready) {
          _appendScanResult(false, 'Database is not ready.');
          _setInfo('Scan failed: database not ready');
          _toast('Scan failed: database not ready', 'error');
          _onScanEnd();
          return;
        }

        _appendScanResult(true, data.output_file || 'Completed');
        await _fetchAndRenderFromDB(data.domain);
        window.markPanelComplete?.('panel-headers', 'Headers');
        _toast(`Header scan completed: ${data.domain}`, 'ok');
        _onScanEnd();
        return;
      }

      if (status === 'error') {
        _appendScanResult(false, data.stderr || 'unknown error');
        _setInfo('Scan ended with an error');
        _toast('Header scan ended with an error', 'error');
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
    _state.status = 'IDLE';
  }

  async function startScan() {
    if (_scanning) return;

    const vals          = _collectInputs();
    const targetPayload = _buildTargetPayload(vals);

    if (!targetPayload) {
      document.getElementById('hdr-sec-target-params')?.classList.remove('collapsed');
      _setInfo('⚠ Please enter a domain name');
      _toast('Please enter a domain name', 'warn');
      return;
    }
    if (!_validateIntercept()) {
      _setInfo('Intercept log must be a .json or .jsonl file.');
      _toast('Intercept log must be a .json or .jsonl file.', 'warn');
      return;
    }

    _scanning = true;
    _aborted  = false;
    _setBtnState(true);
    _clearOutput();
    _state.status = 'RUNNING';

    if (!document.getElementById('_hdr_sc_style')) {
      const s = document.createElement('style');
      s.id          = '_hdr_sc_style';
      s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
      document.head.appendChild(s);
    }

    const domain = vals.domain;
    _appendLabeled('TARGET', domain, OUT_GREEN);
    const previewCmd = `python headers_analyzer.py -t ${domain}${vals.intercept ? ' --intercept ' + vals.intercept : ''} --json -q`;
    _setInfo('Registering target…');

    try {
      const tResp = await fetch(`${API_BASE}/api/target/set`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(targetPayload),
      });
      const tData = await tResp.json().catch(() => ({}));
      if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);
      _setInfo(`Target registered: ${domain} — starting scan…`);
      const scanPayload = {};
      if (vals.intercept) {
        scanPayload.intercept_log = vals.intercept;
        if (_pickedFile && !_pickedFile.path && vals.intercept === _pickedFile.name) {
          scanPayload.intercept_log_content = await _pickedFile.text();
        }
        _appendLabeled('INTERCEPT', vals.intercept, OUT_GREEN);
      }
      const sResp = await fetch(`${API_BASE}/api/headers/scan`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(scanPayload),
      });
      const sData = await sResp.json().catch(() => ({}));
      if (!sResp.ok || !sData.success) throw new Error(sData.error || `headers/scan: ${sResp.status}`);

      _currentJob = sData.job_id;
      _appendLabeled('COMMAND', sData.cmd || previewCmd, OUT_GREEN);
      _appendLabeled('JOB ID', _currentJob, OUT_GREEN);
      _setInfo(`Scanning… job=${_currentJob}`);

      _pollStart = Date.now();
      _poll(_currentJob);

    } catch (err) {
      _appendScanResult(false, err.message);
      _appendLine('Is the API backend running?  →  python3 connection.py', 'var(--text-dim)');
      _setInfo(`Error: ${err.message}`);
      _toast(`Error: ${err.message}`, 'error');
      _onScanEnd();
    }
  }

  function stopScan() {
    if (!_scanning) return;
    _aborted = true;
    _appendScanResult(false, 'Stopped by user.');
    _setInfo('Scan stopped');
    _toast('Header scan stopped', 'warn');
    _onScanEnd();
  }

  function resetAll() {
    if (_scanning) {
      _aborted = true;
      _onScanEnd();
    }
    _clearOutput();
    _state = _defaultState();
    _requests = {};
    _reqFilter = {};
    renderAll();
    _openDefaultView();
    _setInfo('No scan data — enter a target, optionally an intercept log, and click Scan HTTP Headers');
    _toast('Header scan results cleared', 'info');
  }

  function _rank(severity) {
    const r = SEVERITY_RANK[severity];
    return r === undefined ? 1 : r;
  }

  function _statusOf(severity) {
    if (severity === 'CRITICAL' || severity === 'HIGH') return 'fail';
    if (severity === 'MEDIUM' || severity === 'LOW') return 'warn';
    if (severity === 'OK') return 'ok';
    return 'info';
  }

  function _asObject(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  function _stringify(value) {
    if (value === null || value === undefined) return '';
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  function _unique(list) {
    return [...new Set(list)];
  }

  function _firstDefined(list, picker) {
    for (const item of list) {
      const v = picker(item);
      if (v !== null && v !== undefined && v !== '') return v;
    }
    return null;
  }

  function _val(value) {
    return value === null || value === undefined || value === '' ? DASH : String(value);
  }

  function _dirValue(value) {
    if (value === null || value === undefined) return DASH;
    return Array.isArray(value) ? (value.join(' ') || DASH) : String(value);
  }

  function _ratio(n, total) {
    return `${n}/${total}`;
  }

  function _isAbsent(detail) {
    return /\b(missing|absent|not present|not set)\b/i.test(detail || '');
  }

  function _quoted(detail) {
    const m = /'([^']+)'/.exec(detail || '');
    return m ? m[1] : null;
  }

  function _worst(list) {
    return list.reduce((a, b) => (_rank(b.severity) > _rank(a.severity) ? b : a));
  }

  function _indexFindings(entries) {
    const index = {};
    entries.forEach(entry => {
      Object.values(_asObject(entry.modules)).forEach(mod => {
        (mod.findings || []).forEach(f => {
          const key = String(f.header || '').toLowerCase();
          if (!key) return;
          (index[key] = index[key] || []).push({
            entryId:  entry.id,
            module:   mod.module,
            severity: String(f.severity || 'INFO').toUpperCase(),
            detail:   f.detail || ''
          });
        });
      });
    });
    return index;
  }

  function _metaList(entries, moduleName, key) {
    const out = [];
    entries.forEach(entry => {
      const mod = _asObject(entry.modules)[moduleName];
      const v   = mod && mod.metadata ? mod.metadata[key] : null;
      if (v && typeof v === 'object') out.push(v);
    });
    return out;
  }

  function _headerMap(entries) {
    const map = new Map();
    const add = (name, value, debug) => {
      const key = String(name).toLowerCase();
      const cur = map.get(key);
      if (cur) { cur.count++; return; }
      map.set(key, { name: String(name), value: _stringify(value), count: 1, debug: !!debug });
    };
    entries.forEach(entry => {
      const leak = _asObject(_asObject(entry.modules)[MODULE.leak]).metadata || {};
      Object.entries(_asObject(_asObject(leak.backend_fingerprints).fingerprint_headers)).forEach(([k, v]) => add(k, v, false));
      Object.entries(_asObject(_asObject(leak.debug_headers).debug_headers_found)).forEach(([k, v]) => add(k, v, true));
    });
    return map;
  }

  function _hv(map, key) {
    const item = map.get(key);
    return item && item.value ? item.value : null;
  }

  function _overall(entries) {
    const scores = [];
    const tally  = {};
    entries.forEach(e => {
      const sc = e.score || {};
      if (typeof sc.score === 'number') scores.push(sc.score);
      if (sc.grade) tally[sc.grade] = (tally[sc.grade] || 0) + 1;
    });
    const rank   = g => { const i = GRADE_ORDER.indexOf(g); return i === -1 ? GRADE_ORDER.length : i; };
    const grades = Object.keys(tally);
    const grade  = grades.length
      ? grades.reduce((a, b) => (tally[b] > tally[a] || (tally[b] === tally[a] && rank(b) > rank(a)) ? b : a))
      : null;
    const score  = scores.length ? Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10 : null;
    return { grade, score };
  }

  function _findingsCard(list, total) {
    if (!list || !list.length) return null;
    const worst   = _worst(list);
    const same    = list.filter(f => f.severity === worst.severity).length;
    const present = list.filter(f => !_isAbsent(f.detail));
    return {
      status:  _statusOf(worst.severity),
      present: `${present.length > 0 ? 'Yes' : 'No'} (${_ratio(present.length, total)})`,
      value:   _firstDefined(present, f => _quoted(f.detail)) || DASH,
      verdict: `${worst.detail} (${_ratio(same, total)})`
    };
  }

  function _entryUrl(entry, i) {
    const v = entry.url || entry.request_url || entry.final_url || entry.endpoint || entry.target || entry.uri || entry.path || entry.id;
    return v ? String(v) : `Request #${i + 1}`;
  }

  function _entryFindings(entry, header) {
    const out = [];
    Object.values(_asObject(entry.modules)).forEach(mod => {
      (mod.findings || []).forEach(f => {
        if (String(f.header || '').toLowerCase() === header) {
          out.push({ severity: String(f.severity || 'INFO').toUpperCase(), detail: f.detail || '' });
        }
      });
    });
    return out;
  }

  function _requestRows(entries) {
    const result = {};
    REQ_KEYS.forEach(k => { result[k] = []; });

    entries.forEach((entry, i) => {
      const url  = _entryUrl(entry, i);
      const mods = _asObject(entry.modules);
      const secMeta  = _asObject(_asObject(mods[MODULE.security]).metadata);
      const corsMeta = _asObject(_asObject(mods[MODULE.cors]).metadata);

      const fromFindings = (key, absentWhenEmpty) => {
        const list = _entryFindings(entry, REQ_HEADER[key]);
        if (!list.length) {
          return absentWhenEmpty
            ? { present: false, status: 'info', value: DASH, note: 'Header not sent' }
            : { present: null, status: 'none', value: DASH, note: 'Not analyzed' };
        }
        const worst   = _worst(list);
        const absent  = list.every(f => _isAbsent(f.detail));
        return {
          present: !absent,
          status:  _statusOf(worst.severity),
          value:   absent ? DASH : (_firstDefined(list, f => _quoted(f.detail)) || DASH),
          note:    worst.detail
        };
      };

      let row;

      const hsts = secMeta.hsts;
      if (hsts && typeof hsts === 'object') {
        const base = fromFindings('hsts', false);
        const live = !!hsts.present;
        const parts = [];
        if (live && typeof hsts.max_age === 'number') parts.push(`max-age=${hsts.max_age}`);
        if (live && hsts.include_subdomains) parts.push('includeSubDomains');
        if (live && hsts.preload) parts.push('preload');
        result.hsts.push({ url, present: live, status: base.present === null ? (live ? 'ok' : 'fail') : base.status, value: parts.join('; ') || DASH, note: base.present === null ? (live ? 'Header present' : 'Header missing') : base.note });
      } else {
        row = fromFindings('hsts', false);
        result.hsts.push({ url, ...row });
      }

      const csp = secMeta.csp;
      if (csp && typeof csp === 'object') {
        const base = fromFindings('csp', false);
        const live = !!csp.present;
        const dirs = _asObject(csp.directives);
        const names = Object.keys(dirs);
        const unsafe = (csp.unsafe_sources || []).length;
        const value = live
          ? (`${names.length} directive${names.length === 1 ? '' : 's'}` + (unsafe ? `, ${unsafe} unsafe` : ''))
          : DASH;
        result.csp.push({ url, present: live, status: base.present === null ? (live ? 'ok' : 'fail') : base.status, value, note: base.present === null ? (live ? 'Header present' : 'Header missing') : base.note });
      } else {
        result.csp.push({ url, ...fromFindings('csp', false) });
      }

      result.xcto.push({ url, ...fromFindings('xcto', false) });
      result.xss.push({ url, ...fromFindings('xss', true) });
      result.xfo.push({ url, ...fromFindings('xfo', false) });
      result.referrer.push({ url, ...fromFindings('referrer', false) });

      const cacheMeta = _asObject(_asObject(mods[MODULE.cache]).metadata);
      const cache = cacheMeta.cache;
      if (cache && typeof cache === 'object') {
        const base = fromFindings('cc', false);
        const live = !!cache.cache_control;
        result.cc.push({ url, present: live, status: base.present === null ? (live ? 'ok' : 'fail') : base.status, value: live ? String(cache.cache_control) : DASH, note: base.present === null ? (live ? 'Header present' : 'Header missing') : base.note });
      } else {
        result.cc.push({ url, ...fromFindings('cc', false) });
      }

      const cookieMetas = [mods[MODULE.cookie], mods[MODULE.leak]]
        .map(m => _asObject(_asObject(m).metadata))
        .filter(m => m.cookies && typeof m.cookies === 'object')
        .map(m => m.cookies);
      if (cookieMetas.length) {
        const names = new Set();
        cookieMetas.forEach(c => {
          const found = c.cookies_found;
          if (Array.isArray(found)) {
            found.forEach(item => {
              const name = typeof item === 'string' ? item : (item && item.name);
              if (name) names.add(String(name));
            });
          } else if (found && typeof found === 'object') {
            Object.keys(found).forEach(name => names.add(name));
          }
        });
        cookieMetas.forEach(c => {
          if (Array.isArray(c.set_cookie)) c.set_cookie.forEach(item => { if (item && item.name) names.add(String(item.name)); });
        });
        const flagsMissing = ['missing_httponly_flag', 'missing_secure_flag', 'missing_samesite_flag']
          .some(k => cookieMetas.some(c => Array.isArray(c[k]) && c[k].length))
          || cookieMetas.some(c => Array.isArray(c.set_cookie) && c.set_cookie.some(item => item && (item.httponly === false || item.secure === false || !item.samesite)));
        const live = names.size > 0;
        result.sc.push({
          url,
          present: live,
          status: live ? (flagsMissing ? 'warn' : 'ok') : 'info',
          value: live ? Array.from(names).join(', ') : DASH,
          note: live ? (flagsMissing ? 'Cookie flags missing' : 'Cookie flags set') : 'Header not sent'
        });
      } else {
        result.sc.push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' });
      }

      const leakMeta = _asObject(_asObject(mods[MODULE.leak]).metadata);
      const hasLeakMeta = !!mods[MODULE.leak];
      const fpHeaders = Object.assign(
        {},
        _asObject(_asObject(leakMeta.backend_fingerprints).fingerprint_headers)
      );
      const dbgHeaders = _asObject(_asObject(leakMeta.debug_headers).debug_headers_found);

      if (hasLeakMeta) {
        const rlKeys = ['retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'];
        const rlFound = Object.entries(fpHeaders)
          .filter(([k]) => rlKeys.includes(k.toLowerCase()))
          .map(([k, v]) => `${k.toLowerCase()}=${_stringify(v)}`);
        result.rl.push({
          url,
          present: rlFound.length > 0,
          status: rlFound.length ? 'ok' : 'info',
          value: rlFound.length ? rlFound.join(', ') : DASH,
          note: rlFound.length ? 'Rate limit headers present' : 'Header not sent'
        });

        const customFound = [];
        Object.entries(fpHeaders).forEach(([k, v]) => {
          if (!HANDLED_HEADERS.has(k.toLowerCase())) customFound.push({ name: k, category: classifyCustom(k), risk: classifyCustomRisk(k) });
        });
        Object.keys(dbgHeaders).forEach(k => {
          if (!HANDLED_HEADERS.has(k.toLowerCase())) customFound.push({ name: k, category: 'debug', risk: 'High' });
        });
        const riskyCat = customFound.some(c => c.risk === 'High' || c.risk === 'Critical');
        result.cat.push({
          url,
          present: customFound.length > 0,
          status: customFound.length ? (riskyCat ? 'warn' : 'ok') : 'info',
          value: customFound.length ? customFound.map(c => `${c.name} (${c.category})`).join(', ') : DASH,
          note: customFound.length ? _unique(customFound.map(c => c.category)).join(', ') : 'No custom headers'
        });
      } else {
        result.rl.push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' });
        result.cat.push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' });
      }

      const fpLookup = name => {
        const hit = Object.keys(fpHeaders).find(k => k.toLowerCase() === name);
        return hit ? _stringify(fpHeaders[hit]) : null;
      };
      const srvPush = (key, value, version) => {
        if (!hasLeakMeta) { result[key].push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' }); return; }
        result[key].push({
          url,
          present: !!value,
          status: value ? (version ? 'warn' : 'info') : 'ok',
          value: value || DASH,
          note: value ? (version ? 'Version disclosed' : 'Header present') : 'Header not sent'
        });
      };
      const srvInfo = _asObject(leakMeta.server_info);
      const pwrInfo = _asObject(leakMeta.powered_by);
      srvPush('server', srvInfo.raw_server || null, !!srvInfo.version_leaked || !!srvInfo.version_string);
      srvPush('xpb',    pwrInfo.raw_x_powered_by || null, !!pwrInfo.version_leaked);
      srvPush('xasp',   pwrInfo.raw_x_aspnet_version || null, !!pwrInfo.raw_x_aspnet_version);
      srvPush('xrt',    fpLookup('x-runtime'), false);
      srvPush('via',    fpLookup('via'), false);
      srvPush('xsrv',   fpLookup('x-served-by'), false);
      srvPush('xgen',   fpLookup('x-generator'), false);

      if (hasLeakMeta) {
        const invItems = [];
        Object.entries(fpHeaders).forEach(([k, v]) => {
          if (!HANDLED_HEADERS.has(k.toLowerCase())) invItems.push({ name: k, value: _stringify(v), category: classifyCustom(k), risk: classifyCustomRisk(k) });
        });
        Object.entries(dbgHeaders).forEach(([k, v]) => {
          if (!HANDLED_HEADERS.has(k.toLowerCase())) invItems.push({ name: k, value: _stringify(v), category: 'debug', risk: 'High' });
        });
        const invRisky = invItems.some(c => c.risk === 'High' || c.risk === 'Critical');
        result.inv.push({
          url,
          present: invItems.length > 0,
          status: invItems.length ? (invRisky ? 'warn' : 'ok') : 'info',
          value: invItems.length ? invItems.map(c => `${c.name}: ${c.value}`).join(' | ') : DASH,
          note: invItems.length ? `${invItems.length} custom header(s)` : 'No custom headers'
        });
      } else {
        result.inv.push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' });
      }

      const ckMod = mods[MODULE.cookie];
      const ckMeta = _asObject(_asObject(_asObject(ckMod).metadata).cookies);
      const ckItems = [].concat(Array.isArray(ckMeta.set_cookie) ? ckMeta.set_cookie : [], Array.isArray(ckMeta.request_cookie) ? ckMeta.request_cookie : [])
        .filter(c => c && c.name);
      const ckPush = (key, matches, fmt, emptyNote) => {
        if (!ckMod) { result[key].push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' }); return; }
        result[key].push({
          url,
          present: matches.length > 0,
          status: matches.length ? 'info' : 'ok',
          value: matches.length ? matches.map(fmt).join(', ') : DASH,
          note: matches.length ? `${matches.length} cookie(s)` : (ckItems.length ? emptyNote : 'No cookies observed')
        });
      };
      ckPush('ckfp',  ckItems.filter(c => c.fingerprint), c => `${c.name}: ${c.fingerprint}`, 'No cookie identified');
      ckPush('ckcat', ckItems.filter(c => c.category),    c => `${c.name} (${c.category})`,    'No cookie categorized');
      const jwtItems = ckItems.filter(c => c.value_type === 'jwt');
      if (!ckMod) {
        result.ckjwt.push({ url, present: null, status: 'none', value: DASH, note: 'Not analyzed' });
      } else {
        const algs = jwtItems.map(c => `${c.name} (${_parseJwt(c.decoded ? String(c.decoded) : '').alg || 'unspecified'})`);
        const unsigned = jwtItems.some(c => { const a = _parseJwt(c.decoded ? String(c.decoded) : '').alg; return !a || /^none$/i.test(a); });
        result.ckjwt.push({
          url,
          present: jwtItems.length > 0,
          status: jwtItems.length ? (unsigned ? 'fail' : 'info') : 'ok',
          value: jwtItems.length ? algs.join(', ') : DASH,
          note: jwtItems.length ? (unsigned ? 'Unsigned or unspecified algorithm' : `${jwtItems.length} JWT cookie(s)`) : (ckItems.length ? 'No JWT cookie' : 'No cookies observed')
        });
      }

      const wsMeta = Object.values(mods)
        .map(m => _asObject(_asObject(m).metadata).websocket)
        .find(w => w && typeof w === 'object');
      if (wsMeta) {
        const outcome = String(wsMeta.outcome || '');
        const parts = [];
        if (wsMeta.status_code !== undefined && wsMeta.status_code !== null) parts.push(String(wsMeta.status_code));
        if (wsMeta.subprotocol_selected) parts.push(String(wsMeta.subprotocol_selected));
        result.ws.push({
          url: wsMeta.endpoint ? String(wsMeta.endpoint) : url,
          present: outcome === 'accepted' ? true : (outcome === 'rejected' ? false : null),
          status: outcome === 'accepted' ? 'ok' : (outcome === 'rejected' ? 'fail' : 'info'),
          value: parts.join(' · ') || DASH,
          note: wsMeta.origin ? `Origin: ${wsMeta.origin}` : (outcome || DASH)
        });
      }

      const cors = corsMeta.cors;
      if (cors && typeof cors === 'object') {
        const base = fromFindings('cors', false);
        const live = !!cors.allow_origin_header_present;
        let note = live ? 'CORS active' : 'CORS inactive';
        if (cors.wildcard_origin) note = 'Wildcard origin';
        else if (cors.null_origin_allowed) note = 'null origin allowed';
        else if (cors.reflects_origin) note = 'Reflects origin';
        result.cors.push({ url, present: live, status: base.present === null ? (live ? 'ok' : 'info') : base.status, value: live ? _val(cors.allow_origin_value) : DASH, note: base.present === null ? note : base.note });
      } else {
        result.cors.push({ url, ...fromFindings('cors', true) });
      }
    });

    return result;
  }

  function _securityState(entries, idx, total) {
    const sec = _blankSecurity();

    const hstsMeta    = _metaList(entries, MODULE.security, 'hsts');
    const hstsCard    = _findingsCard(idx['strict-transport-security'], total);
    const hstsLive    = hstsMeta.filter(h => h.present);
    const hstsAges    = hstsLive.map(h => h.max_age).filter(a => typeof a === 'number');
    const hstsMaxAge  = hstsAges.length ? Math.max(...hstsAges) : null;
    sec.hsts = {
      status:     hstsCard ? hstsCard.status : (hstsMeta.length ? (hstsLive.length ? 'ok' : 'fail') : 'none'),
      present:    hstsMeta.length ? `${hstsLive.length ? 'Yes' : 'No'} (${_ratio(hstsLive.length, total)})` : DASH,
      maxAge:     hstsMaxAge !== null ? `${hstsMaxAge}s (${Math.floor(hstsMaxAge / 86400)}d)` : DASH,
      subDomains: hstsMeta.length ? (hstsLive.some(h => h.include_subdomains) ? 'Yes' : 'No') : DASH,
      preload:    hstsMeta.length ? (hstsLive.some(h => h.preload) ? 'Yes' : 'No') : DASH,
      verdict:    hstsCard ? hstsCard.verdict : DASH
    };

    const cspMeta   = _metaList(entries, MODULE.security, 'csp');
    const cspCard   = _findingsCard(idx['content-security-policy'], total);
    const cspLive   = cspMeta.filter(c => c.present);
    const cspSample = cspLive[0] || null;
    const dirs      = cspSample ? _asObject(cspSample.directives) : {};
    const unsafe    = _unique(cspLive.flatMap(c => (c.unsafe_sources || []).map(String)));
    sec.csp = {
      status:  cspCard ? cspCard.status : (cspMeta.length ? (cspLive.length ? 'ok' : 'fail') : 'none'),
      present: cspMeta.length ? `${cspLive.length ? 'Yes' : 'No'} (${_ratio(cspLive.length, total)})` : DASH,
      def:     cspSample ? _dirValue(dirs['default-src']) : DASH,
      script:  cspSample ? _dirValue(dirs['script-src'])  : DASH,
      style:   cspSample ? _dirValue(dirs['style-src'])   : DASH,
      object:  cspSample ? _dirValue(dirs['object-src'])  : DASH,
      frame:   cspSample ? _dirValue(dirs['frame-ancestors'] ?? dirs['frame-src']) : DASH,
      report:  cspSample ? _dirValue(dirs['report-uri'] ?? dirs['report-to'])      : DASH,
      unsafe:  cspMeta.length ? (unsafe.length ? unsafe.join(', ') : 'No') : DASH,
      verdict: cspCard ? cspCard.verdict : DASH
    };

    const simple = (key, absentNote) => {
      const card = _findingsCard(idx[key], total);
      if (card) return card;
      if (absentNote) return { status: 'info', present: `No (0/${total})`, value: DASH, verdict: absentNote };
      return { status: 'none', present: DASH, value: DASH, verdict: 'Not analyzed' };
    };

    sec.xcto     = simple('x-content-type-options');
    sec.xss      = simple('x-xss-protection', 'Header not sent (legacy, CSP preferred)');
    sec.referrer = simple('referrer-policy');

    const frameAncestors = cspLive.map(c => _asObject(c.directives)['frame-ancestors']).find(v => v !== undefined);
    sec.xfo = {
      ...simple('x-frame-options'),
      csp: frameAncestors !== undefined ? _dirValue(frameAncestors) : (cspMeta.length ? 'frame-ancestors not set' : DASH)
    };

    const corsMeta = _metaList(entries, MODULE.cors, 'cors');
    const corsCard = _findingsCard(idx['cors'], total);
    const corsRep  = corsMeta.find(c => c.allow_origin_header_present) || corsMeta[0] || null;
    let wildcard   = corsMeta.length ? 'Restricted' : DASH;
    if (corsMeta.some(c => c.wildcard_origin))        wildcard = '⚠ Wildcard';
    else if (corsMeta.some(c => c.null_origin_allowed)) wildcard = '⚠ null origin';
    else if (corsMeta.some(c => c.reflects_origin))   wildcard = '⚠ Reflects Origin';
    sec.cors = {
      status:      corsCard ? corsCard.status : 'none',
      aca:         corsRep ? (corsRep.allow_origin_header_present ? _val(corsRep.allow_origin_value) : 'Not present (CORS inactive)') : DASH,
      credentials: corsRep ? _val(corsRep.allow_credentials) : DASH,
      methods:     corsRep ? _val(corsRep.allow_methods) : DASH,
      headers:     corsRep ? _val(corsRep.allow_headers) : DASH,
      expose:      corsRep ? _val(corsRep.expose_headers) : DASH,
      maxage:      corsRep ? _val(corsRep.max_age) : DASH,
      wildcard,
      verdict:     corsCard ? corsCard.verdict : DASH
    };

    return sec;
  }

  function _serverState(entries, hmap) {
    const serverMeta  = _metaList(entries, MODULE.leak, 'server_info');
    const poweredMeta = _metaList(entries, MODULE.leak, 'powered_by');
    const rawServer   = _firstDefined(serverMeta, s => s.raw_server);
    const versionStr  = _firstDefined(serverMeta, s => s.version_string);
    const sensitive   = serverMeta.some(s => s.sensitive_info_leaked);
    const verLeaked   = serverMeta.some(s => s.version_leaked);
    const poweredRaw  = _firstDefined(poweredMeta, p => p.raw_x_powered_by);
    const aspnetRaw   = _firstDefined(poweredMeta, p => p.raw_x_aspnet_version);
    const techs       = _unique(poweredMeta.flatMap(p => (p.identified_technologies || []).map(String)));
    const poweredVer  = poweredMeta.some(p => p.version_leaked);

    let cveRisk = DASH;
    if (rawServer) {
      cveRisk = sensitive ? 'Sensitive information leaked'
              : verLeaked ? 'Version disclosed — check CVE database'
              : 'No version disclosed';
    }

    const via  = _hv(hmap, 'via');
    const xsrv = _hv(hmap, 'x-served-by');
    const xgen = _hv(hmap, 'x-generator');
    const xrt  = _hv(hmap, 'x-runtime');

    const server = {
      'server':           { value: rawServer, version: versionStr || (rawServer ? (verLeaked ? 'Yes' : 'No') : DASH), cve: cveRisk, exposed: !!versionStr || verLeaked },
      'x-powered-by':     { value: poweredRaw, framework: techs.join(', ') || poweredRaw || DASH, exposed: poweredVer },
      'x-aspnet-version': { value: aspnetRaw, version: aspnetRaw || DASH, exposed: !!aspnetRaw },
      'x-runtime':        { value: xrt, lang: xrt || DASH, exposed: false },
      'via':              { value: via, proxy: via ? (via.split(' ')[1] || via) : DASH, exposed: false },
      'x-served-by':      { value: xsrv, leak: xsrv ? 'Yes' : DASH, exposed: false },
      'x-generator':      { value: xgen, cms: xgen || DASH, exposed: false }
    };

    const leaked = Object.values(server).filter(s => s.value).length;
    let risk = 'LOW';
    if (sensitive || leaked > 3) risk = 'HIGH';
    else if (leaked > 1 || verLeaked) risk = 'MEDIUM';

    return { server, risk };
  }

  function parseCacheControl(val) {
    if (!val) return { value: DASH, noStore: DASH, noCache: DASH, scope: DASH, maxAge: DASH, sMaxage: DASH };
    return {
      value:   val,
      noStore: /no-store/i.test(val) ? 'Yes' : 'No',
      noCache: /no-cache/i.test(val) ? 'Yes' : 'No',
      scope:   /private/i.test(val) ? 'private' : /public/i.test(val) ? 'public' : DASH,
      maxAge:  (val.match(/max-age=(\d+)/i) || [])[1] || DASH,
      sMaxage: (val.match(/s-maxage=(\d+)/i) || [])[1] || DASH
    };
  }

  function _cacheState(entries, idx, total) {
    const cacheList = _metaList(entries, MODULE.cache, 'cache');
    const card      = _findingsCard(idx['cache-control'], total);
    let rep = null;
    if (idx['cache-control']) {
      const worst      = _worst(idx['cache-control']);
      const worstEntry = entries.find(e => String(e.id) === String(worst.entryId));
      const meta       = worstEntry ? _asObject(_asObject(worstEntry.modules)[MODULE.cache]).metadata : null;
      if (meta && meta.cache && meta.cache.cache_control) rep = meta.cache;
    }
    rep = rep || cacheList.find(c => c.cache_control) || cacheList[0] || null;
    return {
      'cache-control': parseCacheControl(rep ? rep.cache_control : null),
      verdict:         card ? { status: card.status, text: card.verdict } : null
    };
  }

  function _authState(entries, idx) {
    const cookieMeta = _metaList(entries, MODULE.leak, 'cookies').concat(_metaList(entries, MODULE.cookie, 'cookies'));
    const names   = new Set();
    const details = [];
    cookieMeta.forEach(c => {
      const found = c.cookies_found;
      if (Array.isArray(found)) {
        found.forEach(item => {
          const name = typeof item === 'string' ? item : (item && item.name);
          if (name) names.add(String(name));
          if (item && typeof item === 'object') details.push(item);
        });
      } else if (found && typeof found === 'object') {
        Object.entries(found).forEach(([name, item]) => {
          names.add(name);
          if (item && typeof item === 'object') details.push(item);
        });
      }
    });
    const missing = key => new Set(cookieMeta.flatMap(c => (Array.isArray(c[key]) ? c[key].map(String) : [])));
    const noHttp = missing('missing_httponly_flag');
    const noSec  = missing('missing_secure_flag');
    const noSame = missing('missing_samesite_flag');
    cookieMeta.forEach(c => {
      if (!Array.isArray(c.set_cookie)) return;
      c.set_cookie.forEach(item => {
        if (!item || !item.name) return;
        names.add(String(item.name));
        details.push(item);
        if (item.httponly === false) noHttp.add(String(item.name));
        if (item.secure === false) noSec.add(String(item.name));
        if (!item.samesite) noSame.add(String(item.name));
      });
    });
    const detail = (...keys) => _val(_firstDefined(details, d => keys.map(k => d[k]).find(v => v !== undefined && v !== null && v !== '')));

    const setCookie = names.size ? {
      count:    String(names.size),
      httponly: noHttp.size ? `Missing on ${noHttp.size}` : 'Yes',
      secure:   noSec.size  ? `Missing on ${noSec.size}`  : 'Yes',
      samesite: noSame.size ? `Missing on ${noSame.size}` : 'Set',
      domain:   detail('domain'),
      maxage:   detail('max_age', 'max-age', 'expires'),
      session:  detail('session', 'persistent'),
      observed: true,
      ok:       noHttp.size === 0 && noSec.size === 0 && noSame.size === 0
    } : { count: '0', httponly: 'No', secure: 'No', samesite: DASH, domain: DASH, maxage: DASH, session: DASH, observed: false, ok: false };

    return { 'set-cookie': setCookie };
  }

  function _cookieIntelFromReport(report) {
    return report.cookies.filter(c => c && c.name).map(c => ({
      name:           String(c.name),
      fingerprint:    c.fingerprint ? String(c.fingerprint) : null,
      category:       c.category ? String(c.category) : null,
      sensitive:      !!c.sensitive,
      valueType:      c.value_type ? String(c.value_type) : null,
      decoded:        c.decoded ? (typeof c.decoded === 'string' ? c.decoded : JSON.stringify(c.decoded)) : null,
      jwt:            c.jwt && typeof c.jwt === 'object' ? c.jwt : null,
      providerTokens: Array.isArray(c.provider_tokens) ? c.provider_tokens.map(String) : []
    }));
  }

  function _setCookieFromReport(report) {
    const issued = report.cookies.filter(c => c && Array.isArray(c.attribute_sets) && c.attribute_sets.length);
    if (!issued.length) return null;
    const sets   = c => c.attribute_sets.filter(a => a && typeof a === 'object');
    const noHttp = issued.filter(c => sets(c).some(a => a.httponly === false)).length;
    const noSec  = issued.filter(c => sets(c).some(a => a.secure === false)).length;
    const noSame = issued.filter(c => sets(c).some(a => !a.samesite)).length;
    const first  = key => _val(_firstDefined(issued.flatMap(sets), a => (a[key] !== undefined && a[key] !== null && a[key] !== '' ? a[key] : undefined)));
    const sessionCount = issued.filter(c => sets(c).some(a => a.lifetime_seconds === null || a.lifetime_seconds === undefined)).length;
    const domain = first('domain');
    const path   = first('path');
    return {
      count:    String(issued.length),
      httponly: noHttp ? `Missing on ${noHttp}` : 'Yes',
      secure:   noSec  ? `Missing on ${noSec}`  : 'Yes',
      samesite: noSame ? `Missing on ${noSame}` : 'Set',
      domain:   domain !== DASH && path !== DASH ? `${domain} ${path}` : (domain !== DASH ? domain : path),
      maxage:   first('max_age') !== DASH ? first('max_age') : first('expires'),
      session:  sessionCount ? `${sessionCount} of ${issued.length}` : 'None',
      observed: true,
      ok:       noHttp === 0 && noSec === 0 && noSame === 0
    };
  }

  function _cookieIntelState(entries) {
    const map = new Map();
    entries.forEach(entry => {
      const mod  = _asObject(_asObject(entry.modules)[MODULE.cookie]);
      const meta = _asObject(_asObject(mod.metadata).cookies);
      ['set_cookie', 'request_cookie'].forEach(direction => {
        (Array.isArray(meta[direction]) ? meta[direction] : []).forEach(item => {
          if (!item || !item.name) return;
          const key = String(item.name);
          const cur = map.get(key) || { name: key, fingerprint: null, category: null, sensitive: false, valueType: null, decoded: null, providerTokens: [] };
          if (item.fingerprint) cur.fingerprint = String(item.fingerprint);
          if (item.category) cur.category = String(item.category);
          cur.sensitive = cur.sensitive || !!item.sensitive;
          if (item.value_type) cur.valueType = String(item.value_type);
          if (item.decoded) cur.decoded = String(item.decoded);
          (Array.isArray(item.provider_tokens) ? item.provider_tokens : []).forEach(t => {
            if (!cur.providerTokens.includes(String(t))) cur.providerTokens.push(String(t));
          });
          map.set(key, cur);
        });
      });
    });
    return Array.from(map.values());
  }

  function _parseJwt(decoded) {
    const out = { alg: null, exp: null, iss: null, aud: null, claims: [] };
    if (!decoded) return out;
    try {
      const obj = JSON.parse(decoded);
      const header  = _asObject(obj.header);
      const payload = _asObject(obj.payload);
      out.alg = header.alg ? String(header.alg) : null;
      out.exp = typeof payload.exp === 'number' ? payload.exp : null;
      out.iss = payload.iss ? String(payload.iss) : null;
      out.aud = payload.aud ? String(Array.isArray(payload.aud) ? payload.aud.join(', ') : payload.aud) : null;
      out.claims = Object.keys(payload);
      return out;
    } catch (err) {
      const alg = /"alg"\s*:\s*"([^"]+)"/.exec(decoded);
      const exp = /"exp"\s*:\s*(\d+)/.exec(decoded);
      out.alg = alg ? alg[1] : null;
      out.exp = exp ? Number(exp[1]) : null;
      return out;
    }
  }

  function classifyCustom(name) {
    const lower = name.toLowerCase();
    if (/debug|dump|trace/i.test(lower))              return 'debug';
    if (/internal|backend|private/i.test(lower))      return 'internal';
    if (/env|environment|config|conf/i.test(lower))   return 'env';
    if (/version|api.ver/i.test(lower))               return 'version';
    if (/request.id|trace.id|correlation/i.test(lower)) return 'trace';
    if (/forwarded|real.ip|proxy|^cf-|cache-status|^age$|x-cache/i.test(lower)) return 'proxy';
    return 'info';
  }

  function classifyCustomRisk(name) {
    const lower = name.toLowerCase();
    if (/secret|token|pass|key|credential/i.test(lower))     return 'Critical';
    if (/debug|dump|internal|backend|env|config/i.test(lower)) return 'High';
    if (/version|api.ver/i.test(lower))                      return 'Medium';
    return 'Low';
  }

  function _customState(hmap) {
    const out = [];
    hmap.forEach((item, key) => {
      if (HANDLED_HEADERS.has(key)) return;
      out.push({
        name:           item.name,
        value:          item.value,
        classification: item.debug ? 'debug' : classifyCustom(item.name),
        risk:           item.debug ? 'High' : classifyCustomRisk(item.name)
      });
    });
    return out;
  }

  function _websocketState(ws) {
    const totals    = _asObject(ws && ws.totals);
    const endpoints = Array.isArray(ws && ws.endpoints) ? ws.endpoints : [];
    const handshakes = Number(totals.handshakes) || 0;
    const accepted   = Number(totals.accepted) || 0;
    const rejected   = Number(totals.rejected) || 0;
    const other      = Number(totals.other_upgrades) || 0;
    const pick = (...keys) => {
      for (const ep of endpoints) {
        if (!ep || typeof ep !== 'object') continue;
        for (const k of keys) {
          if (ep[k] !== undefined && ep[k] !== null && ep[k] !== '') return String(ep[k]);
        }
      }
      return DASH;
    };
    const names = endpoints.map(ep => (typeof ep === 'string' ? ep : (ep && (ep.url || ep.endpoint || ep.path)))).filter(Boolean);
    let upgrade = 'No';
    if (handshakes > 0) upgrade = `Yes (${handshakes})`;
    else if (other > 0) upgrade = `Other upgrades: ${other}`;
    return {
      detected:    handshakes > 0 || other > 0,
      upgrade,
      key:         pick('sec_websocket_key', 'key'),
      accept:      pick('sec_websocket_accept', 'accept'),
      protocol:    pick('sec_websocket_protocol', 'protocol', 'subprotocol'),
      version:     pick('sec_websocket_version', 'version'),
      endpoint:    names.length ? names.join(', ') : (handshakes > 0 ? `${handshakes} handshake(s)` : 'No WebSocket endpoint detected'),
      originCheck: handshakes > 0 ? `${accepted} accepted / ${rejected} rejected` : DASH
    };
  }

  function analyzePayload(payload) {
    const entries = (payload.entries || []).filter(e => e && typeof e === 'object');
    const total   = entries.length;
    const idx     = _indexFindings(entries);
    const hmap    = _headerMap(entries);
    const overall = _overall(entries);

    _state.security = _securityState(entries, idx, total);
    _requests = _requestRows(entries);
    _reqFilter = {};

    const srv = _serverState(entries, hmap);
    _state.server     = srv.server;
    _state.serverRisk = srv.risk;

    _state.cache     = _cacheState(entries, idx, total);
    _state.auth      = _authState(entries, idx);

    _state.rateLimit = {
      'retry-after':           _hv(hmap, 'retry-after') || DASH,
      'x-ratelimit-limit':     _hv(hmap, 'x-ratelimit-limit') || DASH,
      'x-ratelimit-remaining': _hv(hmap, 'x-ratelimit-remaining') || DASH,
      'x-ratelimit-reset':     _hv(hmap, 'x-ratelimit-reset') || DASH
    };

    _state.custom    = _customState(hmap);
    const cookieReport = payload.cookie_report && Array.isArray(payload.cookie_report.cookies) ? payload.cookie_report : null;
    _state.cookieIntel = cookieReport ? _cookieIntelFromReport(cookieReport) : _cookieIntelState(entries);
    if (cookieReport) {
      const reportCookie = _setCookieFromReport(cookieReport);
      if (reportCookie) _state.auth['set-cookie'] = reportCookie;
    }
    _state.websocket = _websocketState(payload.websocket);

    let ok = 0, warn = 0, fail = 0, counted = 0;
    Object.values(_state.security).forEach(card => {
      if (card.status === 'none') return;
      counted++;
      if (card.status === 'ok') ok++;
      else if (card.status === 'warn') warn++;
      else if (card.status === 'fail') fail++;
    });
    _state.score = { ok, warn, fail, total: counted };

    const findings = entries.reduce((n, e) => n + Object.values(_asObject(e.modules)).reduce((m, mod) => m + (mod.findings || []).length, 0), 0);
    _state.summary = {
      domain:    payload.domain || DASH,
      grade:     overall.grade || DASH,
      score:     overall.score !== null ? overall.score : DASH,
      responses: total,
      findings
    };
  }

  function renderAll() {
    renderSecurity();
    renderAllRequests();
    renderServer();
    renderCache();
    renderAuth();
    renderRateLimit();
    renderCustom();
    renderCookieIntel();
    renderWebSocket();
    updateScore();
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = (text !== null && text !== undefined) ? String(text) : DASH;
  }

  function setClass(id, status) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'dcr-val';
    if (status === 'ok')   el.classList.add('ok-text');
    else if (status === 'warn' || status === 'info') el.classList.add('warn-text');
    else if (status === 'fail') el.classList.add('fail-text');
  }

  function _badge(status) {
    return { ok: '✓ OK', warn: '⚠ WARN', fail: 'FAIL', info: 'ℹ INFO' }[status] || DASH;
  }

  function _setStatusBadge(id, status) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = _badge(status);
    el.className = 'dns-section-badge' + (status === 'fail' ? ' hdr-badge-fail' : status === 'warn' ? ' hdr-badge-warn' : status === 'ok' ? ' ok' : ' dim');
  }

  function _renderSimpleCard(prefix, card) {
    _setStatusBadge(`hdr-${prefix}-badge`, card.status);
    setText(`hdr-${prefix}-present`, card.present);
    setText(`hdr-${prefix}-value`,   card.value);
    setText(`hdr-${prefix}-verdict`, card.verdict);
    setClass(`hdr-${prefix}-verdict`, card.status);
  }

  const SRV_LABELS = { present: 'Exposed', missing: 'Hidden', na: 'N/A' };
  const REQ_LABELS = {
    ws:     { present: 'Accepted', missing: 'Rejected', na: 'Other' },
    server: SRV_LABELS, xpb: SRV_LABELS, xasp: SRV_LABELS, xrt: SRV_LABELS, via: SRV_LABELS, xsrv: SRV_LABELS, xgen: SRV_LABELS,
    ckfp:   { present: 'Identified', missing: 'None', na: 'N/A' },
    ckcat:  { present: 'Categorized', missing: 'None', na: 'N/A' },
    ckjwt:  { present: 'JWT', missing: 'None', na: 'N/A' },
    inv:    { present: 'Found', missing: 'None', na: 'N/A' }
  };

  function _reqLabels(key) {
    return REQ_LABELS[key] || { present: 'Present', missing: 'Missing', na: 'N/A' };
  }

  function _reqStatusLabel(row, key) {
    const labels = _reqLabels(key);
    if (row.present === true)  return { cls: 'ok',   text: labels.present };
    if (row.present === false) return { cls: 'fail', text: labels.missing };
    return { cls: 'info', text: labels.na };
  }

  function renderRequests(key) {
    const rows  = _requests[key] || [];
    const panel = document.getElementById(`hdr-req-${key}-panel`);
    const count = document.getElementById(`hdr-req-${key}-count`);
    if (count) count.textContent = rows.length;
    if (!panel) return;

    if (!rows.length) {
      panel.innerHTML = `<div class="hdr-req-empty">${_state.payload ? 'No matching requests found.' : 'No requests to display. Run a scan first.'}</div>`;
      return;
    }

    const labels  = _reqLabels(key);
    const present = rows.filter(r => r.present === true).length;
    const missing = rows.filter(r => r.present === false).length;
    const na      = rows.length - present - missing;
    const filter  = _reqFilter[key] || 'all';
    const shown   = rows.filter(r => filter === 'all'
      || (filter === 'present' && r.present === true)
      || (filter === 'missing' && r.present === false)
      || (filter === 'na' && r.present === null));

    const pill = (f, label, n) =>
      `<button type="button" class="hdr-req-pill${filter === f ? ' active' : ''}" data-req-filter="${f}" data-req-key="${key}">${label}<span>${n}</span></button>`;

    panel.innerHTML = `
      <div class="hdr-req-toolbar">
        ${pill('all', 'All', rows.length)}
        ${pill('present', labels.present, present)}
        ${pill('missing', labels.missing, missing)}
        ${na ? pill('na', labels.na, na) : ''}
      </div>
      <div class="hdr-req-table">
        <div class="hdr-req-head">
          <div class="hdr-req-c-status">Status</div>
          <div class="hdr-req-c-url">URL</div>
          <div class="hdr-req-c-val">Value</div>
        </div>
        <div class="hdr-req-body">
          ${shown.length ? shown.map(r => {
            const st = _reqStatusLabel(r, key);
            return `<div class="hdr-req-row">
              <div class="hdr-req-c-status"><span class="hdr-req-badge ${st.cls}">${st.text}</span></div>
              <div class="hdr-req-c-url" title="${_esc(r.url)}">${_esc(r.url)}</div>
              <div class="hdr-req-c-val" title="${_esc(r.note || '')}">${_esc(r.value && r.value !== DASH ? r.value : (r.note || DASH))}</div>
            </div>`;
          }).join('') : '<div class="hdr-req-empty">No requests match this filter.</div>'}
        </div>
      </div>`;
  }

  function renderAllRequests() {
    REQ_KEYS.forEach(renderRequests);
  }

  function renderSecurity() {
    const s = _state.security;

    _setStatusBadge('hdr-hsts-badge', s.hsts.status);
    setText('hdr-hsts-present', s.hsts.present);
    setText('hdr-hsts-maxage',  s.hsts.maxAge);
    setText('hdr-hsts-sub',     s.hsts.subDomains);
    setText('hdr-hsts-preload', s.hsts.preload);
    setText('hdr-hsts-verdict', s.hsts.verdict);
    setClass('hdr-hsts-verdict', s.hsts.status);

    _setStatusBadge('hdr-csp-badge', s.csp.status);
    setText('hdr-csp-present', s.csp.present);
    setText('hdr-csp-default', s.csp.def);
    setText('hdr-csp-script',  s.csp.script);
    setText('hdr-csp-style',   s.csp.style);
    setText('hdr-csp-object',  s.csp.object);
    setText('hdr-csp-frame',   s.csp.frame);
    setText('hdr-csp-report',  s.csp.report);
    setText('hdr-csp-unsafe',  s.csp.unsafe);
    setText('hdr-csp-verdict', s.csp.verdict);
    setClass('hdr-csp-verdict', s.csp.status);

    _renderSimpleCard('xcto', s.xcto);
    _renderSimpleCard('xss', s.xss);
    _renderSimpleCard('xfo', s.xfo);
    setText('hdr-xfo-csp', s.xfo.csp);
    _renderSimpleCard('referrer', s.referrer);

    _setStatusBadge('hdr-cors-badge', s.cors.status);
    setText('hdr-cors-aca',         s.cors.aca);
    setText('hdr-cors-credentials', s.cors.credentials);
    setText('hdr-cors-methods',     s.cors.methods);
    setText('hdr-cors-headers',     s.cors.headers);
    setText('hdr-cors-expose',      s.cors.expose);
    setText('hdr-cors-maxage',      s.cors.maxage);
    setText('hdr-cors-wildcard',    s.cors.wildcard);
    setText('hdr-cors-verdict',     s.cors.verdict);
    setClass('hdr-cors-verdict',    s.cors.status);
  }

  const SRV_FIELDS = [
    { key: 'server',           sec: 'sec-hdr-server', badge: 'hdr-server-badge', labels: ['Software', 'Platform', 'Raw Header', 'Version Exposed', 'CVE Risk'] },
    { key: 'x-powered-by',     sec: 'sec-hdr-xpb',    badge: 'hdr-xpb-badge',    labels: ['Technology', 'Framework', 'Raw Header', 'Version Exposed'] },
    { key: 'x-aspnet-version', sec: 'sec-hdr-xasp',   badge: 'hdr-xasp-badge',   labels: ['.NET Version', 'Raw Header', 'Version Exposed'] },
    { key: 'x-runtime',        sec: 'sec-hdr-xrt',    badge: 'hdr-xrt-badge',    labels: ['Duration', 'Raw Header'] },
    { key: 'via',              sec: 'sec-hdr-via',    badge: 'hdr-via-badge',    labels: ['Hops', 'Proxy / CDN', 'Raw Header'] },
    { key: 'x-served-by',      sec: 'sec-hdr-xsrv',   badge: 'hdr-xsrv-badge',   labels: ['Hosts', 'Internal Host Leak', 'Raw Header'] },
    { key: 'x-generator',      sec: 'sec-hdr-xgen',   badge: 'hdr-xgen-badge',   labels: ['Generator', 'CMS / Framework', 'Raw Header'] }
  ];

  function _chip(text) {
    return `<span class="hdr-chip">${_esc(text)}</span>`;
  }

  function _comp(name, version) {
    return `<span class="hdr-comp">${_esc(name)}${version ? `<em>${_esc(version)}</em>` : ''}</span>`;
  }

  function _chipList(items) {
    return items.length ? `<span class="hdr-chip-list">${items.join('')}</span>` : null;
  }

  function _parseComponents(raw) {
    const platform = [];
    const stripped = String(raw).replace(/\(([^)]*)\)/g, (_, p) => { platform.push(p.trim()); return ' '; });
    const comps = stripped.split(/\s+/).filter(Boolean).map(tok => {
      const m = /^([^/]+)\/(.+)$/.exec(tok);
      return m ? { name: m[1], version: m[2] } : { name: tok, version: null };
    });
    return { comps, platform };
  }

  function _splitList(raw) {
    return String(raw).split(',').map(x => x.trim()).filter(Boolean);
  }

  function _rawBlock(raw) {
    return `<span class="hdr-raw" title="${_esc(raw)}">${_esc(raw)}</span>`;
  }

  function _flag(text, level) {
    return { html: _esc(text), cls: level };
  }

  function _serverRows(key, s) {
    const raw = String(s.value);
    const exposed = s.exposed ? _flag('Yes', 'warn-text') : _flag('No', 'ok-text');

    if (key === 'server') {
      const p = _parseComponents(raw);
      return [
        ['Software', { html: _chipList(p.comps.map(c => _comp(c.name, c.version))) || DASH }],
        ['Platform', { html: _chipList(p.platform.map(x => _chip(x))) || DASH }],
        ['Raw Header', { html: _rawBlock(raw) }],
        ['Version Exposed', exposed],
        ['CVE Risk', _flag(s.cve || DASH, s.exposed ? 'warn-text' : 'ok-text')]
      ];
    }
    if (key === 'x-powered-by') {
      const p = _parseComponents(raw);
      const fw = s.framework && s.framework !== raw ? s.framework : null;
      return [
        ['Technology', { html: _chipList(p.comps.map(c => _comp(c.name, c.version))) || DASH }],
        ['Framework', { html: fw ? _esc(fw) : DASH }],
        ['Raw Header', { html: _rawBlock(raw) }],
        ['Version Exposed', exposed]
      ];
    }
    if (key === 'x-aspnet-version') {
      return [
        ['.NET Version', { html: _comp('ASP.NET', raw) }],
        ['Raw Header', { html: _rawBlock(raw) }],
        ['Version Exposed', _flag('Yes', 'warn-text')]
      ];
    }
    if (key === 'x-runtime') {
      const n = parseFloat(raw);
      const dur = isFinite(n) ? `${n} s  ≈  ${Math.round(n * 1000)} ms` : raw;
      return [
        ['Duration', { html: _esc(dur) }],
        ['Raw Header', { html: _rawBlock(raw) }]
      ];
    }
    if (key === 'via') {
      const hops = _splitList(raw).map(h => {
        const m = /^(?:(\S+)\s+)?(\S+)(?:\s+\((.*)\))?$/.exec(h);
        if (!m) return _chip(h);
        const proto = m[1] ? `HTTP/${m[1]}` : null;
        return `<span class="hdr-comp">${_esc(m[2])}${proto ? `<em>${_esc(proto)}</em>` : ''}${m[3] ? `<em>${_esc(m[3])}</em>` : ''}</span>`;
      });
      return [
        ['Hops', { html: _chipList(hops) || DASH }],
        ['Proxy / CDN', { html: s.proxy && s.proxy !== DASH ? _esc(s.proxy) : DASH }],
        ['Raw Header', { html: _rawBlock(raw) }]
      ];
    }
    if (key === 'x-served-by') {
      return [
        ['Hosts', { html: _chipList(_splitList(raw).map(h => _chip(h))) || DASH }],
        ['Internal Host Leak', _flag('Yes', 'warn-text')],
        ['Raw Header', { html: _rawBlock(raw) }]
      ];
    }
    const m = /^(.+?)[\s/]+v?(\d[\w.\-+]*)$/.exec(raw);
    return [
      ['Generator', { html: m ? _comp(m[1], m[2]) : _comp(raw, null) }],
      ['CMS / Framework', { html: s.cms && s.cms !== raw ? _esc(s.cms) : DASH }],
      ['Raw Header', { html: _rawBlock(raw) }]
    ];
  }

  function _serverRowsHtml(rows) {
    return rows.map(([label, cell]) =>
      `<div class="dns-check-row"><span class="dcr-label">${_esc(label)}</span><span class="dcr-val hdr-srv-val ${cell.cls || ''}">${cell.html}</span></div>`
    ).join('');
  }

  function renderServer() {
    const srv = _state.server;
    const scanned = !!_state.payload;

    SRV_FIELDS.forEach(f => {
      const s = srv[f.key] || {};
      const present = !!s.value;

      const section = document.getElementById(f.sec);
      const body    = section && section.querySelector('.dns-section-body');
      const badge   = document.getElementById(f.badge);

      if (badge) {
        badge.textContent = scanned ? (present ? 'PRESENT' : 'HIDDEN') : DASH;
        badge.className   = 'dns-section-badge ' + (!scanned ? 'dim' : (present ? 'hdr-badge-leak' : 'ok'));
      }

      let rows;
      if (!scanned)      rows = f.labels.map(l => [l, { html: DASH, cls: 'dim' }]);
      else if (!present) rows = [['Status', { html: 'Header not sent', cls: 'dim' }]];
      else               rows = _serverRows(f.key, s);
      if (body) {
        const wrap = body.querySelector('.hdr-req-wrap');
        body.innerHTML = _serverRowsHtml(rows);
        if (wrap) body.appendChild(wrap);
      }

      if (section) section.classList.toggle('collapsed', scanned && !present);
    });

  }

  function renderCache() {
    const cc = _state.cache['cache-control'];
    const verdict = _state.cache.verdict;
    setText('hdr-cc-value', cc.value); setText('hdr-cc-nostore', cc.noStore); setText('hdr-cc-nocache', cc.noCache);
    setText('hdr-cc-scope', cc.scope); setText('hdr-cc-maxage', cc.maxAge);   setText('hdr-cc-smaxage', cc.sMaxage);
    const ccOk = cc.noStore === 'Yes' || cc.scope === 'private' || (verdict && verdict.status === 'ok');
    setText('hdr-cc-verdict', verdict ? verdict.text : (ccOk ? 'Secure (no-store or private)' : 'Review caching policy'));
    setClass('hdr-cc-verdict', ccOk ? 'ok' : 'warn');
    setText('hdr-cc-badge', ccOk ? 'SECURE' : 'REVIEW');
  }

  function renderAuth() {
    const sc = _state.auth['set-cookie'];
    setText('hdr-sc-count', sc.count); setText('hdr-sc-httponly', sc.httponly); setText('hdr-sc-secure', sc.secure);
    setText('hdr-sc-samesite', sc.samesite); setText('hdr-sc-domain', sc.domain); setText('hdr-sc-maxage', sc.maxage); setText('hdr-sc-session', sc.session);
    if (sc.observed) {
      setText('hdr-sc-verdict', sc.ok ? 'Secure cookie config' : 'Cookie flags missing');
      setClass('hdr-sc-verdict', sc.ok ? 'ok' : 'warn');
      setText('hdr-sc-badge', sc.ok ? 'SECURE' : 'REVIEW');
    } else {
      setText('hdr-sc-verdict', _state.payload ? 'No cookies observed' : DASH);
      setClass('hdr-sc-verdict', '');
      setText('hdr-sc-badge', DASH);
    }
  }

  function _chipsHtml(items) {
    return `<span class="hdr-chip-list">${items.map(i => `<span class="hdr-chip">${_esc(i)}</span>`).join('')}</span>`;
  }

  function _setBadge(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'dns-section-badge ' + cls;
  }

  function _fillRows(id, rows) {
    const el = document.getElementById(id);
    if (!el) return;
    const wrap = el.querySelector('.hdr-req-wrap');
    el.innerHTML = _serverRowsHtml(rows);
    if (wrap) el.appendChild(wrap);
  }

  function renderCookieIntel() {
    const scanned = !!_state.payload;
    const list    = _state.cookieIntel || [];
    const dash    = { html: DASH, cls: 'dim' };

    if (!scanned) {
      _fillRows('hdr-ck-fp-body',  [['Cookies Observed', dash], ['Fingerprinted', dash], ['Unidentified', dash], ['Technologies', dash], ['Provider Tokens', dash]]);
      _fillRows('hdr-ck-cat-body', [['Categories', dash], ['Sensitive Cookies', dash]]);
      _fillRows('hdr-ck-jwt-body', [['JWT Cookies', dash], ['Algorithm', dash], ['Expiry', dash], ['Claims', dash], ['Verdict', dash]]);
      _setBadge('hdr-ck-fp-badge', DASH, 'dim');
      _setBadge('hdr-ck-cat-badge', DASH, 'dim');
      _setBadge('hdr-ck-jwt-badge', DASH, 'dim');
      return;
    }

    const known   = list.filter(c => c.fingerprint);
    const unknown = list.filter(c => !c.fingerprint);
    const techs   = _unique(known.map(c => c.fingerprint));
    const tokens  = _unique(list.flatMap(c => c.providerTokens));
    const fpRows  = [
      ['Cookies Observed', { html: String(list.length), cls: '' }],
      ['Fingerprinted', { html: String(known.length), cls: known.length ? 'warn-text' : 'dim' }],
      ['Unidentified', { html: String(unknown.length), cls: 'dim' }],
      ['Technologies', techs.length ? { html: _chipsHtml(techs), cls: '' } : dash],
      ['Provider Tokens', tokens.length ? { html: _chipsHtml(tokens), cls: 'fail-text' } : { html: 'None', cls: 'dim' }]
    ];
    known.forEach(c => fpRows.push([c.name, { html: _esc(c.fingerprint), cls: 'monospace' }]));
    _fillRows('hdr-ck-fp-body', fpRows);
    _setBadge('hdr-ck-fp-badge', list.length ? `${known.length}/${list.length}` : DASH, known.length ? 'hdr-badge-leak' : 'dim');

    const byCat = new Map();
    list.forEach(c => {
      const key = c.category || 'uncategorized';
      if (!byCat.has(key)) byCat.set(key, []);
      byCat.get(key).push(c.name);
    });
    const sensitive = list.filter(c => c.sensitive).map(c => c.name);
    const catRows = Array.from(byCat.entries())
      .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
      .map(([cat, names]) => [cat.replace(/_/g, ' '), { html: `${names.length} ${_chipsHtml(names)}`, cls: '' }]);
    catRows.push(['Sensitive Cookies', sensitive.length ? { html: `${sensitive.length} ${_chipsHtml(sensitive)}`, cls: 'fail-text' } : { html: '0', cls: 'dim' }]);
    _fillRows('hdr-ck-cat-body', list.length ? catRows : [['Categories', { html: 'No cookies observed', cls: 'dim' }]]);
    _setBadge('hdr-ck-cat-badge', list.length ? String(byCat.size) : DASH, list.length ? 'dim' : 'dim');

    const jwts = list.filter(c => c.valueType === 'jwt');
    if (!jwts.length) {
      _fillRows('hdr-ck-jwt-body', [['JWT Cookies', { html: '0', cls: 'dim' }]]);
      _setBadge('hdr-ck-jwt-badge', 'NONE', 'dim');
      return;
    }
    const now = Date.now() / 1000;
    const jwtRows = [['JWT Cookies', { html: `${jwts.length} ${_chipsHtml(jwts.map(c => c.name))}`, cls: '' }]];
    let worst = 'ok';
    jwts.forEach(c => {
      const p = _parseJwt(c.decoded);
      if (c.jwt) {
        if (c.jwt.alg) p.alg = String(c.jwt.alg);
        if (typeof c.jwt.exp === 'number') p.exp = c.jwt.exp;
        if (c.jwt.issuer) p.iss = String(c.jwt.issuer);
        if (c.jwt.audience) p.aud = String(c.jwt.audience);
      }
      const algText = p.alg || 'unspecified';
      const none = !p.alg || /^none$/i.test(p.alg);
      let expText = 'No exp claim';
      let expCls = 'warn-text';
      if (p.exp !== null) {
        const iso = new Date(p.exp * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
        if (p.exp < now) expText = `Expired (${iso})`;
        else { expText = iso; expCls = 'ok-text'; }
        if (p.exp < now) expCls = 'warn-text';
      }
      const level = none ? 'fail' : (p.exp === null || p.exp < now ? 'warn' : 'ok');
      if (level === 'fail') worst = 'fail';
      else if (level === 'warn' && worst !== 'fail') worst = 'warn';
      jwtRows.push([`${c.name} · Algorithm`, { html: _esc(algText), cls: none ? 'fail-text' : 'monospace' }]);
      jwtRows.push([`${c.name} · Expiry`, { html: _esc(expText), cls: expCls }]);
      if (p.iss || p.aud) jwtRows.push([`${c.name} · Issuer / Audience`, { html: _esc([p.iss, p.aud].filter(Boolean).join(' / ')), cls: 'monospace' }]);
      jwtRows.push([`${c.name} · Claims`, p.claims.length ? { html: _chipsHtml(p.claims), cls: '' } : dash]);
      jwtRows.push([`${c.name} · Verdict`, {
        html: none ? 'Unsigned or unspecified algorithm' : (level === 'warn' ? 'Review token lifetime' : 'No obvious issues'),
        cls: level === 'fail' ? 'fail-text' : (level === 'warn' ? 'warn-text' : 'ok-text')
      }]);
    });
    _fillRows('hdr-ck-jwt-body', jwtRows);
    _setBadge('hdr-ck-jwt-badge', `${jwts.length} FOUND`, worst === 'fail' ? 'hdr-badge-fail' : (worst === 'warn' ? 'hdr-badge-warn' : 'hdr-badge-leak'));
  }

  function renderRateLimit() {
    const rl = _state.rateLimit;
    setText('hdr-rl-retry', rl['retry-after']); setText('hdr-rl-xlimit', rl['x-ratelimit-limit']);
    setText('hdr-rl-xremaining', rl['x-ratelimit-remaining']); setText('hdr-rl-xreset', rl['x-ratelimit-reset']);
    const hasLimit = rl['x-ratelimit-limit'] !== DASH;
    const seen = ['retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'].filter(k => rl[k] !== DASH).length;
    setText('hdr-rl-active', _state.payload ? (hasLimit ? 'Rate limiting active' : 'No rate limiting detected') : DASH);
    setClass('hdr-rl-active', _state.payload ? (hasLimit ? 'ok' : 'warn') : '');
    setText('hdr-rl-headers-badge', _state.payload ? `${seen}/4` : DASH);
  }

  function renderCustom() {
    const customs = _state.custom;
    const body    = document.getElementById('hdr-custom-body');
    if (!body) return;
    if (!customs.length) {
      body.innerHTML = `<div class="data-empty"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" opacity=".18"><rect x="2" y="3" width="20" height="18" rx="2" stroke="currentColor" stroke-width="1.3"/><path d="M2 6h20M8 12h8M8 16h5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg><span>No custom headers detected</span></div>`;
      setText('hdr-custom-inv-badge', '0');
      ['debug', 'internal', 'env', 'version', 'trace', 'forwarded'].forEach(k => setText(`hdr-cat-${k}`, 0));
      setText('hdr-custom-cat-badge', '0');
      return;
    }
    body.innerHTML = customs.map(c => `
      <div class="data-row" style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px;">
        <span style="flex:1.5;font-family:var(--mono);color:var(--text-sec);">${_esc(c.name)}</span>
        <span style="flex:2;font-family:var(--mono);color:var(--text-dim);word-break:break-all;">${_esc(c.value)}</span>
        <span style="width:110px;"><span class="hdr-custom-leak ${_esc(c.classification)}">${_esc(c.classification)}</span></span>
        <span style="width:80px;color:${c.risk === 'Critical' ? '#c05030' : c.risk === 'High' ? 'var(--amber)' : 'var(--text-dim)'};">${_esc(c.risk)}</span>
      </div>`).join('');
    setText('hdr-custom-inv-badge', customs.length);
    const cats = { debug: 0, internal: 0, env: 0, version: 0, trace: 0, proxy: 0, info: 0 };
    customs.forEach(c => { cats[c.classification] = (cats[c.classification] || 0) + 1; });
    setText('hdr-cat-debug', cats.debug); setText('hdr-cat-internal', cats.internal); setText('hdr-cat-env', cats.env);
    setText('hdr-cat-version', cats.version); setText('hdr-cat-trace', cats.trace); setText('hdr-cat-forwarded', cats.proxy);
    setText('hdr-custom-cat-badge', customs.length);
  }

  function renderWebSocket() {
    const ws = _state.websocket;
    if (!_state.payload) {
      ['upgrade', 'key', 'accept', 'proto', 'version', 'endpoint', 'origin'].forEach(k => setText(`hdr-ws-${k}`, DASH));
      setText('hdr-ws-rows-badge', DASH);
      return;
    }
    setText('hdr-ws-upgrade', ws.upgrade); setText('hdr-ws-key', ws.key);
    setText('hdr-ws-accept', ws.accept); setText('hdr-ws-proto', ws.protocol);
    setText('hdr-ws-version', ws.version); setText('hdr-ws-endpoint', ws.endpoint); setText('hdr-ws-origin', ws.originCheck);
    setText('hdr-ws-rows-badge', ws.detected ? '7' : '0');
  }

  function updateScore() {
    const s = _state.score;
    setText('hdr-sec-score-badge', s.total ? `${s.ok}/${s.total}` : DASH);
    setText('hdr-sec-ok', s.ok); setText('hdr-sec-warn', s.warn); setText('hdr-sec-fail', s.fail); setText('hdr-sec-total', s.total);
    const pct = s.total > 0 ? Math.round((s.ok / s.total) * 100) : 0;
    setText('hdr-sec-percent', `${pct}%`);
    const bar = document.getElementById('hdr-sec-bar');
    if (bar) {
      bar.style.width = `${pct}%`;
      bar.className   = 'progress-fill';
      if (pct < 50) bar.classList.add('low');
      else if (pct < 75) bar.classList.add('med');
      else bar.classList.add('high');
    }
  }

  function _openDefaultView() {
    const firstBtn = document.querySelector('#hdr-subtab-bar .tls-subtab-btn[data-hdrtab]');
    const tabId = firstBtn && firstBtn.getAttribute('data-hdrtab');
    if (firstBtn && tabId) switchSubTab(tabId, firstBtn);
    document.getElementById('hdr-sec-target-params')?.classList.remove('collapsed');
    document.getElementById(tabId || '')?.querySelectorAll('.dns-section.collapsed').forEach(sec => sec.classList.remove('collapsed'));
  }

  function switchSubTab(tabId, btn) {
    document.querySelectorAll('#panel-headers .tls-sub-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('#hdr-subtab-bar .tls-subtab-btn').forEach(b => b.classList.remove('active'));
    const target = document.getElementById(tabId);
    if (target) target.classList.add('active');
    if (btn) btn.classList.add('active');
  }

  function exportData() {
    if (!_state.payload) {
      _setInfo('No scan data to export.');
      _toast('No scan data to export.', 'warn');
      return;
    }
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), summary: _state.summary, results: _state.payload }, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `header-scan-${new Date().toISOString().split('T')[0]}.json`; a.click();
    URL.revokeObjectURL(url);
  }

  function init() {
    if (!document.getElementById('_hdr_sc_style')) {
      const s = document.createElement('style');
      s.id          = '_hdr_sc_style';
      s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
      document.head.appendChild(s);
    }

    const scanBtn   = document.getElementById('hdr-scan-btn');
    const stopBtn   = document.getElementById('hdr-stop-btn');
    const resetBtn  = document.getElementById('hdr-reset-btn');
    const exportBtn = document.getElementById('hdr-export-btn');

    if (scanBtn)   scanBtn.addEventListener('click', startScan);
    if (stopBtn)   stopBtn.addEventListener('click', stopScan);
    if (resetBtn)  resetBtn.addEventListener('click', resetAll);
    if (exportBtn) exportBtn.addEventListener('click', exportData);
    document.getElementById('hdr-load-db-btn')?.addEventListener('click', () => {
      _fetchAndRenderFromDB(document.getElementById('hdr-input-domain')?.value.trim() || '');
    });

    const paramsHead = document.getElementById('hdr-target-params-head');
    if (paramsHead) paramsHead.addEventListener('click', () => {
      paramsHead.closest('.dns-section').classList.toggle('collapsed');
    });

    const browseBtn      = document.getElementById('hdr-browse-btn');
    const interceptFile  = document.getElementById('hdr-intercept-file');
    const interceptInput = document.getElementById('hdr-input-intercept');

    if (browseBtn) browseBtn.addEventListener('click', () => {
      document.getElementById('hdr-intercept-file')?.click();
    });

    if (interceptFile) interceptFile.addEventListener('change', e => {
      const f = e.target.files && e.target.files[0];
      if (f) _onInterceptPicked(f);
      e.target.value = '';
    });

    if (interceptInput) interceptInput.addEventListener('input', () => {
      const v = interceptInput.value.trim();
      if (_pickedFile && v !== (_pickedFile.path || _pickedFile.name)) _pickedFile = null;
      _validateIntercept();
    });

    document.addEventListener('click', e => {
      const toggle = e.target.closest('[data-req-toggle]');
      if (toggle) {
        const key   = toggle.getAttribute('data-req-toggle');
        const panel = document.getElementById(`hdr-req-${key}-panel`);
        if (!panel) return;
        const open = panel.hasAttribute('hidden');
        if (open) { renderRequests(key); panel.removeAttribute('hidden'); }
        else panel.setAttribute('hidden', '');
        toggle.classList.toggle('active', open);
        return;
      }
      const pill = e.target.closest('[data-req-filter]');
      if (pill) {
        const key = pill.getAttribute('data-req-key');
        _reqFilter[key] = pill.getAttribute('data-req-filter');
        renderRequests(key);
      }
    });

    document.querySelectorAll('#hdr-subtab-bar .tls-subtab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tabId = btn.getAttribute('data-hdrtab');
        if (tabId) switchSubTab(tabId, btn);
      });
    });

    _openDefaultView();
  }

  return { init, startScan, stopScan, resetAll, exportData, loadFromDatabase: _fetchAndRenderFromDB, getState: () => ({ ..._state }) };

})();

(function _waitForPanel() {
  if (document.getElementById('hdr-scan-btn')) {
    HeaderScan.init();
  } else {
    setTimeout(_waitForPanel, 50);
  }
})();