const OxsProxy = (() => {

    let _jobId = null;
    let _configuredKey = null;
    let _running = false;
    let _stopRequested = false;
    let _statusTimer = null;
    let _javaAuto = false;
    let _javaMeta = { required: null, tested: null };

    const _busy   = { configure: false, start: false, stop: false, reconfig: false };
    const _labels = {};

    const _lists = {
        burp: { listId: 'burp-jar-versions', btnId: 'burp-jar-versions-btn', countId: 'burp-jar-versions-count', fieldId: 'burp-jar-path', items: [] },
        java: { listId: 'java-versions',     btnId: 'java-versions-btn',     countId: 'java-versions-count',     fieldId: 'java-path',     items: [] },
    };

    const _apiHost = '127.0.0.1';
    const _apiPort = 30302;
    const _retryMs = 5000;
    const _pollMs  = 2000;
    let   _apiConnState = 'disconnected';
    let   _latency = null;
    let   _startedAt = null;
    let   _lastEntryAt = null;
    let   _loopTimer = null;
    let   _tickTimer = null;
    let   _loopRunning = false;
    // Entries older than this (server timestamp, ms) belong to a previous
    // page load / connection and are hidden -- the GUI only ever shows
    // traffic captured during the current session. Reset on every fresh
    // connect attempt (page refresh, or reconnect after a disconnect).
    // -1500ms is a small grace window to absorb clock skew between this
    // browser and the burp_api.py host.
    let   _sessionStartMs = Date.now() - 1500;
    const _rq = { entries: [], job: null, q: '', method: 'ALL', status: 'ALL', selected: null, dtab: 'request', paused: false, pending: 0, seen: new Set(), cleared: new Set(), keyBound: false };

    const _fd = { findings: [], job: null, q: '', sev: 'ALL', cat: 'ALL', selected: null, keyBound: false };

    const _fdSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    const _fdSevMeta = {
        critical: { label: 'Critical', cls: 'oxs-rq-st-5xx' },
        high:     { label: 'High',     cls: 'oxs-rq-st-4xx' },
        medium:   { label: 'Medium',   cls: 'oxs-rq-st-3xx' },
        low:      { label: 'Low',      cls: 'oxs-rq-st-2xx' },
        info:     { label: 'Info',     cls: 'oxs-rq-st-1xx' },
    };

    const _fdCats = [
        {
            key: 'cache', label: 'Web Cache Findings', short: 'Web Cache', color: '#8e7cf0',
            match: /cache[-_ ]?(poison|deception)?/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><ellipse cx="8" cy="3.6" rx="5" ry="1.8" stroke="currentColor" stroke-width="1.2"/><path d="M3 3.6v3.6c0 1 2.2 1.8 5 1.8s5-.8 5-1.8V3.6M3 7.2v3.6c0 1 2.2 1.8 5 1.8s5-.8 5-1.8V7.2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>',
        },
        {
            key: 'cors', label: 'CORS Findings', short: 'CORS', color: '#4fb6e8',
            match: /cors|cross[-_ ]?origin/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5.2" stroke="currentColor" stroke-width="1.2"/><path d="M2.8 8h10.4M8 2.8c1.8 1.4 2.8 3.3 2.8 5.2s-1 3.8-2.8 5.2c-1.8-1.4-2.8-3.3-2.8-5.2S6.2 4.2 8 2.8z" stroke="currentColor" stroke-width="1.1"/></svg>',
        },
        {
            key: 'upload', label: 'File Upload Findings', short: 'File Upload', color: '#f5a84f',
            match: /upload/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 10.5V2.8M8 2.8L5.2 5.6M8 2.8l2.8 2.8" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/><path d="M2.8 10.2v1.6c0 .9.7 1.6 1.6 1.6h7.2c.9 0 1.6-.7 1.6-1.6v-1.6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>',
        },
        {
            key: 'idor', label: 'IDOR / BOLA Vectors', short: 'IDOR / BOLA', color: '#e66464',
            match: /idor|bola|broken[-_ ]?object/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="5" cy="8" r="2.4" stroke="currentColor" stroke-width="1.2"/><path d="M7 8h6M10.5 8v2M12.5 8v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>',
        },
        {
            key: 'jwt', label: 'JWT / Cookie Findings', short: 'JWT / Cookie', color: '#f5c518',
            match: /jwt|cookie|session[-_ ]?token/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2.2l4.6 1.6v3.5c0 3-2 5.3-4.6 6.5-2.6-1.2-4.6-3.5-4.6-6.5V3.8L8 2.2z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M5.8 8l1.6 1.6 2.8-3.2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        },
        {
            key: 'lfi', label: 'LFI / Path Traversal Vectors', short: 'LFI / Traversal', color: '#78c88c',
            match: /lfi|rfi|path[-_ ]?traversal|directory[-_ ]?traversal/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2.4 4.6c0-.6.5-1 1-1h2.8l1.1 1.3h5.3c.6 0 1 .5 1 1v5.5c0 .6-.5 1-1 1H3.4c-.6 0-1-.5-1-1V4.6z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M6 10.5l2.6-2.6M8.6 10.5l-2.6-2.6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>',
        },
        {
            key: 'xml', label: 'XML Vectors', short: 'XML', color: '#b07cf0',
            match: /xxe|xml|doctype|entity|soap/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 2.4h5.4l2.6 2.6v8.1a.9.9 0 0 1-.9.9H4a.9.9 0 0 1-.9-.9V3.3c0-.5.4-.9.9-.9z" stroke="currentColor" stroke-width="1.15" stroke-linejoin="round"/><path d="M5.6 9l-1.3 1.3L5.6 11.6M9.4 9l1.3 1.3-1.3 1.3" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        },
        {
            key: 'csrf', label: 'CSRF Findings', short: 'CSRF', color: '#f2789f',
            match: /csrf|cross[-_ ]?site[-_ ]?request[-_ ]?forgery/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2.2l4.6 1.6v3.3c0 3.1-2 5.5-4.6 6.7-2.6-1.2-4.6-3.6-4.6-6.7V3.8L8 2.2z" stroke="currentColor" stroke-width="1.15" stroke-linejoin="round"/><path d="M8 5.4v3M8 10.2h.01" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>',
        },
        {
            key: 'clickjacking', label: 'Clickjacking Findings', short: 'Clickjacking', color: '#5fb0a3',
            match: /clickjack|frame[-_ ]?(busting|options)|x-frame-options/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="2.6" y="2.6" width="8" height="8" rx=".8" stroke="currentColor" stroke-width="1.1"/><rect x="5.4" y="5.4" width="8" height="8" rx=".8" stroke="currentColor" stroke-width="1.1"/></svg>',
        },
        {
            key: 'deserialization', label: 'Insecure Deserialization Vectors', short: 'Deserialization', color: '#c97b4f',
            match: /deserializ|viewstate|gadget|serialized[-_ ]?object/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="2.4" y="6.5" width="3.4" height="3.4" rx=".5" stroke="currentColor" stroke-width="1.1"/><rect x="10.2" y="6.5" width="3.4" height="3.4" rx=".5" stroke="currentColor" stroke-width="1.1"/><path d="M5.8 8.2h4.4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-dasharray="1.6 1.4"/></svg>',
        },
        {
            key: 'oauth', label: 'OAuth Findings', short: 'OAuth', color: '#5f9ef0',
            match: /oauth|authoriz(e|ation)[-_ ]?(code|request)|openid/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="3.4" y="7" width="9.2" height="6" rx="1" stroke="currentColor" stroke-width="1.1"/><path d="M5.4 7V5a2.6 2.6 0 0 1 5.2 0v2" stroke="currentColor" stroke-width="1.1"/></svg>',
        },
        {
            key: 'websocket', label: 'WebSocket Findings', short: 'WebSocket', color: '#4fcf8e',
            match: /websocket|wss?:\/\//i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2.4 8c1-1.6 2-1.6 3 0s2 1.6 3 0 2-1.6 3 0 2 1.6 2.6 0" stroke="currentColor" stroke-width="1.15" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        },
        {
            key: 'info_disclosure', label: 'Information Disclosure Vectors', short: 'Info Disclosure', color: '#d6c24f',
            match: /info(rmation)?[-_ ]?disclos|data[-_ ]?leak|secret[-_ ]?expos/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M1.6 8s2.2-4 6.4-4 6.4 4 6.4 4-2.2 4-6.4 4-6.4-4-6.4-4z" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/><circle cx="8" cy="8" r="1.7" stroke="currentColor" stroke-width="1.1"/></svg>',
        },
        {
            key: 'cookie_security', label: 'Cookie Security Findings', short: 'Cookie Security', color: '#e0a9f5',
            match: /cookie[-_ ]?(secur|flag|fixation)/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5.4" stroke="currentColor" stroke-width="1.1"/><circle cx="6" cy="6.4" r=".6" fill="currentColor"/><circle cx="9.6" cy="6.8" r=".6" fill="currentColor"/><circle cx="7.4" cy="9.6" r=".6" fill="currentColor"/></svg>',
        },
        {
            key: 'open_redirect', label: 'Open Redirect Findings', short: 'Open Redirect', color: '#f55f5f',
            match: /open[-_ ]?redirect|unvalidated[-_ ]?redirect/i,
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2.6 8h8M7.2 4.8L10.6 8l-3.4 3.2M10.6 8h2.8" stroke="currentColor" stroke-width="1.15" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        },
    ];

    const $    = id => document.getElementById(id);
    const _val = id => ($(id)?.value?.trim() || '');

    function _apiBase() {
        return `http://${_apiHost}:${_apiPort}`;
    }

    function _setText(id, val) {
        const el = $(id);
        if (el) el.textContent = (val === null || val === undefined || val === '') ? '—' : val;
    }

    function _badge(text, cls) {
        const el = $('proxy-api-badge');
        if (!el) return;
        el.textContent = text;
        el.className   = `dns-section-badge ${cls}`;
    }

    function _fmtClock(value) {
        if (!value) return '—';
        const d = new Date(value);
        return isNaN(d) ? '—' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function _fmtDuration(ms) {
        if (ms === null || ms === undefined || ms < 0) return '—';
        const s = Math.floor(ms / 1000);
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        if (h) return `${h}h ${String(m).padStart(2, '0')}m`;
        if (m) return `${m}m ${String(sec).padStart(2, '0')}s`;
        return `${sec}s`;
    }

    function _renderClocks() {
        const now = Date.now();
        const connected = _apiConnState === 'connected';
        _setText('proxy-uptime-text', connected && _startedAt ? _fmtDuration(now - _startedAt) : '—');
        if (connected && _lastEntryAt) {
            _setText('proxy-lastentry-text', _fmtClock(_lastEntryAt));
            _setText('proxy-lastentry-note', `${_fmtDuration(now - _lastEntryAt)} ago`);
        } else {
            _setText('proxy-lastentry-text', '—');
            _setText('proxy-lastentry-note', connected ? 'no traffic yet' : 'not listening');
        }
    }

    function _showError(msg) {
        const box = $('proxy-error-area');
        if (!box) return;
        if (!msg) {
            box.hidden = true;
            _setText('proxy-error-msg', '');
            _setText('proxy-error-meta', '');
            return;
        }
        _setText('proxy-error-msg', msg);
        _setText('proxy-error-meta', `${_fmtClock(Date.now())} · retrying every ${_retryMs / 1000}s`);
        box.hidden = false;
    }

    function _setState(state, sub) {
        // This hero reflects reachability of burp_api.py only (the local
        // Flask service the GUI talks to) — NOT whether the Burp Suite
        // extension (Burp Exporter) is actually attached. That distinction
        // lives in the Requests tab's LIVE indicator (see _updateRqLive),
        // which is driven by job.exporter_connected.
        _apiConnState = state;
        const hero = $('proxy-hero');
        if (hero) hero.dataset.state = state;
        const map = {
            connected:    { text: 'Connected',     badge: 'CONNECTED',     cls: 'ok'   },
            connecting:   { text: 'Connecting ...', badge: 'CONNECTING ...', cls: 'warn' },
            disconnected: { text: 'Disconnected',  badge: 'DISCONNECTED',  cls: 'dim'  },
        };
        const m = map[state];
        _badge(m.badge, m.cls);
        _setText('proxy-status-text', m.text);
        _setText('proxy-status-sub', sub);
        _setText('proxy-endpoint-text', `${_apiHost}:${_apiPort}`);
        _setText('proxy-latency-text', state === 'connected' && _latency !== null ? `${_latency} ms` : '—');
        _setText('proxy-checked-text', _fmtClock(Date.now()));
        if (state !== 'connected') {
            _startedAt = null;
            _lastEntryAt = null;
            _setText('proxy-captured-text', '0');
            _setText('proxy-jobid-text', '—');
            _setText('proxy-started-text', '—');
            if (state === 'disconnected') _setText('proxy-service-text', '—');
            _renderRequests(null);
        }
        _renderClocks();
    }

    function _startNewSession() {
        _sessionStartMs = Date.now() - 1500;
        _rq.entries  = [];
        _rq.pending  = 0;
        _rq.selected = null;
        _rq.cleared  = new Set();
        _rq.seen     = new Set();
    }

    function _applyJob(job, service) {
        _startedAt   = job.started_at ? Date.parse(job.started_at) : _startedAt;
        _lastEntryAt = job.last_entry_at ? Date.parse(job.last_entry_at) : null;
        _setText('proxy-captured-text', String(job.captured_count ?? 0));
        _setText('proxy-jobid-text', job.job_id || _jobId);
        _setText('proxy-started-text', _fmtClock(job.started_at));
        if (service) _setText('proxy-service-text', service);
        _setText('proxy-endpoint-text', `${job.host || _apiHost}:${job.port || _apiPort}`);
        _renderRequests(job);
        _renderFindings(job);
    }

    function _fmtBytes(n) {
        if (n === null || n === undefined || isNaN(n)) return '—';
        if (n < 1024) return `${n} B`;
        if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
        return `${(n / 1024 / 1024).toFixed(1)} MB`;
    }

    function _attr(text) {
        return _esc(text).replace(/"/g, '&quot;');
    }

    function _fmtStamp(value) {
        if (!value) return '—';
        const d = new Date(value);
        if (isNaN(d)) return '—';
        const p = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    }

    function _fmtMs(n) {
        if (n === null || n === undefined || isNaN(n)) return '—';
        const v = Number(n);
        return v >= 1000 ? `${(v / 1000).toFixed(2)} s` : `${Math.round(v)} ms`;
    }

    function _mimeLabel(mime, path) {
        const m = String(mime || '').toLowerCase().split(';')[0].trim();
        if (m) {
            const tail = m.split('/')[1] || m;
            return tail.replace(/^x-/, '').replace(/\+.*$/, '').replace('javascript', 'js').slice(0, 10);
        }
        const ext = (String(path || '').split('?')[0].match(/\.([a-z0-9]{1,5})$/i) || [])[1];
        return ext ? ext.toLowerCase() : '';
    }

    function _statusClass(s) {
        if (s === null || s === undefined || isNaN(s)) return 'oxs-rq-st-na';
        if (s >= 500) return 'oxs-rq-st-5xx';
        if (s >= 400) return 'oxs-rq-st-4xx';
        if (s >= 300) return 'oxs-rq-st-3xx';
        if (s >= 200) return 'oxs-rq-st-2xx';
        if (s >= 100) return 'oxs-rq-st-1xx';
        return 'oxs-rq-st-na';
    }

    function _statusBucket(s) {
        if (s === null || s === undefined || isNaN(s)) return 'other';
        if (s >= 500) return '5xx';
        if (s >= 400) return '4xx';
        if (s >= 300) return '3xx';
        if (s >= 200) return '2xx';
        if (s >= 100) return '1xx';
        return 'other';
    }

    function _methodClass(m) {
        return `oxs-rq-m-${String(m).toLowerCase().replace(/[^a-z]/g, '') || 'other'}`;
    }

    function _headersText(h) {
        if (h === null || h === undefined || h === '') return '';
        if (typeof h === 'string') return h;
        if (Array.isArray(h)) {
            return h.map(x => {
                if (typeof x === 'string') return x;
                if (Array.isArray(x)) return `${x[0]}: ${x[1] ?? ''}`;
                if (x && x.name !== undefined) return `${x.name}: ${x.value ?? ''}`;
                return JSON.stringify(x);
            }).join('\n');
        }
        if (typeof h === 'object') {
            return Object.keys(h).map(k => `${k}: ${Array.isArray(h[k]) ? h[k].join(', ') : h[k]}`).join('\n');
        }
        return String(h);
    }

    function _bodyText(b) {
        if (b === null || b === undefined) return '';
        if (typeof b === 'string') return b;
        try { return JSON.stringify(b, null, 2); } catch (err) { return String(b); }
    }

    function _numOrNull(v) {
        if (v === null || v === undefined || v === '' || isNaN(v)) return null;
        return Number(v);
    }

    function _normEntry(e, i) {
        const req  = e.request && typeof e.request === 'object' ? e.request : {};
        const res  = e.response && typeof e.response === 'object' ? e.response : {};
        const rawUrl = String(req.url || e.url || e.path || '');
        let host   = String(e.host || '');
        let path   = String(e.path || rawUrl);
        let scheme = String(e.protocol || e.scheme || '');
        let query  = '';
        try {
            const u = new URL(rawUrl);
            host   = u.host;
            path   = `${u.pathname}${u.search}`;
            query  = u.search;
            scheme = u.protocol.replace(':', '');
        } catch (err) {}
        const ts     = e.timestamp || e.time || null;
        const method = String(req.method || e.method || '—').toUpperCase();
        const status = _numOrNull(res.status_code ?? e.status ?? e.status_code);
        const id     = e.id ?? e.entry_id ?? null;
        const reqHeaders = _headersText(req.headers ?? e.request_headers);
        const resHeaders = _headersText(res.headers ?? e.response_headers);
        const reqBody    = _bodyText(req.body ?? e.request_body);
        const resBody    = _bodyText(res.body_preview ?? res.body ?? e.response_body);
        const ver        = String(e.http_version || 'HTTP/1.1');
        const resMime    = res.headers && typeof res.headers === 'object' && !Array.isArray(res.headers) ? (res.headers['content-type'] || '') : '';
        const elapsedS   = _numOrNull(e.elapsed_seconds);
        const reqRaw = typeof e.request === 'string' ? e.request
            : (req.method ? `${method} ${path || '/'} ${ver}\n${host ? `host: ${host}\n` : ''}${reqHeaders}${reqBody ? `\n\n${reqBody}` : ''}` : '');
        const resRaw = typeof e.response === 'string' ? e.response
            : (status !== null ? `${ver} ${status}\n${resHeaders}${resBody ? `\n\n${resBody}` : ''}` : '');
        return {
            key:        id !== null ? `id:${id}` : `${ts}|${method}|${rawUrl}|${status}`,
            index:      i + 1,
            method,
            url:        rawUrl,
            host,
            path:       path || '/',
            scheme,
            status,
            ts,
            size:       _numOrNull(e.length ?? e.size),
            mime:       String(resMime || e.mime || e.mime_type || e.content_type || ''),
            duration:   elapsedS !== null ? elapsedS * 1000 : _numOrNull(e.duration_ms ?? e.duration ?? e.elapsed_ms),
            ip:         String(e.ip || e.remote_ip || ''),
            source:     String(e.source || e.tool || e.client_ip || e.client || e.src || ''),
            reqHeaders,
            reqBody,
            reqRaw,
            resHeaders,
            resBody,
            resRaw,
        };
    }

    function _rqFiltered() {
        const q = _rq.q.trim().toLowerCase();
        const main = ['GET', 'POST', 'PUT', 'DELETE'];
        return _rq.entries.filter(e => {
            if (_rq.method === 'OTHER' && main.includes(e.method)) return false;
            if (_rq.method !== 'ALL' && _rq.method !== 'OTHER' && e.method !== _rq.method) return false;
            if (_rq.status !== 'ALL' && _statusBucket(e.status) !== _rq.status) return false;
            if (q) {
                const hay = `${e.method} ${e.source} ${e.url} ${e.host} ${e.path} ${e.status ?? ''} ${e.mime}`.toLowerCase();
                if (!q.split(/\s+/).every(t => hay.includes(t))) return false;
            }
            return true;
        });
    }

    function _renderRqStats() {
        const list  = _rq.entries;
        const c     = { '1xx': 0, '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0 };
        list.forEach(e => {
            c[_statusBucket(e.status)]++;
        });
        _setText('proxy-rq-stat-total', String(list.length));
        _setText('proxy-rq-stat-1xx', String(c['1xx']));
        _setText('proxy-rq-stat-2xx', String(c['2xx']));
        _setText('proxy-rq-stat-3xx', String(c['3xx']));
        _setText('proxy-rq-stat-4xx', String(c['4xx']));
        _setText('proxy-rq-stat-5xx', String(c['5xx']));

        const total = list.length || 1;
        ['1xx', '2xx', '3xx', '4xx', '5xx', 'other'].forEach(k => {
            const el = $(`proxy-rq-dist-${k}`);
            if (el) el.style.width = `${(c[k] / total * 100).toFixed(2)}%`;
        });
    }

    function _markSelectedRow() {
        const body = $('proxy-requests-body');
        if (!body) return;
        body.querySelectorAll('.oxs-rq-row').forEach(r => r.classList.toggle('sel', r.dataset.key === _rq.selected));
    }

    function _renderRqTable() {
        const body     = $('proxy-requests-body');
        const empty    = $('proxy-requests-empty');
        const emptyTxt = $('proxy-requests-empty-text');
        const table    = $('proxy-rq-table');
        if (!body) return;

        const rows  = _rqFiltered();
        const shown = rows.slice(-500).reverse();
        _setText('proxy-rq-showing', `Showing ${shown.length} of ${_rq.entries.length}${rows.length > 500 ? ' · latest 500' : ''}`);

        if (!shown.length) {
            let msg;
            if (!_rq.job) msg = 'The listener is not connected. Start it from Configurations to begin capturing requests.';
            else if (_rq.entries.length) msg = 'No requests match the current filters.';
            else if (_rq.cleared.size) msg = 'View cleared. New traffic will appear here.';
            else msg = 'No requests captured yet in this session. Start the listener and route traffic through Burp to see entries here.';
            body.innerHTML = `<tr class="oxs-rq-empty-row"><td colspan="6"><div class="oxs-rq-empty-box"><svg width="22" height="22" viewBox="0 0 16 16" fill="none"><path d="M3 3.5h10M3 8h10M3 12.5h6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity=".6"/></svg><span>${_esc(msg)}</span></div></td></tr>`;
            if (table) table.style.display = '';
            if (empty) empty.style.display = 'none';
            if (emptyTxt) emptyTxt.textContent = msg;
            return;
        }

        if (table) table.style.display = '';
        if (empty) empty.style.display = 'none';

        const hadSeen = _rq.seen.size > 0;
        body.innerHTML = shown.map(e => {
            const isNew = hadSeen && !_rq.seen.has(e.key);
            return `<tr class="oxs-rq-row${e.key === _rq.selected ? ' sel' : ''}${isNew ? ' new' : ''}" data-key="${_attr(e.key)}">` +
                   `<td class="oxs-rq-c-time">${_fmtStamp(e.ts)}</td>` +
                   `<td class="oxs-rq-c-src" title="${_attr(e.source)}">${_esc(e.source || '—')}</td>` +
                   `<td><span class="oxs-rq-m ${_methodClass(e.method)}">${_esc(e.method)}</span></td>` +
                   `<td class="oxs-rq-c-path" title="${_attr(e.url)}">${_esc(e.url || e.path)}</td>` +
                   `<td><span class="oxs-rq-st ${_statusClass(e.status)}">${e.status ?? '—'}</span></td>` +
                   `<td class="oxs-rq-c-num">${_fmtMs(e.duration)}</td>` +
                   `</tr>`;
        }).join('');

        if (_rq.seen.size > 5000) _rq.seen.clear();
        _rq.entries.forEach(e => _rq.seen.add(e.key));
    }

    function _curlFor(e) {
        const q = s => `'${String(s).replace(/'/g, "'\\''")}'`;
        const rawParts = e.reqRaw ? e.reqRaw.split(/\r?\n\r?\n/) : [];
        const headers  = e.reqHeaders || (rawParts[0] ? rawParts[0].split(/\r?\n/).slice(1).join('\n') : '');
        const body     = e.reqBody || rawParts.slice(1).join('\n\n');
        const parts    = ['curl', '-i', '-X', e.method, q(e.url)];
        headers.split('\n').forEach(line => {
            const t = line.trim();
            if (t && t.includes(':') && !/^(host|content-length):/i.test(t)) parts.push('-H', q(t));
        });
        if (body) parts.push('--data-raw', q(body));
        return parts.join(' ');
    }

    async function _copyText(text, okMsg) {
        try {
            await navigator.clipboard.writeText(text);
            if (typeof UI !== 'undefined') UI.toast(okMsg, 'success');
        } catch (err) {
            if (typeof UI !== 'undefined') UI.toast('Copy failed', 'error');
        }
    }

    function _renderRqDetail() {
        const panel  = $('proxy-rq-detail');
        const layout = $('proxy-rq-layout');
        if (!panel || !layout) return;

        const e = _rq.selected ? _rq.entries.find(x => x.key === _rq.selected) : null;
        if (!e) {
            _rq.selected = null;
            panel.hidden = true;
            layout.classList.remove('has-detail');
            _markSelectedRow();
            return;
        }

        panel.hidden = false;
        layout.classList.add('has-detail');

        const m = $('proxy-rq-d-method');
        m.textContent = e.method;
        m.className   = `oxs-rq-m ${_methodClass(e.method)}`;
        const s = $('proxy-rq-d-status');
        s.textContent = e.status ?? '—';
        s.className   = `oxs-rq-st ${_statusClass(e.status)}`;
        _setText('proxy-rq-d-url', e.url || e.path);

        const meta = [
            ['Host', e.host],
            ['Scheme', e.scheme ? e.scheme.toUpperCase() : ''],
            ['Timestamp', _fmtStamp(e.ts)],
            ['Source', e.source],
            ['Elapsed', _fmtMs(e.duration)],
            ['Content type', e.mime],
            ['Remote IP', e.ip],
            ['Entry', `#${e.index}`],
        ];
        $('proxy-rq-d-meta').innerHTML = meta.map(([k, v]) =>
            `<div class="oxs-rq-d-kv"><span class="oxs-rq-label">${k}</span><span class="oxs-rq-d-v" title="${_attr(v || '')}">${_esc(v || '—')}</span></div>`
        ).join('');

        document.querySelectorAll('.oxs-rq-d-tab').forEach(t => {
            const active = t.dataset.dtab === _rq.dtab;
            t.classList.toggle('active', active);
            t.setAttribute('aria-selected', String(active));
        });

        const isReq = _rq.dtab === 'request';
        const raw   = isReq ? e.reqRaw : e.resRaw;
        const head  = isReq ? e.reqHeaders : e.resHeaders;
        const body  = isReq ? e.reqBody : e.resBody;
        const pre   = $('proxy-rq-d-pre');
        let out = raw;
        if (!out) out = [head, body].filter(Boolean).join('\n\n');
        pre.classList.toggle('empty', !out);
        pre.textContent = out || `No ${isReq ? 'request' : 'response'} data was provided by Burp Exporter for this entry.`;

        _markSelectedRow();
    }

    function _updateRqLive() {
        const live = $('proxy-rq-live');
        if (live) {
            const connected = Boolean(_rq.job && _rq.job.exporter_connected);
            const state = !connected ? 'offline' : (_rq.paused ? 'paused' : 'live');
            live.dataset.state = state;
            _setText('proxy-rq-live-text', state === 'live' ? 'Live' : (state === 'paused' ? 'Paused' : 'Offline'));
        }
        const btn = $('proxy-rq-pause');
        if (btn) {
            const pauseIcon = '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M5.5 3.5v9M10.5 3.5v9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
            const playIcon  = '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M5 3.5l8 4.5-8 4.5z" fill="currentColor"/></svg>';
            btn.innerHTML = _rq.paused
                ? `${playIcon}Resume${_rq.pending ? ` <b class="oxs-rq-pending">+${_rq.pending}</b>` : ''}`
                : `${pauseIcon}Pause`;
            btn.classList.toggle('on', _rq.paused);
        }
    }

    function _renderRqAll() {
        _renderRqStats();
        _renderRqTable();
        _renderRqDetail();
        _updateRqLive();
    }

    function _selectRq(key) {
        _rq.selected = _rq.selected === key ? null : key;
        _renderRqDetail();
    }

    function _clearRq() {
        _rq.entries.forEach(e => _rq.cleared.add(e.key));
        _rq.entries  = [];
        _rq.selected = null;
        _rq.pending  = 0;
        _renderRqAll();
        if (typeof UI !== 'undefined') UI.toast('Request view cleared', 'success');
    }

    function _exportRq() {
        const rows = _rqFiltered();
        if (!rows.length) {
            if (typeof UI !== 'undefined') UI.toast('Nothing to export', 'error');
            return;
        }
        const payload = rows.map(e => ({
            time:        e.ts,
            method:      e.method,
            url:         e.url,
            status:      e.status,
            size:        e.size,
            content_type: e.mime || null,
            duration_ms: e.duration,
            request:     e.reqRaw || e.reqHeaders || null,
            response:    e.resRaw || e.resHeaders || null,
        }));
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        const href = URL.createObjectURL(blob);
        link.href = href;
        link.download = `burp-requests-${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(href), 1000);
    }

    function _togglePauseRq() {
        _rq.paused = !_rq.paused;
        if (!_rq.paused) {
            _rq.pending = 0;
            _renderRequests(_rq.job);
            return;
        }
        _updateRqLive();
    }

    function _inSession(e) {
        const t = Date.parse(e.ts);
        return !isNaN(t) && t >= _sessionStartMs;
    }

    function _renderRequests(job) {
        const badge    = $('proxy-requests-badge');
        const tabCount = $('proxy-requests-tab-count');
        const meta     = $('proxy-requests-meta');
        if (!badge || !$('proxy-requests-body')) return;

        _rq.job = job || null;

        if (!job) {
            _rq.entries  = [];
            _rq.pending  = 0;
            _rq.selected = null;
            badge.textContent = '0 CAPTURED';
            badge.className   = 'dns-section-badge dim';
            if (tabCount) { tabCount.textContent = '0'; tabCount.hidden = true; }
            if (meta) meta.textContent = 'Listener is offline';
            _lastEntryAt = null;
            _renderRqAll();
            return;
        }

        // Only requests captured since this session started (page load, or
        // last reconnect) are shown -- traffic buffered server-side from a
        // previous session is intentionally left out.
        const list     = Array.isArray(job.entries) ? job.entries : [];
        const incoming = list.map(_normEntry).filter(e => !_rq.cleared.has(e.key) && _inSession(e));
        if (_rq.paused) {
            _rq.pending = Math.max(0, incoming.length - _rq.entries.length);
        } else {
            _rq.entries = incoming;
            _rq.pending = 0;
        }

        const count = _rq.entries.length;
        badge.textContent = `${count} CAPTURED`;
        badge.className   = `dns-section-badge ${count > 0 ? 'ok' : 'dim'}`;
        if (tabCount) {
            tabCount.textContent = String(count);
            tabCount.hidden = count === 0;
        }
        // Keep the Configurations tab's "Captured" stat in sync with the
        // session-scoped count too, so the two tabs never disagree.
        _setText('proxy-captured-text', String(count));

        const sessionLastEntryAt = _rq.entries.length ? _rq.entries[_rq.entries.length - 1].ts : null;
        _lastEntryAt = sessionLastEntryAt ? Date.parse(sessionLastEntryAt) : null;

        if (meta) {
            if (!job.exporter_connected) {
                meta.textContent = sessionLastEntryAt
                    ? `Burp Exporter disconnected · last request ${_fmtClock(sessionLastEntryAt)}`
                    : 'Waiting for Burp Exporter to connect';
            } else {
                meta.textContent = sessionLastEntryAt
                    ? `Last request ${_fmtClock(sessionLastEntryAt)}`
                    : 'Connected · waiting for traffic';
            }
        }
        _renderRqAll();
    }

    function _initRequests() {
        const search = $('proxy-rq-search');
        search?.addEventListener('input', () => {
            _rq.q = search.value;
            _renderRqTable();
        });

        const bindChips = (selector, prop, key) => {
            const nodes = document.querySelectorAll(selector);
            nodes.forEach(btn => btn.addEventListener('click', () => {
                _rq[key] = btn.dataset[prop];
                nodes.forEach(n => n.classList.toggle('active', n === btn));
                _renderRqTable();
            }));
        };
        bindChips('[data-rq-method]', 'rqMethod', 'method');
        bindChips('[data-rq-status]', 'rqStatus', 'status');

        $('proxy-requests-body')?.addEventListener('click', event => {
            const row = event.target.closest('.oxs-rq-row');
            if (row) _selectRq(row.dataset.key);
        });

        $('proxy-rq-d-close')?.addEventListener('click', () => {
            _rq.selected = null;
            _renderRqDetail();
        });

        document.querySelectorAll('.oxs-rq-d-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                _rq.dtab = tab.dataset.dtab;
                _renderRqDetail();
            });
        });

        const current = () => _rq.entries.find(x => x.key === _rq.selected);
        $('proxy-rq-d-copy-url')?.addEventListener('click', () => {
            const e = current();
            if (e) _copyText(e.url, 'URL copied');
        });
        $('proxy-rq-d-copy-curl')?.addEventListener('click', () => {
            const e = current();
            if (e) _copyText(_curlFor(e), 'cURL command copied');
        });

        $('proxy-rq-pause')?.addEventListener('click', _togglePauseRq);
        $('proxy-rq-clear')?.addEventListener('click', _clearRq);
        $('proxy-rq-export')?.addEventListener('click', _exportRq);

        if (!_rq.keyBound) {
            _rq.keyBound = true;
            document.addEventListener('keydown', event => {
                if (event.key !== 'Escape' || !_rq.selected) return;
                const panel = $('proxy-panel-requests');
                if (!panel || panel.hidden) return;
                _rq.selected = null;
                _renderRqDetail();
            });
        }

        _renderRqAll();
    }

    function _fdCatMeta(key) {
        return _fdCats.find(c => c.key === key) || null;
    }

    function _resolveFdCategory(raw) {
        const s = String(raw || '');
        for (const c of _fdCats) {
            if (c.match.test(s)) return c.key;
        }
        return 'other';
    }

    function _fdSevRank(sev) {
        const i = _fdSeverities.indexOf(sev);
        return i === -1 ? _fdSeverities.length : i;
    }

    function _normFinding(f, i) {
        const rawCat  = String(f.category || f.type || f.vuln_type || f.class || f.vector || '').trim();
        const catKey  = _resolveFdCategory(rawCat);
        let   sev     = String(f.severity || f.risk || f.level || 'info').toLowerCase();
        if (!_fdSeverities.includes(sev)) sev = 'info';
        const rawUrl  = String(f.url || f.request_url || (f.request && f.request.url) || '');
        let   host    = String(f.host || '');
        let   path    = rawUrl;
        try {
            const u = new URL(rawUrl);
            host = u.host;
            path = `${u.pathname}${u.search}`;
        } catch (err) {}
        const method  = String(f.method || (f.request && f.request.method) || '').toUpperCase() || '—';
        const detail  = String(f.detail || f.description || f.evidence || f.reason || f.message || '');
        const matched = String(f.parameter || f.param || f.header || f.matched_on || f.matched_parameter || '');
        const ts      = f.timestamp || f.detected_at || f.time || f.ts || null;
        const reqId   = f.request_id ?? f.entry_id ?? null;
        const reqKey  = reqId !== null && reqId !== undefined ? `id:${reqId}` : (f.request_key || null);
        const meta    = _fdCatMeta(catKey);
        const id      = f.id ?? f.finding_id ?? `${catKey}-${i}`;
        return {
            id, key: `fd:${id}`, catKey,
            rawCat: rawCat || (meta ? meta.label : 'Uncategorized'),
            sev, url: rawUrl, host, path: path || '/', method, detail, matched, ts, reqKey,
        };
    }

    function _fdFiltered() {
        const q = _fd.q.trim().toLowerCase();
        return _fd.findings.filter(f => {
            if (_fd.cat !== 'ALL' && f.catKey !== _fd.cat) return false;
            if (_fd.sev !== 'ALL' && f.sev !== _fd.sev) return false;
            if (q) {
                const hay = `${f.rawCat} ${f.url} ${f.host} ${f.path} ${f.method} ${f.matched} ${f.detail}`.toLowerCase();
                if (!q.split(/\s+/).every(t => hay.includes(t))) return false;
            }
            return true;
        });
    }

    function _renderFindingsGrid() {
        const grid = $('proxy-fd-grid');
        if (!grid) return;
        grid.innerHTML = _fdCats.map(c => {
            const items = _fd.findings.filter(f => f.catKey === c.key);
            const count = items.length;
            const top   = items.reduce((best, f) => (_fdSevRank(f.sev) < _fdSevRank(best) ? f.sev : best), 'info');
            const active = _fd.cat === c.key;
            const sub   = count ? `${_fdSevMeta[top].label} severity (max)` : 'No vectors found';
            return `<button type="button" class="oxs-fd-card${active ? ' active' : ''}${count ? '' : ' empty'}" data-fd-cat="${c.key}" style="--fd-accent:${c.color};">` +
                   `<span class="oxs-fd-card-icon">${c.icon}</span>` +
                   `<span class="oxs-fd-card-main"><span class="oxs-fd-card-title">${_esc(c.label)}</span><span class="oxs-fd-card-sub">${_esc(sub)}</span></span>` +
                   `<span class="oxs-fd-card-count">${count}</span>` +
                   `</button>`;
        }).join('');
    }

    function _renderFindingsStats() {
        const list = _fd.findings;
        const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        list.forEach(f => { c[f.sev] = (c[f.sev] || 0) + 1; });
        _setText('proxy-fd-stat-total', String(list.length));
        _fdSeverities.forEach(s => _setText(`proxy-fd-stat-${s}`, String(c[s])));

        const total = list.length || 1;
        _fdSeverities.forEach(s => {
            const el = $(`proxy-fd-dist-${s}`);
            if (el) el.style.width = `${(c[s] / total * 100).toFixed(2)}%`;
        });

        const badge = $('proxy-findings-badge');
        if (badge) {
            badge.textContent = `${list.length} FOUND`;
            badge.className   = `dns-section-badge ${(c.critical || c.high) ? 'warn' : (list.length ? 'ok' : 'dim')}`;
        }
        const tabCount = $('proxy-findings-tab-count');
        if (tabCount) {
            tabCount.textContent = String(list.length);
            tabCount.hidden = list.length === 0;
        }
    }

    function _markSelectedFdRow() {
        const body = $('proxy-fd-body');
        if (!body) return;
        body.querySelectorAll('.oxs-rq-row').forEach(r => r.classList.toggle('sel', r.dataset.key === _fd.selected));
    }

    function _renderFindingsTable() {
        const body     = $('proxy-fd-body');
        const empty    = $('proxy-fd-empty');
        const emptyTxt = $('proxy-fd-empty-text');
        const table    = $('proxy-fd-table');
        if (!body) return;

        const rows  = _fdFiltered().slice().sort((a, b) => _fdSevRank(a.sev) - _fdSevRank(b.sev));
        const shown = rows.slice(0, 500);
        _setText('proxy-fd-showing', `Showing ${shown.length} of ${_fd.findings.length}${rows.length > 500 ? ' · top 500' : ''}`);

        if (!shown.length) {
            let msg;
            if (!_fd.job) msg = 'The listener is not connected. Start it from Configurations to begin analysis.';
            else if (_fd.findings.length) msg = 'No findings match the current filters.';
            else msg = 'No findings yet. Captured requests are analyzed automatically for potential vulnerability vectors.';
            body.innerHTML = `<tr class="oxs-rq-empty-row"><td colspan="6"><div class="oxs-rq-empty-box"><svg width="22" height="22" viewBox="0 0 16 16" fill="none"><circle cx="7" cy="7" r="4.3" stroke="currentColor" stroke-width="1.2" opacity=".6"/><path d="M10.2 10.2L13 13" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" opacity=".6"/></svg><span>${_esc(msg)}</span></div></td></tr>`;
            if (table) table.style.display = '';
            if (empty) empty.style.display = 'none';
            if (emptyTxt) emptyTxt.textContent = msg;
            return;
        }

        if (table) table.style.display = '';
        if (empty) empty.style.display = 'none';

        body.innerHTML = shown.map(f => {
            const meta    = _fdCatMeta(f.catKey);
            const sevMeta = _fdSevMeta[f.sev];
            return `<tr class="oxs-rq-row${f.key === _fd.selected ? ' sel' : ''}" data-key="${_attr(f.key)}">` +
                   `<td><span class="oxs-fd-cat-badge" style="--fd-accent:${meta ? meta.color : '#8a93a6'};">${_esc(meta ? meta.short : f.rawCat)}</span></td>` +
                   `<td><span class="oxs-rq-st ${sevMeta.cls}">${_esc(sevMeta.label)}</span></td>` +
                   `<td><span class="oxs-rq-m ${_methodClass(f.method)}">${_esc(f.method)}</span></td>` +
                   `<td class="oxs-rq-c-path" title="${_attr(f.url)}">${_esc(f.url || f.path)}</td>` +
                   `<td class="oxs-rq-c-src" title="${_attr(f.matched)}">${_esc(f.matched || '—')}</td>` +
                   `<td class="oxs-rq-c-time">${_fmtStamp(f.ts)}</td>` +
                   `</tr>`;
        }).join('');
    }

    function _renderFindingsDetail() {
        const panel  = $('proxy-fd-detail');
        const layout = $('proxy-fd-layout');
        if (!panel || !layout) return;

        const f = _fd.selected ? _fd.findings.find(x => x.key === _fd.selected) : null;
        if (!f) {
            _fd.selected = null;
            panel.hidden = true;
            layout.classList.remove('has-detail');
            _markSelectedFdRow();
            return;
        }

        panel.hidden = false;
        layout.classList.add('has-detail');

        const meta    = _fdCatMeta(f.catKey);
        const sevMeta = _fdSevMeta[f.sev];

        const catBadge = $('proxy-fd-d-cat');
        catBadge.textContent = meta ? meta.label : f.rawCat;
        catBadge.style.setProperty('--fd-accent', meta ? meta.color : '#8a93a6');

        const sevBadge = $('proxy-fd-d-sev');
        sevBadge.textContent = sevMeta.label;
        sevBadge.className   = `oxs-rq-st ${sevMeta.cls}`;

        _setText('proxy-fd-d-url', f.url || f.path);

        const metaRows = [
            ['Host', f.host],
            ['Method', f.method],
            ['Matched on', f.matched],
            ['Detected', _fmtStamp(f.ts)],
            ['Linked request', f.reqKey ? `#${f.reqKey.replace('id:', '')}` : 'Not linked'],
        ];
        $('proxy-fd-d-meta').innerHTML = metaRows.map(([k, v]) =>
            `<div class="oxs-rq-d-kv"><span class="oxs-rq-label">${k}</span><span class="oxs-rq-d-v" title="${_attr(v || '')}">${_esc(v || '—')}</span></div>`
        ).join('');

        const pre = $('proxy-fd-d-pre');
        pre.classList.toggle('empty', !f.detail);
        pre.textContent = f.detail || 'No further detail was provided for this finding.';

        const viewBtn = $('proxy-fd-d-view-request');
        if (viewBtn) viewBtn.disabled = !f.reqKey;

        _markSelectedFdRow();
    }

    function _updateFdLive() {
        const live = $('proxy-fd-live');
        if (live) {
            const state = _fd.job ? 'live' : 'offline';
            live.dataset.state = state;
            _setText('proxy-fd-live-text', state === 'live' ? 'Scanning' : 'Offline');
        }
    }

    function _renderFindingsAll() {
        _renderFindingsGrid();
        _renderFindingsStats();
        _renderFindingsTable();
        _renderFindingsDetail();
        _updateFdLive();
    }

    function _selectFd(key) {
        _fd.selected = _fd.selected === key ? null : key;
        _renderFindingsDetail();
    }

    function _exportFd() {
        const rows = _fdFiltered();
        if (!rows.length) {
            if (typeof UI !== 'undefined') UI.toast('Nothing to export', 'error');
            return;
        }
        const payload = rows.map(f => ({
            category:    f.rawCat,
            severity:    f.sev,
            method:      f.method,
            url:         f.url,
            matched_on:  f.matched || null,
            detail:      f.detail || null,
            detected_at: f.ts,
            request:     f.reqKey || null,
        }));
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        const href = URL.createObjectURL(blob);
        link.href = href;
        link.download = `oxs-findings-${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(href), 1000);
    }

    function _renderFindings(job) {
        const badge = $('proxy-findings-badge');
        if (!badge || !$('proxy-fd-body')) return;

        _fd.job = job || null;

        if (!job) {
            _fd.findings = [];
            _fd.selected = null;
            if ($('proxy-fd-meta')) $('proxy-fd-meta').textContent = 'Listener is offline';
            _renderFindingsAll();
            return;
        }

        const list = Array.isArray(job.findings) ? job.findings : [];
        _fd.findings = list.map(_normFinding);

        const meta = $('proxy-fd-meta');
        if (meta) {
            if (_fd.findings.length) {
                const cats = new Set(_fd.findings.map(f => f.catKey)).size;
                meta.textContent = `${_fd.findings.length} potential vector${_fd.findings.length === 1 ? '' : 's'} across ${cats} categor${cats === 1 ? 'y' : 'ies'}`;
            } else {
                meta.textContent = 'Connected · no vectors detected yet';
            }
        }
        _renderFindingsAll();
    }

    function _initFindings() {
        const search = $('proxy-fd-search');
        search?.addEventListener('input', () => {
            _fd.q = search.value;
            _renderFindingsTable();
        });

        $('proxy-fd-grid')?.addEventListener('click', event => {
            const card = event.target.closest('.oxs-fd-card');
            if (!card) return;
            const cat = card.dataset.fdCat;
            _fd.cat = _fd.cat === cat ? 'ALL' : cat;
            _renderFindingsGrid();
            _renderFindingsTable();
        });

        const sevChips = document.querySelectorAll('[data-fd-sev]');
        sevChips.forEach(btn => btn.addEventListener('click', () => {
            _fd.sev = btn.dataset.fdSev;
            sevChips.forEach(n => n.classList.toggle('active', n === btn));
            _renderFindingsTable();
        }));

        $('proxy-fd-body')?.addEventListener('click', event => {
            const row = event.target.closest('.oxs-rq-row');
            if (row) _selectFd(row.dataset.key);
        });

        $('proxy-fd-d-close')?.addEventListener('click', () => {
            _fd.selected = null;
            _renderFindingsDetail();
        });

        const currentFd = () => _fd.findings.find(x => x.key === _fd.selected);
        $('proxy-fd-d-copy-url')?.addEventListener('click', () => {
            const f = currentFd();
            if (f) _copyText(f.url, 'URL copied');
        });
        $('proxy-fd-d-view-request')?.addEventListener('click', () => {
            const f = currentFd();
            if (!f || !f.reqKey) return;
            _switchTab('requests');
            if (_rq.entries.some(e => e.key === f.reqKey)) {
                _rq.selected = f.reqKey;
                _renderRqDetail();
            } else if (typeof UI !== 'undefined') {
                UI.toast('Linked request is not in the current session view', 'error');
            }
        });

        $('proxy-fd-export')?.addEventListener('click', _exportFd);

        if (!_fd.keyBound) {
            _fd.keyBound = true;
            document.addEventListener('keydown', event => {
                if (event.key !== 'Escape' || !_fd.selected) return;
                const panel = $('proxy-panel-findings');
                if (!panel || panel.hidden) return;
                _fd.selected = null;
                _renderFindingsDetail();
            });
        }

        _renderFindingsAll();
    }

    function _initTabs() {
        const tabs = document.querySelectorAll('.oxs-tab');
        if (!tabs.length) return;
        tabs.forEach(tab => {
            tab.addEventListener('click', () => _switchTab(tab.dataset.tab));
        });
    }

    function _switchTab(name) {
        document.querySelectorAll('.oxs-tab').forEach(tab => {
            const active = tab.dataset.tab === name;
            tab.classList.toggle('active', active);
            tab.setAttribute('aria-selected', String(active));
        });
        document.querySelectorAll('.oxs-tabpanel').forEach(panel => {
            panel.hidden = panel.dataset.panel !== name;
        });
    }

    async function _request(path, options) {
        const res  = await fetch(`${_apiBase()}${path}`, {
            headers: { 'Content-Type': 'application/json' },
            ...(options || {}),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    }

    function _describeError(err) {
        const msg = err && err.message ? err.message : String(err);
        if (/Failed to fetch|NetworkError|Load failed/i.test(msg)) {
            return `Cannot reach Burp API at ${_apiHost}:${_apiPort}. Make sure the Burp API service is running.`;
        }
        return msg;
    }

    function _schedule(ms) {
        if (_loopTimer) clearTimeout(_loopTimer);
        if (!_loopRunning) return;
        _loopTimer = setTimeout(_tick, ms);
    }

    async function _tick() {
        if (!_loopRunning) return;
        if (!$('proxy-hero')) { _stopLoop(); return; }

        try {
            if (!_jobId) {
                // Starting (or restarting) a connection -- whatever was
                // captured before this point belongs to a previous session
                // and must not reappear in the GUI.
                _startNewSession();
                if (_apiConnState !== 'connected') _setState('connecting', 'Contacting Burp API');
                const t0   = performance.now();
                const ping = await _request('/api/ping');
                _latency   = Math.round(performance.now() - t0);
                const data = await _request('/api/burp/push/start', {
                    method: 'POST',
                    body:   JSON.stringify({ host: _apiHost, port: _apiPort }),
                });
                _jobId = data.job_id;
                _setText('proxy-service-text', ping.service || 'burp_api');
                _showError(null);
                _setState('connected', 'burp_api.py reachable');
                _applyJob({ ...data, job_id: _jobId }, ping.service || 'burp_api');
                _renderClocks();
                _schedule(300);
                return;
            }

            const t0  = performance.now();
            const job = await _request(`/api/burp/job/${_jobId}`);
            _latency  = Math.round(performance.now() - t0);
            _showError(null);
            _setState('connected', job.status === 'running' ? 'burp_api.py reachable' : `Job ${job.status}`);
            _applyJob({ ...job, job_id: _jobId });
            _renderClocks();
            if (job.status !== 'running') _jobId = null;
            _schedule(_pollMs);
        } catch (err) {
            const wasJob = Boolean(_jobId);
            _jobId = null;
            _latency = null;
            _setState('disconnected', wasJob ? 'Connection lost' : 'Waiting for Burp API');
            _showError(_describeError(err));
            _schedule(_retryMs);
        }
    }

    function _startLoop() {
        if (_loopRunning) return;
        _loopRunning = true;
        _tick();
        _tickTimer = setInterval(_renderClocks, 1000);
    }

    function _stopLoop() {
        _loopRunning = false;
        if (_loopTimer) { clearTimeout(_loopTimer); _loopTimer = null; }
        if (_tickTimer) { clearInterval(_tickTimer); _tickTimer = null; }
    }

    async function close() {
        if (!_jobId) return;
        const id = _jobId;
        _jobId = null;
        try { await _request(`/api/burp/push/stop/${id}`, { method: 'POST' }); } catch (err) {}
        _schedule(0);
    }

    function listen() { _startLoop(); }

    function reset() {
        _jobId = null;
        _latency = null;
        _setState('connecting', 'Contacting Burp API');
        _showError(null);
        _schedule(0);
    }

    function _ensureStyles() {
        if (document.getElementById('oxs-proxy-styles')) return;
        const style = document.createElement('style');
        style.id = 'oxs-proxy-styles';
        style.textContent = `
.oxs-ls-hero { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; padding: 14px 16px; border-radius: 8px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.03); transition: border-color .3s ease, background-color .3s ease; }
.oxs-ls-hero[data-state="connected"] { border-color: rgba(120,200,140,.4); background: rgba(120,200,140,.07); }
.oxs-ls-hero[data-state="connecting"] { border-color: rgba(245,197,24,.4); background: rgba(245,197,24,.06); }
.oxs-ls-hero[data-state="disconnected"] { border-color: rgba(230,100,100,.35); background: rgba(230,100,100,.05); }
.oxs-ls-state { display: flex; align-items: center; gap: 12px; min-width: 0; }
.oxs-ls-state-text { display: flex; flex-direction: column; gap: 2px; }
.oxs-ls-state-main { font-size: 18px; font-weight: 700; line-height: 1.1; }
.oxs-ls-state-sub { font-size: 11px; color: var(--text-dim); }
.oxs-ls-hero[data-state="connected"] .oxs-ls-state-main { color: #78c88c; }
.oxs-ls-hero[data-state="connecting"] .oxs-ls-state-main { color: #f5c518; }
.oxs-ls-hero[data-state="disconnected"] .oxs-ls-state-main { color: #e66464; }
.oxs-ls-dot { width: 12px; height: 12px; border-radius: 50%; flex: 0 0 auto; background: #e66464; box-shadow: 0 0 0 4px rgba(230,100,100,.15); }
.oxs-ls-hero[data-state="connected"] .oxs-ls-dot { background: #78c88c; box-shadow: 0 0 0 4px rgba(120,200,140,.18); animation: oxsLsPulse 2s ease-in-out infinite; }
.oxs-ls-hero[data-state="connecting"] .oxs-ls-dot { background: #f5c518; box-shadow: 0 0 0 4px rgba(245,197,24,.18); animation: oxsLsBlink 1s ease-in-out infinite; }
.oxs-ls-endpoint { display: flex; flex-direction: column; gap: 3px; align-items: flex-end; }
.oxs-ls-endpoint-value { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 16px; font-weight: 600; padding: 4px 10px; border-radius: 6px; background: rgba(255,255,255,.06); border: 1px solid var(--border, rgba(255,255,255,.1)); }
.oxs-ls-label { font-size: 10px; letter-spacing: .06em; text-transform: uppercase; color: var(--text-dim); }
.oxs-ls-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 10px; }
.oxs-ls-stat { display: flex; flex-direction: column; gap: 3px; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.025); min-width: 0; }
.oxs-ls-stat-value { font-size: 17px; font-weight: 700; font-variant-numeric: tabular-nums; white-space: nowrap; }
.oxs-ls-big { font-size: 24px; line-height: 1; }
.oxs-ls-stat-note { font-size: 10px; color: var(--text-dim); }
.oxs-ls-details { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 10px; padding: 10px 12px; border-radius: 8px; border: 1px dashed var(--border, rgba(255,255,255,.12)); }
.oxs-ls-detail { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.oxs-ls-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.oxs-ls-error { margin-top: 10px; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(230,100,100,.4); background: rgba(230,100,100,.1); }
.oxs-ls-error[hidden] { display: none; }
.oxs-ls-error-head { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 4px; }
.oxs-ls-error-title { font-size: 10px; letter-spacing: .06em; text-transform: uppercase; font-weight: 700; color: #e66464; }
.oxs-ls-error-meta { font-size: 10px; color: var(--text-dim); }
.oxs-ls-error-msg { font-size: 12px; color: #f0a0a0; word-break: break-word; }
@keyframes oxsLsPulse { 0%, 100% { box-shadow: 0 0 0 3px rgba(120,200,140,.18); } 50% { box-shadow: 0 0 0 7px rgba(120,200,140,0); } }
@keyframes oxsLsBlink { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
@media (max-width: 640px) { .oxs-ls-stats, .oxs-ls-details { grid-template-columns: repeat(2, 1fr); } .oxs-ls-endpoint { align-items: flex-start; } }
@media (prefers-reduced-motion: reduce) { .oxs-ls-dot { animation: none !important; } }
.dns-section-badge.warn { background: rgba(245,197,24,.15); color: rgba(245,197,24,.9); border-color: rgba(245,197,24,.3); }
#burp-configure-btn { transition: background-color .45s ease, color .45s ease, border-color .45s ease, box-shadow .45s ease, opacity .3s ease; }
#burp-configure-btn.burp-cfg-ready { background: #f5c518; background-image: none; color: #1a1400; border-color: #f5c518; animation: oxsCfgFill .6s ease-out, oxsCfgGlow 1.6s ease-in-out .6s 3; }
#burp-configure-btn.burp-cfg-ready:disabled { opacity: .75; cursor: progress; animation: none; }
#burp-configure-btn:disabled:not(.burp-cfg-ready), #burp-start-btn:disabled, #burp-stop-btn:disabled, #burp-reconfig-btn:disabled { opacity: .45; cursor: not-allowed; }
@keyframes oxsCfgFill { from { background-color: rgba(245,197,24,0); } to { background-color: #f5c518; } }
@keyframes oxsCfgGlow { 0%, 100% { box-shadow: 0 0 0 0 rgba(245,197,24,0); } 50% { box-shadow: 0 0 14px 2px rgba(245,197,24,.55); } }
@media (prefers-reduced-motion: reduce) { #burp-configure-btn.burp-cfg-ready { animation: none; } }
#burp-configure-btn.burp-cfg-done { background: rgba(245,197,24,.2); background-image: none; color: rgba(245,197,24,.55); border-color: rgba(245,197,24,.25); cursor: default; animation: none; }

.oxs-tabbar { display: flex; gap: 4px; margin-bottom: 14px; border-bottom: 1px solid var(--border, rgba(255,255,255,.1)); }
.oxs-tab { display: flex; align-items: center; gap: 6px; padding: 9px 14px; background: none; border: none; border-bottom: 2px solid transparent; color: var(--text-dim); font-size: 12px; font-weight: 600; cursor: pointer; transition: color .2s ease, border-color .2s ease; }
.oxs-tab:hover { color: var(--text, #e6e6e6); }
.oxs-tab.active { color: var(--text, #e6e6e6); border-bottom-color: #f5c518; }
.oxs-tab-count { display: inline-flex; align-items: center; justify-content: center; min-width: 16px; height: 16px; padding: 0 4px; border-radius: 8px; background: rgba(255,255,255,.1); color: var(--text-dim); font-size: 10px; font-weight: 700; }
.oxs-tab.active .oxs-tab-count { background: rgba(245,197,24,.2); color: #f5c518; }

.oxs-rq-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.oxs-rq-live { display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 12px; border: 1px solid var(--border, rgba(255,255,255,.12)); font-size: 10px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; color: var(--text-dim); }
.oxs-rq-live i { width: 7px; height: 7px; border-radius: 50%; background: #8a93a6; display: block; }
.oxs-rq-live[data-state="live"] { border-color: rgba(120,200,140,.4); color: #78c88c; }
.oxs-rq-live[data-state="live"] i { background: #78c88c; box-shadow: 0 0 0 3px rgba(120,200,140,.18); animation: oxsLsPulse 2s ease-in-out infinite; }
.oxs-rq-live[data-state="paused"] { border-color: rgba(245,197,24,.4); color: #f5c518; }
.oxs-rq-live[data-state="paused"] i { background: #f5c518; }
.oxs-rq-live[data-state="offline"] i { background: #8a93a6; }
.oxs-req-toolbar-label { font-size: 11px; color: var(--text-dim); }
.oxs-req-toolbar-meta { font-size: 11px; color: var(--text-dim); margin-left: auto; }

.oxs-rq-hero { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 14px; border-radius: 8px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.03); margin-bottom: 10px; }
.oxs-rq-hero-main { display: flex; flex-direction: column; gap: 2px; }
.oxs-rq-hero-v { font-size: 26px; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; }
.oxs-rq-dist { display: flex; width: 220px; max-width: 40%; height: 8px; border-radius: 4px; overflow: hidden; background: rgba(255,255,255,.06); }
.oxs-rq-dist span { display: block; height: 100%; width: 0; transition: width .3s ease; }
.oxs-rq-dist .c1 { background: #4fb6e8; }
.oxs-rq-dist .c2 { background: #78c88c; }
.oxs-rq-dist .c3 { background: #f5c518; }
.oxs-rq-dist .c4 { background: #f5a84f; }
.oxs-rq-dist .c5 { background: #e66464; }
.oxs-rq-dist .c0 { background: #8a93a6; }

.oxs-rq-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 12px; }
.oxs-rq-card { display: flex; flex-direction: column; gap: 4px; padding: 9px 11px; border-radius: 7px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.025); border-left: 2px solid transparent; }
.oxs-rq-card .oxs-rq-label { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.oxs-rq-card-v { font-size: 18px; font-weight: 700; font-variant-numeric: tabular-nums; }
.oxs-rq-card.c1 { border-left-color: #4fb6e8; }
.oxs-rq-card.c2 { border-left-color: #78c88c; }
.oxs-rq-card.c3 { border-left-color: #f5c518; }
.oxs-rq-card.c4 { border-left-color: #f5a84f; }
.oxs-rq-card.c5 { border-left-color: #e66464; }

.oxs-rq-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.oxs-rq-search { flex: 1; display: flex; align-items: center; gap: 8px; padding: 7px 10px; border-radius: 6px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.025); color: var(--text-dim); min-width: 0; }
.oxs-rq-search svg { flex: 0 0 auto; opacity: .6; }
.oxs-rq-search input { flex: 1; min-width: 0; background: none; border: none; outline: none; color: var(--text, #e6e6e6); font-size: 12px; }
.oxs-rq-search input::placeholder { color: var(--text-dim); }
.oxs-rq-actions { display: flex; gap: 8px; flex: 0 0 auto; }
.oxs-rq-btn { display: inline-flex; align-items: center; gap: 5px; padding: 7px 12px; border-radius: 6px; border: 1px solid var(--border, rgba(255,255,255,.12)); background: rgba(255,255,255,.04); color: var(--text, #e6e6e6); font-size: 11px; font-weight: 600; cursor: pointer; white-space: nowrap; transition: background-color .2s ease, border-color .2s ease; }
.oxs-rq-btn:hover { background: rgba(255,255,255,.08); }
.oxs-rq-btn.danger { color: #e66464; border-color: rgba(230,100,100,.3); }
.oxs-rq-btn.danger:hover { background: rgba(230,100,100,.1); }
.oxs-rq-btn.on { background: rgba(245,197,24,.15); border-color: rgba(245,197,24,.35); color: #f5c518; }
.oxs-rq-pending { margin-left: 2px; padding: 1px 5px; border-radius: 8px; background: rgba(245,197,24,.25); font-size: 9px; }

.oxs-rq-filters { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 10px; }
.oxs-rq-group { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.oxs-rq-group .oxs-rq-label { margin-right: 2px; }
.oxs-rq-chip { padding: 4px 10px; border-radius: 12px; border: 1px solid var(--border, rgba(255,255,255,.12)); background: rgba(255,255,255,.03); color: var(--text-dim); font-size: 11px; font-weight: 600; cursor: pointer; transition: background-color .2s ease, color .2s ease, border-color .2s ease; }
.oxs-rq-chip:hover { color: var(--text, #e6e6e6); }
.oxs-rq-chip.active { background: rgba(255,255,255,.1); color: var(--text, #e6e6e6); border-color: rgba(255,255,255,.2); }
.oxs-rq-chip.c1.active { background: rgba(79,182,232,.18); color: #4fb6e8; border-color: rgba(79,182,232,.4); }
.oxs-rq-chip.c2.active { background: rgba(120,200,140,.18); color: #78c88c; border-color: rgba(120,200,140,.4); }
.oxs-rq-chip.c3.active { background: rgba(245,197,24,.18); color: #f5c518; border-color: rgba(245,197,24,.4); }
.oxs-rq-chip.c4.active { background: rgba(245,168,79,.18); color: #f5a84f; border-color: rgba(245,168,79,.4); }
.oxs-rq-chip.c5.active { background: rgba(230,100,100,.18); color: #e66464; border-color: rgba(230,100,100,.4); }
.oxs-rq-showing { margin-left: auto; font-size: 11px; color: var(--text-dim); white-space: nowrap; }

.oxs-rq-layout { display: flex; gap: 12px; align-items: flex-start; }
.oxs-rq-main { flex: 1; min-width: 0; }
.oxs-rq-layout.has-detail .oxs-rq-main { flex: 1 1 60%; }

.oxs-req-table-wrap { border-radius: 8px; border: 1px solid var(--border, rgba(255,255,255,.1)); overflow: hidden; }
.oxs-rq-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.oxs-rq-table thead th { text-align: left; padding: 8px 10px; font-size: 10px; letter-spacing: .05em; text-transform: uppercase; color: var(--text-dim); background: rgba(255,255,255,.03); border-bottom: 1px solid var(--border, rgba(255,255,255,.1)); white-space: nowrap; }
.oxs-rq-table tbody td { padding: 7px 10px; border-bottom: 1px solid rgba(255,255,255,.05); vertical-align: middle; }
.oxs-rq-row { cursor: pointer; transition: background-color .15s ease; }
.oxs-rq-row:hover { background: rgba(255,255,255,.035); }
.oxs-rq-row.sel { background: rgba(245,197,24,.08); }
.oxs-rq-row.new { animation: oxsRqNew 1.4s ease-out; }
@keyframes oxsRqNew { 0% { background: rgba(120,200,140,.18); } 100% { background: transparent; } }
.oxs-rq-c-time, .oxs-rq-c-num { font-variant-numeric: tabular-nums; color: var(--text-dim); white-space: nowrap; }
.oxs-rq-c-src { color: var(--text-dim); max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.oxs-rq-c-path { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }
.oxs-rq-empty-row td { border-bottom: none; }
.oxs-rq-empty-box { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 36px 20px; text-align: center; color: var(--text-dim); font-size: 12px; }
.oxs-req-empty { display: none; }

.oxs-rq-m { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: .03em; background: rgba(255,255,255,.08); color: var(--text, #e6e6e6); }
.oxs-rq-m-get { background: rgba(79,182,232,.16); color: #4fb6e8; }
.oxs-rq-m-post { background: rgba(120,200,140,.16); color: #78c88c; }
.oxs-rq-m-put { background: rgba(245,197,24,.16); color: #f5c518; }
.oxs-rq-m-delete { background: rgba(230,100,100,.16); color: #e66464; }
.oxs-rq-m-other { background: rgba(255,255,255,.1); color: var(--text-dim); }

.oxs-rq-st { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; font-variant-numeric: tabular-nums; }
.oxs-rq-st-1xx { background: rgba(79,182,232,.16); color: #4fb6e8; }
.oxs-rq-st-2xx { background: rgba(120,200,140,.16); color: #78c88c; }
.oxs-rq-st-3xx { background: rgba(245,197,24,.16); color: #f5c518; }
.oxs-rq-st-4xx { background: rgba(245,168,79,.16); color: #f5a84f; }
.oxs-rq-st-5xx { background: rgba(230,100,100,.16); color: #e66464; }
.oxs-rq-st-na { background: rgba(255,255,255,.08); color: var(--text-dim); }

.oxs-rq-detail { flex: 0 0 340px; max-width: 340px; display: flex; flex-direction: column; gap: 10px; padding: 14px; border-radius: 8px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.03); }
.oxs-rq-d-head { display: flex; align-items: center; gap: 8px; }
.oxs-rq-x { margin-left: auto; display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 5px; border: none; background: rgba(255,255,255,.06); color: var(--text-dim); cursor: pointer; }
.oxs-rq-x:hover { background: rgba(255,255,255,.12); color: var(--text, #e6e6e6); }
.oxs-rq-d-url { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; word-break: break-all; color: var(--text, #e6e6e6); background: rgba(255,255,255,.04); padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border, rgba(255,255,255,.08)); }
.oxs-rq-d-btns { display: flex; gap: 8px; }
.oxs-rq-d-btns .oxs-rq-btn { flex: 1; justify-content: center; }
.oxs-rq-d-meta { display: flex; flex-direction: column; gap: 6px; }
.oxs-rq-d-kv { display: flex; justify-content: space-between; gap: 10px; font-size: 11px; }
.oxs-rq-d-v { color: var(--text, #e6e6e6); max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: right; }
.oxs-rq-d-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border, rgba(255,255,255,.1)); }
.oxs-rq-d-tab { padding: 6px 10px; background: none; border: none; border-bottom: 2px solid transparent; color: var(--text-dim); font-size: 11px; font-weight: 600; cursor: pointer; }
.oxs-rq-d-tab.active { color: var(--text, #e6e6e6); border-bottom-color: #f5c518; }
.oxs-rq-d-pre { margin: 0; max-height: 320px; overflow: auto; padding: 10px; border-radius: 6px; background: rgba(0,0,0,.25); border: 1px solid var(--border, rgba(255,255,255,.08)); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; color: var(--text, #e6e6e6); }
.oxs-rq-d-pre.empty { color: var(--text-dim); font-style: italic; }

.oxs-fd-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 12px; }
.oxs-fd-card { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border, rgba(255,255,255,.1)); background: rgba(255,255,255,.025); border-left: 3px solid var(--fd-accent, #8a93a6); cursor: pointer; text-align: left; transition: background-color .2s ease, border-color .2s ease; }
.oxs-fd-card:hover { background: rgba(255,255,255,.05); }
.oxs-fd-card.active { background: rgba(255,255,255,.07); border-color: var(--fd-accent, #8a93a6); }
.oxs-fd-card.empty { opacity: .55; }
.oxs-fd-card-icon { flex: 0 0 auto; display: inline-flex; color: var(--fd-accent, #8a93a6); }
.oxs-fd-card-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.oxs-fd-card-title { font-size: 12px; font-weight: 600; color: var(--text, #e6e6e6); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.oxs-fd-card-sub { font-size: 10px; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.oxs-fd-card-count { flex: 0 0 auto; font-size: 18px; font-weight: 700; font-variant-numeric: tabular-nums; }

.oxs-fd-cat-badge { display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 5px; font-size: 10px; font-weight: 700; background: color-mix(in srgb, var(--fd-accent, #8a93a6) 18%, transparent); color: var(--fd-accent, #8a93a6); }
.oxs-fd-d-section-title { font-size: 10px; letter-spacing: .05em; text-transform: uppercase; color: var(--text-dim); margin-top: 2px; }

@media (max-width: 900px) {
  .oxs-rq-cards { grid-template-columns: repeat(2, 1fr); }
  .oxs-fd-grid { grid-template-columns: repeat(2, 1fr); }
  .oxs-rq-layout.has-detail { flex-direction: column; }
  .oxs-rq-detail { flex: 1 1 auto; max-width: none; }
}
`;
        document.head.appendChild(style);
    }

    function _pathKey()      { return `${_val('burp-jar-path')}\n${_val('java-path')}`; }
    function _pathsReady()   { return Boolean(_val('burp-jar-path')) && Boolean(_val('java-path')); }
    function _isConfigured() { return _pathsReady() && _configuredKey === _pathKey(); }
    function _anyBusy()      { return Object.values(_busy).some(Boolean); }

    function _setLabel(id, html) {
        if ($(id)) $(id).innerHTML = html;
    }

    function _restoreLabel(id) {
        if ($(id) && _labels[id] !== undefined) $(id).innerHTML = _labels[id];
    }

    function _syncControls() {
        const ready      = _pathsReady();
        const configured = _isConfigured();
        const busy       = _anyBusy();

        const cfg = $('burp-configure-btn');
        if (cfg) {
            cfg.disabled = !ready || busy || configured;
            cfg.classList.toggle('burp-cfg-ready', ready && !configured);
            cfg.classList.toggle('burp-cfg-done', configured);
            if (!busy) cfg.textContent = configured ? 'Configured' : 'Configure';
        }
        if ($('burp-start-btn'))    $('burp-start-btn').disabled    = !configured || _running || busy;
        if ($('burp-stop-btn'))     $('burp-stop-btn').disabled     = !(_running || _busy.start) || _busy.stop || _busy.reconfig;
        if ($('burp-reconfig-btn')) $('burp-reconfig-btn').disabled = !(configured || _running) || busy;
    }

    function _updateConfigBadge() {
        const el = $('burp-config-badge');
        if (el) {
            const configured = _isConfigured();
            el.textContent = configured ? 'CONFIGURED' : (_pathsReady() ? 'READY' : 'NOT CONFIGURED');
            el.className   = `dns-section-badge ${configured ? 'ok' : 'dim'}`;
        }
        _syncControls();
    }

    function _setupBrowse(fieldId, fileId, browseBtnId) {
        const field  = $(fieldId);
        const file   = $(fileId);
        const browse = $(browseBtnId);
        if (!field || !file || !browse) return;

        browse.addEventListener('click', () => file.click());
        file.addEventListener('change', event => {
            const picked = event.target.files?.[0];
            if (!picked) return;
            field.value = picked.path || picked.name;
            _updateConfigBadge();
        });
    }

    function _esc(text) {
        const d = document.createElement('div');
        d.textContent = text ?? '';
        return d.innerHTML;
    }

    function _fallbackCandidate(path) {
        const low   = path.toLowerCase();
        const ed    = /enterprise/.test(low) ? 'Enterprise'
                    : /(^|[^a-z])pro(fessional)?([^a-z]|$)|burp[-_ ]?suite[-_ ]?pro/.test(low) ? 'Professional'
                    : /community/.test(low) ? 'Community' : '';
        const ver   = (path.match(/\d{4}\.\d+(?:\.\d+)*/) || [])[0];
        const label = `Burp Suite${ed ? ' ' + ed : ''}${ver ? ' ' + ver : ''}`;
        return { path, edition: ed || 'Unknown', version: ver || null, label };
    }

    function _badge2(text, color) {
        return ` <span style="font-size:9px;font-weight:600;letter-spacing:.04em;padding:1px 6px;border-radius:8px;margin-left:4px;background:${color};">${text}</span>`;
    }

    function _itemBadges(kind, c) {
        if (kind !== 'java') return '';
        let out = '';
        if (c.bundled) out += _badge2('BURP BUNDLED', 'rgba(120,200,140,.22)');
        if (c.recommended) out += _badge2('RECOMMENDED', 'rgba(120,200,140,.22)');
        else if (!c.compatible) out += _badge2('TOO OLD', 'rgba(230,100,100,.22)');
        else out += _badge2('MAY SHOW JRE WARNING', 'rgba(230,180,80,.22)');
        return out;
    }

    function _renderList(kind) {
        const state = _lists[kind];
        const list  = $(state.listId);
        if (!list) return;
        const current = _val(state.fieldId);
        const extra   = kind === 'java' ? ' java-version-item' : '';
        list.innerHTML = state.items.map((c, i) => {
            const active = c.path === current;
            return `<div class="burp-version-item${extra}" data-index="${i}" style="display:flex;flex-direction:column;gap:2px;padding:8px 10px;cursor:pointer;` +
                   `${i ? 'border-top:1px solid var(--border, rgba(255,255,255,.08));' : ''}` +
                   `${active ? 'background:rgba(120,200,140,.12);' : ''}">` +
                   `<span style="font-size:12px;font-weight:600;">${_esc(c.label)}${_itemBadges(kind, c)}${active ? ' <span style="opacity:.7;font-weight:400;">· selected</span>' : ''}</span>` +
                   `<span style="font-size:10px;color:var(--text-dim);word-break:break-all;">${_esc(c.path)}</span></div>`;
        }).join('');
    }

    function _toggleList(kind, show) {
        const list = $(_lists[kind].listId);
        if (!list) return;
        list.hidden = show === undefined ? !list.hidden : !show;
        if (!list.hidden) _renderList(kind);
    }

    function _setList(kind, items, show) {
        const state = _lists[kind];
        const list  = $(state.listId);
        state.items = Array.isArray(items) ? items : [];
        const has   = state.items.length > 0;
        const btn   = $(state.btnId);
        if (btn) btn.style.display = has ? '' : 'none';
        if ($(state.countId)) $(state.countId).textContent = state.items.length;
        const open = show === undefined ? Boolean(list && !list.hidden) : show;
        _toggleList(kind, has && open);
    }

    const _extensions = [
        { id: 'burp-exporter', label: 'Burp Exporter', description: 'Streams captured Burp traffic into the Oxsium database in real time.' },
    ];
    let _selectedExtensionId = 'burp-exporter';

    function _currentExtension() {
        return _extensions.find(e => e.id === _selectedExtensionId) || _extensions[0] || null;
    }

    function _renderExtensionCurrent() {
        const ext = _currentExtension();
        if ($('burp-extension-current')) $('burp-extension-current').textContent = ext ? ext.label : 'None selected';
    }

    function _renderExtensionList() {
        const list = $('burp-extension-list');
        if (!list) return;
        list.innerHTML = _extensions.map((e, i) => {
            const active = e.id === _selectedExtensionId;
            return `<div class="burp-version-item" data-id="${_esc(e.id)}" style="display:flex;flex-direction:column;gap:2px;padding:8px 10px;cursor:pointer;` +
                   `${i ? 'border-top:1px solid var(--border, rgba(255,255,255,.08));' : ''}` +
                   `${active ? 'background:rgba(120,200,140,.12);' : ''}">` +
                   `<span style="font-size:12px;font-weight:600;">${_esc(e.label)}${active ? ' <span style="opacity:.7;font-weight:400;">· selected</span>' : ''}</span>` +
                   `${e.description ? `<span style="font-size:10px;color:var(--text-dim);">${_esc(e.description)}</span>` : ''}</div>`;
        }).join('');
    }

    function _toggleExtensionList(show) {
        const list = $('burp-extension-list');
        if (!list) return;
        list.hidden = show === undefined ? !list.hidden : !show;
        if (!list.hidden) _renderExtensionList();
    }

    function _selectExtension(id) {
        if (!_extensions.some(e => e.id === id)) return;
        _selectedExtensionId = id;
        _renderExtensionCurrent();
        _renderExtensionList();
        _toggleExtensionList(false);
    }

    async function _loadJava(applyDefault) {
        let data;
        try {
            data = await _request('/api/java/list', { method: 'GET' });
        } catch (err) {
            return null;
        }
        _javaMeta = { required: data.required_java_version ?? null, tested: data.tested_java_major ?? null };
        _lists.java.items = Array.isArray(data.candidates) ? data.candidates : [];
        if ($(_lists.java.countId)) $(_lists.java.countId).textContent = _lists.java.items.length;
        if (applyDefault && data.default_path && $('java-path')) {
            $('java-path').value = data.default_path;
            _javaAuto = true;
            _updateConfigBadge();
            _renderList('java');
            try {
                await _request('/api/burp/config', {
                    method: 'POST',
                    body:   JSON.stringify({ java_path: data.default_path }),
                });
            } catch (err) {
                return data;
            }
        }
        return data;
    }

    async function _selectItem(kind, index) {
        const state  = _lists[kind];
        const picked = state.items[index];
        if (!picked) return;
        if ($(state.fieldId)) $(state.fieldId).value = picked.path;
        if (kind === 'java') _javaAuto = false;
        _updateConfigBadge();
        _renderList(kind);
        try {
            await _request('/api/burp/config', {
                method: 'POST',
                body:   JSON.stringify(kind === 'java' ? { java_path: picked.path } : { burp_jar: picked.path }),
            });
        } catch (err) {
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
            return;
        }
        if (typeof UI !== 'undefined') {
            if (kind === 'java' && !picked.compatible) {
                const need = _javaMeta.required ? ` (Burp JAR requires Java ${_javaMeta.required}+)` : '';
                UI.toast(`Selected: ${picked.label} — too old${need}`, 'error');
            } else if (kind === 'java' && !picked.recommended) {
                UI.toast(`Selected: ${picked.label} — Burp may show a JRE warning dialog`, 'success');
            } else {
                UI.toast(`Selected: ${picked.label}`, 'success');
            }
        }
        _toggleList(kind, false);
        if (kind === 'burp') _loadJava(_javaAuto);
    }

    async function _autoDetect(target, fieldId) {
        const btnId = target === 'java' ? 'java-auto-btn' : 'burp-jar-auto-btn';
        const btn   = $(btnId);
        const orig  = btn ? btn.innerHTML : null;

        if (btn) {
            btn.disabled  = true;
            btn.innerHTML = '<span class="auto-dots"><span></span><span></span><span></span></span>Searching';
        }

        try {
            const endpoint = target === 'java' ? '/api/java/auto' : '/api/burp/auto';
            let data;
            try {
                data = await _request(endpoint, { method: 'POST' });
            } catch (error) {
                if (!/^HTTP (404|405)$/.test(error.message)) throw error;
                data = await _request(`/api/burp/detect/${target}`, { method: 'GET' });
            }
            if ($(fieldId)) $(fieldId).value = data.path;
            _updateConfigBadge();

            if (target === 'java') {
                _javaAuto = true;
                _javaMeta = { required: data.required_java_version ?? null, tested: data.tested_java_major ?? null };
                _setList('java', data.candidates, (data.candidates || []).length > 1);
                const found = (data.candidates || []).find(c => c.path === data.path);
                const label = found ? found.label : data.path;
                const tooOld = Boolean(data.required_java_version) && data.java_version < data.required_java_version;
                if (typeof UI !== 'undefined') {
                    const note = data.warning && !data.default_recommended ? ` — ${data.warning}` : '';
                    UI.toast(`Java selected: ${label}${note}`, tooOld ? 'error' : 'success');
                }
                return;
            }

            _setList('burp', Array.isArray(data.candidates) && data.candidates.length
                ? data.candidates
                : [_fallbackCandidate(data.path)], true);
            const n = _lists.burp.items.length;
            _loadJava(_javaAuto);
            if (n > 1 && typeof UI !== 'undefined') {
                UI.toast(`${n} Burp Suite versions found — pick one from the list`, 'success');
                return;
            }
            if (typeof UI !== 'undefined') UI.toast(`Burp JAR found: ${data.path}`, 'success');
        } catch (err) {
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        } finally {
            if (btn) { btn.innerHTML = orig; btn.disabled = false; }
        }
    }

    async function configure() {
        if (!_pathsReady() || _anyBusy()) return;

        const key = _pathKey();
        _busy.configure = true;
        _setLabel('burp-configure-btn', '<span class="auto-dots"><span></span><span></span><span></span></span>Configuring');
        _syncControls();

        try {
            const data = await _request('/api/burp/configure', {
                method: 'POST',
                body:   JSON.stringify({ burp_jar: _val('burp-jar-path'), java_path: _val('java-path') }),
            });
            _configuredKey = key;
            if (typeof UI !== 'undefined') {
                const next = _running ? 'Restart Burp Suite to load the extension.' : 'You can start Burp Suite now.';
                UI.toast(`${data.edition || 'Burp'} configured. ${next}`, 'success');
            }
        } catch (err) {
            _configuredKey = null;
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        } finally {
            _busy.configure = false;
            _restoreLabel('burp-configure-btn');
            _updateConfigBadge();
        }
    }

    function _setProcessState(running, pid) {
        _running = Boolean(running);
        const status = $('burp-process-status');
        if (status) status.textContent = _running ? `Running (pid ${pid})` : 'Not running';
        _syncControls();
    }

    async function _refreshProcessState() {
        try {
            const data = await _request('/api/burp/status');
            _setProcessState(Boolean(data.running), data.pid);
        } catch (err) {
            _syncControls();
        }
    }

    function _startStatusPolling() {
        if (_statusTimer) clearInterval(_statusTimer);
        _statusTimer = setInterval(() => {
            if (!$('burp-start-btn')) {
                clearInterval(_statusTimer);
                _statusTimer = null;
                return;
            }
            if (!_anyBusy()) _refreshProcessState();
        }, 60000);
    }

    async function startBurp() {
        if (_busy.start || _running || !_isConfigured()) return;

        _stopRequested = false;
        _busy.start = true;
        _setLabel('burp-start-btn', 'Starting...');
        if ($('burp-process-status')) $('burp-process-status').textContent = 'Starting...';
        _syncControls();

        try {
            const data = await _request('/api/burp/launch', { method: 'POST' });
            _setProcessState(true, data.pid);
            if (typeof UI !== 'undefined') UI.toast(`BurpSuite started (pid ${data.pid})`, 'success');
        } catch (err) {
            if (!_stopRequested && typeof UI !== 'undefined') UI.toast(err.message, 'error');
        } finally {
            _busy.start = false;
            _restoreLabel('burp-start-btn');
            await _refreshProcessState();
        }
    }

    async function closeBurp() {
        if (_busy.stop) return;

        _stopRequested = true;
        _busy.stop = true;
        _setLabel('burp-stop-btn', 'Closing...');
        _syncControls();

        try {
            const data = await _request('/api/burp/close', { method: 'POST' });
            _setProcessState(false);
            if (typeof UI !== 'undefined') UI.toast(data.closed ? 'BurpSuite closed' : 'BurpSuite was not running', 'success');
        } catch (err) {
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        } finally {
            _busy.stop = false;
            _restoreLabel('burp-stop-btn');
            await _refreshProcessState();
        }
    }

    async function reconfigBurp() {
        if (_anyBusy()) return;

        _busy.reconfig = true;
        _setLabel('burp-reconfig-btn', 'Reconfiguring...');
        _syncControls();

        try {
            const data = await _request('/api/burp/reconfig', { method: 'POST' });
            _setProcessState(true, data.pid);

            const integ = data.jython_integration || {};
            const kept  = [];
            if (integ.jython_already_configured)    kept.push('Jython');
            if (integ.extension_already_configured) kept.push('Burp Exporter');

            const msg = kept.length
                ? `Reconfigured and relaunched. Kept existing: ${kept.join(', ')}.`
                : 'Reconfigured and relaunched.';
            if (typeof UI !== 'undefined') UI.toast(msg, 'success');
        } catch (err) {
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        } finally {
            _busy.reconfig = false;
            _restoreLabel('burp-reconfig-btn');
            await _refreshProcessState();
        }
    }

    function init() {
        _ensureStyles();
        _startLoop();
        ['burp-configure-btn', 'burp-start-btn', 'burp-stop-btn', 'burp-reconfig-btn'].forEach(id => {
            if ($(id)) _labels[id] = $(id).innerHTML;
        });
        _syncControls();

        $('burp-configure-btn')?.addEventListener('click', configure);

        $('burp-start-btn')?.addEventListener('click', startBurp);
        $('burp-stop-btn')?.addEventListener('click', closeBurp);
        $('burp-reconfig-btn')?.addEventListener('click', reconfigBurp);
        _refreshProcessState();
        _startStatusPolling();


        document.querySelectorAll('.dns-section-head').forEach(head => {
            head.addEventListener('click', () => {
                head.closest('.dns-section').classList.toggle('collapsed');
            });
        });

        _initTabs();
        _initRequests();

        _setupBrowse('burp-jar-path', 'burp-jar-file', 'burp-jar-browse-btn');
        _setupBrowse('java-path', 'java-file', 'java-browse-btn');

        $('burp-jar-auto-btn')?.addEventListener('click', () => _autoDetect('burp-jar', 'burp-jar-path'));
        $('java-auto-btn')?.addEventListener('click', () => _autoDetect('java', 'java-path'));

        Object.keys(_lists).forEach(kind => {
            const state = _lists[kind];
            $(state.btnId)?.addEventListener('click', () => _toggleList(kind));
            $(state.listId)?.addEventListener('click', event => {
                const item = event.target.closest('.burp-version-item');
                if (item) _selectItem(kind, Number(item.dataset.index));
            });
        });

        _renderExtensionCurrent();
        $('burp-extension-select-btn')?.addEventListener('click', () => _toggleExtensionList());
        $('burp-extension-list')?.addEventListener('click', event => {
            const item = event.target.closest('.burp-version-item');
            if (item) _selectExtension(item.dataset.id);
        });

        $('burp-jar-path')?.addEventListener('input', () => {
            _updateConfigBadge();
            if (_lists.burp.items.length > 1) _renderList('burp');
        });
        $('java-path')?.addEventListener('input', () => {
            _javaAuto = false;
            _updateConfigBadge();
            if (_lists.java.items.length) _renderList('java');
        });
        $('java-file')?.addEventListener('change', () => { _javaAuto = false; });

        _loadJava(false);
    }

    return { init, listen, close, reset };

})();