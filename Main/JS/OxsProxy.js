const OxsProxy = (() => {

    let _timer     = null;
    let _running   = false;
    const seenLogs = new Set();

    const $     = id => document.getElementById(id);
    const _val  = id => ($( id)?.value?.trim() || '');
    const _chk  = id => Boolean($(id)?.checked);

    // ─────────────────────────── Payload ─────────────────────

    function _payload() {
        const limit = _val('proxy-limit');
        return {
            listener_ip:  _val('proxy-listener-ip')   || '0.0.0.0',
            listener_port: Number(_val('proxy-listener-port') || 8080),
            domain:        _val('proxy-domain'),
            crawl:         _chk('proxy-crawl'),
            intercept:     _chk('proxy-intercept'),
            full_traffic:  _chk('proxy-full-traffic'),
            max_pages:     Number(_val('proxy-max-pages') || 200),
            limit:         limit ? Number(limit) : null,
            crawl_delay:   Number(_val('proxy-crawl-delay') || 0.1),
            probe_delay:   Number(_val('proxy-probe-delay') || 1),
            user_agent:    _val('proxy-user-agent'),
            ca_cert:       _val('proxy-ca-cert') || 'oxsproxy.crt',
            ca_key:        _val('proxy-ca-key')  || 'oxsproxy.key',
            output:        _val('proxy-output')  || 'oxsproxy',
            cookies:       _val('proxy-cookies'),
        };
    }

    // ─────────────────────────── Output log ──────────────────

    function _log(message, type) {
        const el = $('proxy-output-log');
        if (!el) return;
        el.querySelector('.output-placeholder')?.remove();
        let pre = el.querySelector('pre');
        if (!pre) {
            pre = document.createElement('pre');
            pre.style.cssText = 'margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:11px;line-height:1.6;';
            el.innerHTML = '';
            el.appendChild(pre);
        }
        const span       = document.createElement('span');
        span.style.color = type === 'success' ? 'var(--green)'
                         : type === 'error'   ? '#c07820'
                         : type === 'warn'    ? '#d09030'
                         :                      'var(--text-sec)';
        span.textContent = `[${new Date().toLocaleTimeString('en-GB', { hour12: false })}] ${message}\n`;
        pre.appendChild(span);
        el.scrollTop = el.scrollHeight;
    }

    function _clearLog() {
        const el = $('proxy-output-log');
        if (el) el.innerHTML = '<span class="output-placeholder">// Proxy output will appear here when running…</span>';
    }

    // ─────────────────────────── Badge helpers ────────────────

    function _badge(id, text, cls) {
        const el = $(id);
        if (!el) return;
        el.textContent = text;
        el.className   = `dns-section-badge ${cls}`;
    }

    function _text(id, text) {
        const el = $(id);
        if (el) el.textContent = text;
    }

    function _val2(id, text, cls) {
        const el = $(id);
        if (!el) return;
        el.textContent = text;
        el.className   = `dcr-val ${cls || 'dim'}`;
    }

    // ─────────────────────────── Render state ────────────────

    function _render(data) {
        const running  = data.running  || false;
        const starting = data.starting || false;
        const err      = data.error    || false;

        const stateLabel = running  ? 'ONLINE'
                         : starting ? 'STARTING'
                         : err      ? '--'
                         :            'OFFLINE';
        const stateCls   = running  ? 'ok'
                         : starting ? 'warn'
                         : err      ? 'dim'
                         :            'dim';

        _badge('proxy-state-badge', stateLabel, stateCls);

        if ($('proxy-start-btn')) $('proxy-start-btn').disabled = running || starting;
        if ($('proxy-stop-btn'))  $('proxy-stop-btn').disabled  = !running && !starting;

        const p = data.config || {};

        // Listener section
        _badge('listener-badge', stateLabel, stateCls);
        _val2('lst-bind',         p.listener_ip   || '--');
        _val2('lst-port',         p.listener_port ? String(p.listener_port) : '--');
        _val2('lst-status',       stateLabel, stateCls);
        _val2('lst-intercept',    p.intercept     ? 'ENABLED'  : 'DISABLED',  p.intercept     ? 'ok' : 'dim');
        _val2('lst-full-traffic', p.full_traffic  ? 'ENABLED'  : 'DISABLED',  p.full_traffic  ? 'ok' : 'dim');

        // Crawler section
        _badge('crawler-badge', p.crawl ? 'ACTIVE' : '--', p.crawl ? 'ok' : 'dim');
        _val2('crawl-enabled',     p.crawl      ? 'YES' : 'NO',          p.crawl ? 'ok' : 'dim');
        _val2('crawl-delay',       p.crawl_delay  != null ? `${p.crawl_delay}s`  : '--');
        _val2('crawl-probe-delay', p.probe_delay   != null ? `${p.probe_delay}s`  : '--');
        _val2('crawl-ua',          p.user_agent || 'Default');
        _val2('crawl-file',        data.files?.crawl     || '--');

        _text('crawl-pages-visited', data.stats?.pages_visited ?? '--');
        _text('crawl-pages-max',     p.max_pages               ?? '--');
        _text('crawl-requests',      data.stats?.requests      ?? '--');
        _text('crawl-limit',         p.limit                   ?? '∞');

        // CA section
        _badge('ca-badge', data.ca_ready ? 'READY' : '--', data.ca_ready ? 'ok' : 'dim');
        _val2('ca-cert-path',  p.ca_cert  || '--');
        _val2('ca-key-path',   p.ca_key   || '--');
        _val2('ca-cn',         p.ca_cn    || '--');
        _val2('ca-overwrite',  p.overwrite ? 'YES' : 'NO');

        (data.logs || []).forEach(item => {
            const key = `${item.type || ''}:${item.message}`;
            if (seenLogs.has(key)) return;
            seenLogs.add(key);
            _log(item.message, item.type || '');
        });
    }

    // ─────────────────────────── API ─────────────────────────

    async function _request(path, options) {
        const res  = await fetch(`${State.api.base}${path}`, {
            headers: { 'Content-Type': 'application/json' },
            ...(options || {}),
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    }

    // ─────────────────────────── Actions ─────────────────────

    async function refresh() {
        try {
            const data = await _request('/api/proxy/status');
            _render(data);
        } catch (_e) {
            _render({ error: true });
        }
    }

    async function start() {
        try {
            _clearLog();
            const p    = _payload();
            const data = await _request('/api/proxy/start', {
                method: 'POST',
                body:   JSON.stringify(p),
            });
            _render({ ...data, config: p });
            _log(data.message || 'Proxy started.', 'success');
            if (typeof UI !== 'undefined') UI.toast('OxsIntercept proxy started', 'success');
            _running = true;
            _startPolling();
        } catch (err) {
            _log(err.message, 'error');
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        }
    }

    async function stop() {
        try {
            const data = await _request('/api/proxy/stop', { method: 'POST' });
            _render(data);
            _log(data.message || 'Proxy stopped.', 'success');
            _running = false;
            _stopPolling();
        } catch (err) {
            _log(err.message, 'error');
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        }
    }

    async function generateCertificate() {
        try {
            const data = await _request('/api/proxy/cert', {
                method: 'POST',
                body:   JSON.stringify({
                    ca_cert:   _val('proxy-ca-cert') || 'oxsproxy.crt',
                    ca_key:    _val('proxy-ca-key')  || 'oxsproxy.key',
                    ca_cn:     _val('proxy-ca-cn')   || 'OxsIntercept CA',
                    overwrite: _chk('proxy-overwrite-cert'),
                }),
            });
            _log(data.message, 'success');
            _badge('ca-badge', 'READY', 'ok');
            _val2('ca-cert-path', _val('proxy-ca-cert') || 'oxsproxy.crt');
            _val2('ca-key-path',  _val('proxy-ca-key')  || 'oxsproxy.key');
            _val2('ca-cn',        _val('proxy-ca-cn')   || 'OxsIntercept CA');
            if (typeof UI !== 'undefined') UI.toast('CA certificate generated', 'success');
        } catch (err) {
            _log(err.message, 'error');
            if (typeof UI !== 'undefined') UI.toast(err.message, 'error');
        }
    }

    // ─────────────────────────── Polling ─────────────────────

    function _startPolling() {
        _stopPolling();
        _timer = setInterval(refresh, 2500);
    }

    function _stopPolling() {
        if (_timer) { clearInterval(_timer); _timer = null; }
    }

    // ─────────────────────────── Init ────────────────────────

    function init() {
        $('proxy-start-btn')?.addEventListener('click', start);
        $('proxy-stop-btn')?.addEventListener('click', stop);
        $('proxy-refresh-btn')?.addEventListener('click', refresh);
        $('proxy-cert-btn')?.addEventListener('click', generateCertificate);

        const paramsHead = $('proxy-target-params-head');
        if (paramsHead) {
            paramsHead.addEventListener('click', () => {
                paramsHead.closest('.dns-section').classList.toggle('collapsed');
            });
        }

        refresh();
        _startPolling();
    }

    return { init, start, stop, refresh };

})();