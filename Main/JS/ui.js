/**
 * Oxsium Web — ui.js
 * DOM yeniləmə, toast, statusbar köməkçiləri.
 */

const UI = (() => {

    /* ── Statusbar ─────────────────────────────────────────── */
    function setStatus(status) {
        State.statusbar.status = status;
        State.info.status = status;
        const els = document.querySelectorAll('.s-val[data-field="status"]');
        els.forEach(el => el.textContent = status);
        const rightVal = document.querySelector('.stat-value[data-field="status"]');
        if (rightVal) rightVal.textContent = status;
    }

    function setModule(name) {
        State.statusbar.module = name || '--';
        const el = document.querySelector('.s-val[data-field="module"]');
        if (el) el.textContent = State.statusbar.module;
    }

    function setSession(val) {
        State.statusbar.session = val || '--';
        const el = document.querySelector('.s-val[data-field="session"]');
        if (el) el.textContent = State.statusbar.session;
    }

    /* ── Sağ panel ─────────────────────────────────────────── */
    function updateRightPanel(data = {}) {
        Object.entries(data).forEach(([key, val]) => {
            if (key in State.info) State.info[key] = val;
            const el = document.querySelector(`.stat-value[data-field="${key}"]`);
            if (!el) return;
            el.textContent = val || '--';
            el.className = 'stat-value';
            if (!val || val === '--') el.classList.add('dim');
        });
    }

    function resetRightPanel() {
        const defaults = {
            status: 'IDLE', targetUrl: '--', ipAddress: '--',
            webServer: '--', tlsVersion: '--', wafDetected: '--',
            responseTime: '--', http2: '--', cors: '--',
            hsts: '--', csp: '--', clickjacking: '--',
            apiBackend: '--', latency: '--',
        };
        updateRightPanel(defaults);
        const fill = document.querySelector('.progress-fill');
        if (fill) fill.style.width = '0%';
    }

    function setProgressBar(pct) {
        const fill = document.querySelector('.progress-fill');
        if (fill) fill.style.width = Math.min(100, Math.max(0, pct)) + '%';
    }

    /* ── Conn badge ────────────────────────────────────────── */
    function setConnBadge(state) {
        // state: 'idle' | 'connected' | 'scanning' | 'error'
        const dot   = document.querySelector('.conn-dot');
        const label = document.querySelector('.conn-label');
        if (!dot || !label) return;

        dot.className   = 'conn-dot';
        label.className = 'conn-label';

        const map = {
            idle:      { dot: '',          label: 'IDLE',       cls: '' },
            connected: { dot: 'connected', label: 'CONNECTED',  cls: 'connected' },
            scanning:  { dot: 'scanning',  label: 'SCANNING',   cls: '' },
            error:     { dot: 'error',     label: 'ERROR',      cls: 'error' },
        };

        const cfg = map[state] || map.idle;
        if (cfg.dot)  dot.classList.add(cfg.dot);
        if (cfg.cls)  label.classList.add(cfg.cls);
        label.textContent = cfg.label;
    }

    /* ── Toast bildirişləri ────────────────────────────────── */
    function toast(msg, type = 'info', duration = 3500) {
        const container = document.getElementById('toasts');
        if (!container) return;

        const icons = {
            success: `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="6" stroke="currentColor" stroke-width="1.3"/><path d="M4.5 7l2 2 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
            error:   `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="6" stroke="currentColor" stroke-width="1.3"/><path d="M5 5l4 4M9 5l-4 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>`,
            info:    `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="6" stroke="currentColor" stroke-width="1.3"/><path d="M7 6v4M7 4.5v.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>`,
        };

        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.innerHTML = `${icons[type] || icons.info}<span>${msg}</span>`;
        container.appendChild(el);

        setTimeout(() => {
            el.style.opacity = '0';
            el.style.transform = 'translateX(20px)';
            el.style.transition = 'all 0.25s ease';
            setTimeout(() => el.remove(), 260);
        }, duration);
    }

    /* ── Output terminal ───────────────────────────────────── */
    function logOutput(msg, type = 'info') {
        const wrap = document.querySelector('.output-wrap');
        if (!wrap) return;

        // İlk açılışdakı placeholder-ı sil
        const ph = wrap.querySelector('.output-placeholder');
        if (ph) ph.remove();

        const colors = {
            info:    'var(--text-dim)',
            ok:      '#22ff6e',
            warn:    '#ff9922',
            error:   '#ff4444',
            accent:  'var(--accent)',
        };

        const line = document.createElement('div');
        line.className = 'log-line';
        const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
        line.innerHTML = `<span style="color:var(--text-dim);user-select:none">[${ts}]</span> <span style="color:${colors[type] || colors.info}">${msg}</span>`;
        wrap.appendChild(line);
        wrap.scrollTop = wrap.scrollHeight;
    }

    function clearOutput() {
        const wrap = document.querySelector('.output-wrap');
        if (!wrap) return;
        wrap.innerHTML = `<span class="output-placeholder">// Output will appear here when scan is running...</span>`;
    }

    /* ── Nav count badge ───────────────────────────────────── */
    function setNavCount(moduleId, count) {
        const item = document.querySelector(`.nav-item[data-module="${moduleId}"] .nav-count`);
        if (item) item.textContent = count !== null ? count : '--';
    }

    /* ── API Backend ping loop ─────────────────────────────── */
    let _pingTimer = null;

    // Latency-dən bar faizi: 0ms→100%, 500ms→0% (xətti)
    const _LATENCY_MAX = 500;

    function _setApiStatus(online, latencyMs) {
        State.api.online  = online;
        State.api.latency = online ? latencyMs : null;

        // ── Sağ panel — API Backend mətni + rəngi ──────────────
        const backendEl = document.querySelector('.stat-value[data-field="apiBackend"]');
        if (backendEl) {
            backendEl.textContent = online ? 'Online' : 'Offline';
            backendEl.style.color  = online ? '#22c55e' : '#ef4444';
            backendEl.className    = 'stat-value';
        }

        // ── Sağ panel — Latency mətni ──────────────────────────
        const latEl = document.querySelector('.stat-value[data-field="latency"]');
        if (latEl) {
            latEl.textContent = online ? `${latencyMs} ms` : '--';
            latEl.className   = 'stat-value' + (online ? '' : ' dim');
        }

        // ── Latency progress bar ────────────────────────────────
        const fill = document.getElementById('api-latency-bar');
        if (fill) {
            if (!online) {
                fill.style.width      = '100%';
                fill.style.background = '#ef4444';
            } else {
                // Latency aşağı → bar dolu (yaxşı); latency yüksək → bar azalır
                const pct = Math.max(0, 100 - (latencyMs / _LATENCY_MAX) * 100);
                fill.style.width      = pct + '%';
                fill.style.background = pct > 60 ? '#22c55e'
                                      : pct > 30 ? '#f0c030'
                                      :            '#ef4444';
            }
            fill.style.transition = 'width 0.4s ease, background 0.4s ease';
        }

        // ── Statusbar — API sətri ───────────────────────────────
        const apiStatusEl = document.querySelector('.s-val[data-field="apiStatus"]');
        if (apiStatusEl) {
            apiStatusEl.textContent = online
                ? `${State.api.base.replace('http://', '')}  ·  ${latencyMs}ms`
                : 'OFFLINE';
            apiStatusEl.style.color = online ? '#22c55e' : '#ef4444';
        }
    }

    async function _ping() {
        const t0 = performance.now();
        try {
            const res = await fetch(`${State.api.base}/api/ping`, {
                method: 'GET',
                signal: AbortSignal.timeout(3000),
            });
            if (res.ok) {
                const latency = Math.round(performance.now() - t0);
                _setApiStatus(true, latency);
                return;
            }
        } catch { /* offline */ }
        _setApiStatus(false, null);
    }

    function startPing(intervalMs = 5000) {
        _ping();
        if (_pingTimer) clearInterval(_pingTimer);
        _pingTimer = setInterval(_ping, intervalMs);
    }

    function stopPing() {
        if (_pingTimer) { clearInterval(_pingTimer); _pingTimer = null; }
    }

    return {
        setStatus, setModule, setSession,
        updateRightPanel, resetRightPanel, setProgressBar,
        setConnBadge,
        toast, logOutput, clearOutput,
        setNavCount,
        startPing, stopPing,
    };
})();

window.reportDatabaseUnavailable = function (appendLabeled, toast) {
    const message = 'No usable results returned from the database or the JSON file';
    if (typeof appendLabeled === 'function') {
        appendLabeled('DATABASE', message, '#ff5c5c');
    } else if (typeof UI !== 'undefined' && typeof UI.logOutput === 'function') {
        UI.logOutput(`[ DATABASE ] ${message}`, 'error');
    }
    if (typeof toast === 'function') toast('Database results unavailable', 'error');
};