/**
 * Oxsium Web — target.js
 * Target formu: oxuma, saxlama, doğrulama.
 */

const Target = (() => {

    const STORAGE_KEY = 'oxsium_web_target';

    /* ── Form sahələri ─────────────────────────────────────── */
    const fields = {
        domain:   () => document.getElementById('input-domain'),
        url:      () => null,
        threads:  () => document.querySelector('#target-threads-group .dns-thread-btn-active'),
        intercept:() => document.getElementById('input-intercept'),
    };

    /* ── URL-dən domain çıxar ──────────────────────────────── */
    function _extractDomain(url) {
        try {
            return new URL(url).hostname;
        } catch {
            return url.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
        }
    }

    /* ── Domain-dən URL yarat (prefix yoxdursa əlavə et) ──── */
    function _buildUrl(domain) {
        const d = domain.trim();
        if (!d) return '';
        if (/^https?:\/\//i.test(d)) return d;
        return 'https://' + d;
    }

    /* ── Formdan State-ə oxu ───────────────────────────────── */
    function readForm() {
        Object.entries(fields).forEach(([key, fn]) => {
            const el = fn();
            if (el) State.target[key] = key === 'threads'
                ? parseInt(el.dataset.val || '3', 10)
                : el.value.trim();
        });
    }

    /* ── State-dən forma yaz ───────────────────────────────── */
    function writeForm() {
        Object.entries(fields).forEach(([key, fn]) => {
            const el = fn();
            if (el && State.target[key]) {
                if (key === 'threads') {
                    document.querySelectorAll('#target-threads-group .dns-thread-btn').forEach(btn => {
                        btn.classList.toggle('dns-thread-btn-active', btn.dataset.val === String(State.target[key]));
                    });
                } else {
                    el.value = State.target[key];
                }
            }
        });
    }

    /* ── Domain dəyişdikdə yalnız state-i yenilə (URL sahəsinə toxunma) ── */
    function _onDomainChange() {
        const domainEl = fields.domain();
        if (!domainEl) return;

        State.target.domain = domainEl.value.trim();
        State.target.url = _buildUrl(State.target.domain);
        save();
    }

    /* ── URL dəyişdikdə Domain-i avtomatik yenilə ─────────── */
    function _onUrlChange() {
        const domainEl = fields.domain();
        if (!domainEl) return;
        const domain = _extractDomain(domainEl.value.trim());
        if (domain) domainEl.value = domain;

        State.target.domain = domainEl.value.trim();
        State.target.url    = _buildUrl(State.target.domain);
        save();
    }

    /* ── Doğrulama ─────────────────────────────────────────── */
    function validate() {
        readForm();
        const url = State.target.url || _buildUrl(State.target.domain);
        State.target.url = url;

        if (!url) {
            UI.toast('Domain Name is required', 'error');
            const el = fields.domain();
            if (el) {
                el.classList.add('error');
                setTimeout(() => el.classList.remove('error'), 2000);
            }
            return false;
        }

        try {
            new URL(url);
        } catch {
            UI.toast('Invalid URL format', 'error');
            return false;
        }

        return true;
    }

    /* ── LocalStorage-ə saxla ──────────────────────────────── */
    function save() {
        readForm();
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(State.target));
        } catch { /* ignore */ }
    }

    /* ── LocalStorage-dən yüklə ────────────────────────────── */
    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return;
            const saved = JSON.parse(raw);
            Object.assign(State.target, saved);
            writeForm();
        } catch { /* ignore */ }
    }

    /* ── Sağ paneli Target məlumatı ilə yenilə ─────────────── */
    function syncRightPanel() {
        readForm();
        UI.updateRightPanel({
            targetUrl: State.target.url    || '--',
            ipAddress: State.target.ip     || '--',
        });
    }

    /* ── Backend-ə target məlumatı göndər ─────────────────── */
    async function syncBackend() {
        readForm();
        const url  = State.target.url;
        if (!url) return;

        try {
            const body = {
                url,
                ...(State.target.threads ? { threads: State.target.threads } : {}),
            };

            const res = await fetch(`${State.api.base}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(body),
            });

            const data = await res.json();

            if (data.success) {
                UI.toast(`Target set → ${data.target.host}`, 'success');
                UI.setConnBadge('connected');
                UI.updateRightPanel({
                    targetUrl: data.target.url,
                    ipAddress: State.target.ip || '--',
                });
            } else {
                UI.toast(`Backend error: ${data.error}`, 'error');
                UI.setConnBadge('error');
            }

        } catch {
            UI.toast('Backend unreachable', 'error');
            UI.setConnBadge('error');
        }
    }

    function reset() {
        const domainEl = fields.domain();
        const interceptEl = fields.intercept();
        if (domainEl) domainEl.value = '';
        if (interceptEl) interceptEl.value = '';
        document.querySelectorAll('#target-threads-group .dns-thread-btn').forEach(btn => {
            btn.classList.toggle('dns-thread-btn-active', btn.dataset.val === '3');
        });
        State.target.domain = '';
        State.target.url = '';
        State.target.threads = 3;
        State.target.intercept = '';
        save();
        syncRightPanel();
        UI.toast('Target settings reset', 'info');
    }

    /* ── Form input-larını dinlə ───────────────────────────── */
    function initListeners() {
        const domainEl = fields.domain();
        if (domainEl) {
            domainEl.addEventListener('input', _onDomainChange);
            domainEl.addEventListener('blur',  () => {
                _onDomainChange();
                syncRightPanel();
                syncBackend();
            });
        }

        document.querySelectorAll('#target-threads-group .dns-thread-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('#target-threads-group .dns-thread-btn').forEach(item => item.classList.remove('dns-thread-btn-active'));
                btn.classList.add('dns-thread-btn-active');
                readForm();
                save();
            });
        });

        const browseBtn = document.getElementById('target-browse-btn');
        const interceptFile = document.getElementById('target-intercept-file');
        if (browseBtn && interceptFile) browseBtn.addEventListener('click', () => interceptFile.click());
        if (interceptFile) interceptFile.addEventListener('change', event => {
            const file = event.target.files?.[0];
            const input = fields.intercept();
            if (!file || !input) return;
            input.value = file.name;
            readForm();
            save();
        });
        const resetBtn = document.getElementById('ts-reset-btn');
        if (resetBtn) resetBtn.addEventListener('click', reset);

        const otherKeys = ['intercept'];
        otherKeys.forEach(key => {
            const el = fields[key]();
            if (!el) return;
            el.addEventListener('input', () => { readForm(); save(); });
            el.addEventListener('blur',  () => {
                syncRightPanel();
                syncBackend();
            });
        });
    }

    function init() {
        load();
        initListeners();
    }

    return { init, readForm, writeForm, validate, save, load, reset, syncRightPanel, syncBackend };
})();