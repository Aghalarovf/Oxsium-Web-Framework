/**
 * Oxsium Web — target.js
 * Target formu: oxuma, saxlama, doğrulama.
 */

const Target = (() => {

    const STORAGE_KEY = 'oxsium_web_target';

    /* ── Form sahələri ─────────────────────────────────────── */
    const fields = {
        domain:   () => document.getElementById('input-domain'),
        url:      () => document.querySelector('input[placeholder="https://target.com"]'),
        ip:       () => document.querySelector('input[placeholder="192.168.1.10"]'),
        port:     () => document.querySelector('input[placeholder="443"]'),
        basePath: () => document.querySelector('input[placeholder="/api/v1"]'),
        username: () => document.querySelector('input[placeholder="admin"]'),
        password: () => document.querySelector('input[type="password"]'),
        headers:  () => document.querySelector('.form-textarea'),
        proxy:    () => document.querySelector('input[placeholder="http://127.0.0.1:8080"]'),
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
            if (el) State.target[key] = el.value.trim();
        });
    }

    /* ── State-dən forma yaz ───────────────────────────────── */
    function writeForm() {
        Object.entries(fields).forEach(([key, fn]) => {
            const el = fn();
            if (el && State.target[key]) el.value = State.target[key];
        });
    }

    /* ── Domain dəyişdikdə yalnız state-i yenilə (URL sahəsinə toxunma) ── */
    function _onDomainChange() {
        const domainEl = fields.domain();
        if (!domainEl) return;

        State.target.domain = domainEl.value.trim();
        save();
    }

    /* ── URL dəyişdikdə Domain-i avtomatik yenilə ─────────── */
    function _onUrlChange() {
        const domainEl = fields.domain();
        const urlEl    = fields.url();
        if (!domainEl || !urlEl) return;

        const raw = urlEl.value.trim();

        // http:// və ya https:// ilə başlamırsa avtomatik əlavə et
        if (raw && !/^https?:\/\//i.test(raw)) {
            urlEl.value = 'https://' + raw;
        }

        const domain = _extractDomain(urlEl.value.trim());
        if (domain) domainEl.value = domain;

        State.target.domain = domainEl.value.trim();
        State.target.url    = urlEl.value.trim();
        save();
    }

    /* ── Doğrulama ─────────────────────────────────────────── */
    function validate() {
        readForm();
        const url = State.target.url;

        if (!url) {
            UI.toast('Target URL is required', 'error');
            const el = fields.url();
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
        const port = State.target.port ? parseInt(State.target.port, 10) : undefined;

        if (!url) return;

        try {
            const body = {
                url,
                ...(port && !isNaN(port) ? { port }            : {}),
                ...(State.target.proxy   ? { proxy:   State.target.proxy   } : {}),
                ...(State.target.headers ? { headers: State.target.headers } : {}),
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

    /* ── Form input-larını dinlə ───────────────────────────── */
    function initListeners() {
        const domainEl = fields.domain();
        const urlEl    = fields.url();

        // Domain inputu dəyişdikdə → URL avtomatik yenilənsin
        if (domainEl) {
            domainEl.addEventListener('input', _onDomainChange);
            domainEl.addEventListener('blur',  () => {
                _onDomainChange();
                syncRightPanel();
                syncBackend();
            });
        }

        // URL inputu dəyişdikdə → Domain avtomatik yenilənsin + prefix əlavə edilsin
        if (urlEl) {
            urlEl.addEventListener('input', _onUrlChange);
            urlEl.addEventListener('blur',  () => {
                _onUrlChange();
                syncRightPanel();
                syncBackend();
            });
        }

        // Digər sahələr
        const otherKeys = ['ip', 'port', 'basePath', 'username', 'password', 'headers', 'proxy'];
        otherKeys.forEach(key => {
            const el = fields[key]();
            if (!el) return;
            el.addEventListener('input', () => { readForm(); save(); });
            el.addEventListener('blur',  () => {
                syncRightPanel();
                if (key === 'port') syncBackend();
            });
        });
    }

    function init() {
        load();
        initListeners();
    }

    return { init, readForm, writeForm, validate, save, load, syncRightPanel, syncBackend };
})();