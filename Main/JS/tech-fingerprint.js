/**
 * Oxsium Web — Technology Fingerprint Module
 * ──────────────────────────────────────────
 * 11 sub-categories for passive technology detection:
 *  1. Web Framework Detection
 *  2. Frontend Library Fingerprinting
 *  3. CMS Identification
 *  4. Favicon Hash Matching (Shodan-style)
 *  5. Backend Language Detection
 *  6. OS Fingerprinting via Server Banners
 *
 * Follows DnsEnum.js IIFE pattern.
 */

const TechFingerprint = (() => {

    /* ── Known technology fingerprints ──────────────────────────
       Each entry: { name, category, version?, confidence?, test() }
       test() returns an object { detected, version, evidence }
       or null if not detected.
       Pattern-based matching on headers, HTML, JS, cookies, etc.
    ──────────────────────────────────────────────────────────── */

    const SIGNATURES = {

        /* ── 1. Web Frameworks ─────────────────────────────────── */
        'web-framework': [
            {
                name: 'Django',
                test: (ctx) => {
                    const h = ctx.headers;
                    if (h['x-frame-options'] && h['x-content-type-options'] === 'nosniff') {
                        return { detected: true, version: /^(\d+\.\d+)/.test(h['x-powered-by']) ? RegExp.$1 : '?', evidence: 'X-Frame-Options + X-Content-Type-Options' };
                    }
                    if (h['x-powered-by'] && h['x-powered-by'].toLowerCase().includes('django')) {
                        return { detected: true, version: (h['x-powered-by'].match(/[\d.]+/) || ['?'])[0], evidence: 'X-Powered-By: Django' };
                    }
                    if (/csrftoken/.test(ctx.cookies)) {
                        return { detected: true, version: '?', evidence: 'csrftoken cookie present' };
                    }
                    return null;
                }
            },
            {
                name: 'Laravel',
                test: (ctx) => {
                    if (ctx.cookies.includes('laravel_session') || ctx.cookies.includes('XSRF-TOKEN')) {
                        return { detected: true, version: '?', evidence: 'laravel_session / XSRF-TOKEN cookie' };
                    }
                    return null;
                }
            },
            {
                name: 'Ruby on Rails',
                test: (ctx) => {
                    if (ctx.headers['x-powered-by'] && ctx.headers['x-powered-by'].toLowerCase().includes('phusion')) {
                        return { detected: true, version: '?', evidence: 'X-Powered-By: Phusion Passenger' };
                    }
                    if (ctx.cookies.includes('_session_id') || ctx.cookies.includes('_rails')) {
                        return { detected: true, version: '?', evidence: 'Rails session cookie' };
                    }
                    return null;
                }
            },
            {
                name: 'Express.js',
                test: (ctx) => {
                    if (ctx.headers['x-powered-by'] && ctx.headers['x-powered-by'].toLowerCase().includes('express')) {
                        return { detected: true, version: (ctx.headers['x-powered-by'].match(/[\d.]+/) || ['?'])[0], evidence: 'X-Powered-By: Express' };
                    }
                    if (ctx.cookies.includes('connect.sid')) {
                        return { detected: true, version: '?', evidence: 'connect.sid cookie' };
                    }
                    return null;
                }
            },
            {
                name: 'Flask',
                test: (ctx) => {
                    if (ctx.cookies.includes('session') && !ctx.cookies.includes('PHPSESSID')) {
                        return { detected: true, version: '?', evidence: 'Flask session cookie' };
                    }
                    return null;
                }
            },
            {
                name: 'Spring Boot',
                test: (ctx) => {
                    if (ctx.headers['x-application-context'] || ctx.cookies.includes('JSESSIONID')) {
                        return { detected: true, version: '?', evidence: 'X-Application-Context / JSESSIONID' };
                    }
                    return null;
                }
            },
            {
                name: 'ASP.NET',
                test: (ctx) => {
                    const h = ctx.headers;
                    if (h['x-aspnet-version'] || h['x-powered-by']?.toLowerCase().includes('asp.net')) {
                        const v = h['x-aspnet-version'] || '?';
                        return { detected: true, version: v, evidence: 'X-AspNet-Version / X-Powered-By: ASP.NET' };
                    }
                    if (ctx.cookies.includes('ASP.NET_SessionId') || ctx.cookies.includes('__RequestVerificationToken')) {
                        return { detected: true, version: '?', evidence: 'ASP.NET session cookie' };
                    }
                    return null;
                }
            },
        ],

        /* ── 2. Frontend Libraries ───────────────────────────── */
        'frontend-library': [
            {
                name: 'React',
                test: (ctx) => {
                    if (ctx.html.includes('__NEXT_DATA__') || ctx.html.includes('_reactRootContainer') || ctx.html.includes('data-reactroot')) {
                        return { detected: true, version: '?', evidence: 'React DOM markers' };
                    }
                    if (ctx.html.match(/react(?:\.min)?\.js/i)) {
                        return { detected: true, version: '?', evidence: 'react.js script reference' };
                    }
                    return null;
                }
            },
            {
                name: 'Vue.js',
                test: (ctx) => {
                    if (ctx.html.includes('__VUE__') || ctx.html.includes('v-bind') || ctx.html.includes('v-model') || ctx.html.includes('vue-app')) {
                        return { detected: true, version: '?', evidence: 'Vue.js directives' };
                    }
                    if (ctx.html.match(/vue(?:\.min)?\.js/i)) {
                        return { detected: true, version: '?', evidence: 'vue.js script reference' };
                    }
                    return null;
                }
            },
            {
                name: 'Angular',
                test: (ctx) => {
                    if (ctx.cookies.includes('ng-')) {
                        return { detected: true, version: '?', evidence: 'ng- cookie prefix' };
                    }
                    if (ctx.html.match(/angular(?:\.min)?\.js/i) || ctx.html.includes('ng-app') || ctx.html.includes('ng-version=')) {
                        return { detected: true, version: (ctx.html.match(/ng-version="([^"]+)"/) || ['?','?'])[1], evidence: 'Angular script / directive' };
                    }
                    return null;
                }
            },
            {
                name: 'jQuery',
                test: (ctx) => {
                    const m = ctx.html.match(/jquery(?:[.-])([\d.]+)(?:\.min)?\.js/i);
                    if (m) { return { detected: true, version: m[1], evidence: 'jQuery script reference' }; }
                    if (ctx.html.includes('jQuery') || ctx.windowVars.includes('jQuery')) {
                        return { detected: true, version: '?', evidence: 'jQuery global detected' };
                    }
                    return null;
                }
            },
            {
                name: 'Bootstrap',
                test: (ctx) => {
                    const m = ctx.html.match(/bootstrap(?:[.-])([\d.]+)(?:\.min)?\.js/i) || ctx.html.match(/bootstrap(?:[.-])([\d.]+)(?:\.min)?\.css/i);
                    if (m) { return { detected: true, version: m[1], evidence: 'Bootstrap reference' }; }
                    if (ctx.html.includes('bootstrap')) {
                        return { detected: true, version: '?', evidence: 'Bootstrap string in source' };
                    }
                    return null;
                }
            },
            {
                name: 'Tailwind CSS',
                test: (ctx) => {
                    if (ctx.html.includes('tailwind') || ctx.html.match(/\.tw-/)) {
                        return { detected: true, version: '?', evidence: 'Tailwind CSS utility classes' };
                    }
                    return null;
                }
            },
        ],

        /* ── 3. CMS ───────────────────────────────────────────── */
        'cms': [
            {
                name: 'WordPress',
                test: (ctx) => {
                    if (ctx.html.includes('wp-content') || ctx.html.includes('wp-includes') || ctx.html.includes('wp-json')) {
                        return { detected: true, version: '?', evidence: 'wp-content / wp-json paths' };
                    }
                    if (ctx.headers['x-powered-by']?.toLowerCase().includes('wordpress')) {
                        const v = (ctx.headers['x-powered-by'].match(/[\d.]+/) || ['?'])[0];
                        return { detected: true, version: v, evidence: 'X-Powered-By: WordPress' };
                    }
                    if (ctx.cookies.includes('wordpress_') || ctx.cookies.includes('wp-settings-')) {
                        return { detected: true, version: '?', evidence: 'WordPress cookies' };
                    }
                    return null;
                }
            },
            {
                name: 'Drupal',
                test: (ctx) => {
                    if (ctx.html.includes('drupal') || ctx.headers['x-generator']?.toLowerCase().includes('drupal')) {
                        return { detected: true, version: '?', evidence: 'X-Generator: Drupal / HTML contains Drupal' };
                    }
                    if (ctx.html.includes('sites/default') || ctx.cookies.includes('Drupal')) {
                        return { detected: true, version: '?', evidence: 'Drupal paths / cookies' };
                    }
                    return null;
                }
            },
            {
                name: 'Joomla',
                test: (ctx) => {
                    if (ctx.html.includes('joomla') || ctx.html.includes('com_content') || ctx.html.includes('com_')) {
                        return { detected: true, version: '?', evidence: 'Joomla com_ components' };
                    }
                    if (ctx.cookies.includes('joomla') || ctx.headers['x-generator']?.toLowerCase().includes('joomla')) {
                        return { detected: true, version: '?', evidence: 'Joomla cookies / generator tag' };
                    }
                    return null;
                }
            },
            {
                name: 'Shopify',
                test: (ctx) => {
                    if (ctx.html.includes('shopify') || ctx.html.includes('myshopify.com') || ctx.headers['x-shopid']) {
                        return { detected: true, version: '?', evidence: 'Shopify headers / HTML markers' };
                    }
                    return null;
                }
            },
            {
                name: 'Magento',
                test: (ctx) => {
                    if (ctx.html.includes('magento') || ctx.cookies.includes('mage-') || ctx.headers['x-magento-*']) {
                        return { detected: true, version: '?', evidence: 'Magento cookies / paths' };
                    }
                    return null;
                }
            },
        ],

        /* ── 4. Favicon Hash ───────────────────────────────────── */
        'favicon': [],

        /* ── 5. Backend Languages ──────────────────────────────── */
        'backend-lang': [],

        /* ── 6. OS Fingerprinting ──────────────────────────────── */
        'os': [],
    };

    /* ── Known cookie-to-framework mappings ───────────────────── */
    const COOKIE_SIGNATURES = [
        { pattern: /^PHPSESSID/,     framework: 'PHP',         category: 'web-framework' },
        { pattern: /^JSESSIONID/,    framework: 'Java (JEE)',   category: 'web-framework' },
        { pattern: /^laravel_session/, framework: 'Laravel',    category: 'web-framework' },
        { pattern: /^XSRF-TOKEN/,   framework: 'Laravel',      category: 'web-framework' },
        { pattern: /^connect\.sid/,  framework: 'Express.js',   category: 'web-framework' },
        { pattern: /^session/,      framework: 'Flask',         category: 'web-framework' },
        { pattern: /^csrftoken/,    framework: 'Django',        category: 'web-framework' },
        { pattern: /^wordpress_/,   framework: 'WordPress',     category: 'cms' },
        { pattern: /^wp-settings-/, framework: 'WordPress',     category: 'cms' },
        { pattern: /^ASP.NET_SessionId/, framework: 'ASP.NET',  category: 'web-framework' },
        { pattern: /^__RequestVerificationToken/, framework: 'ASP.NET', category: 'web-framework' },
        { pattern: /^mage-/,        framework: 'Magento',       category: 'cms' },
        { pattern: /^Drupal/,       framework: 'Drupal',        category: 'cms' },
        { pattern: /^joomla/,       framework: 'Joomla',        category: 'cms' },
        { pattern: /^ng-/,          framework: 'Angular',       category: 'frontend-library' },
    ];

    /* ── Known backend language signatures from headers ─────── */
    const BACKEND_SIGNATURES = [
        { header: 'x-powered-by', pattern: /php/i,     lang: 'PHP',     version: null },
        { header: 'x-powered-by', pattern: /python/i,  lang: 'Python',  version: null },
        { header: 'x-powered-by', pattern: /express/i, lang: 'JavaScript (Node.js)', version: null },
        { header: 'x-powered-by', pattern: /asp\.net/i,lang: 'C# / ASP.NET', version: null },
        { header: 'x-powered-by', pattern: /rails/i,   lang: 'Ruby',    version: null },
        { header: 'server',       pattern: /nginx/i,   lang: 'Nginx (reverse proxy)', version: null },
        { header: 'server',       pattern: /apache/i,  lang: 'Apache HTTPD', version: null },
        { header: 'server',       pattern: /iis/i,     lang: 'IIS (Windows Server)', version: null },
        { header: 'server',       pattern: /gunicorn/i,lang: 'Python (Gunicorn)', version: null },
        { header: 'server',       pattern: /jetty/i,   lang: 'Java (Jetty)', version: null },
        { header: 'server',       pattern: /tomcat/i,  lang: 'Java (Tomcat)', version: null },
        { header: 'server',       pattern: /caddy/i,   lang: 'Go (Caddy)', version: null },
    ];

    /* ── Known OS signatures from Server header ────────────── */
    const OS_SIGNATURES = [
        { header: 'server', pattern: /ubuntu/i,        os: 'Ubuntu Linux' },
        { header: 'server', pattern: /debian/i,        os: 'Debian Linux' },
        { header: 'server', pattern: /centos/i,        os: 'CentOS Linux' },
        { header: 'server', pattern: /red hat/i,       os: 'Red Hat Enterprise Linux' },
        { header: 'server', pattern: /fedora/i,        os: 'Fedora Linux' },
        { header: 'server', pattern: /alpine/i,        os: 'Alpine Linux' },
        { header: 'server', pattern: /freebsd/i,       os: 'FreeBSD' },
        { header: 'server', pattern: /openbsd/i,       os: 'OpenBSD' },
        { header: 'server', pattern: /netbsd/i,        os: 'NetBSD' },
        { header: 'server', pattern: /windows/i,       os: 'Microsoft Windows' },
        { header: 'server', pattern: /win32/i,         os: 'Microsoft Windows' },
        { header: 'server', pattern: /darwin/i,        os: 'macOS / Darwin' },
        { header: 'server', pattern: /solaris/i,       os: 'Solaris' },
        { header: 'server', pattern: /sunos/i,         os: 'SunOS / Solaris' },
        { header: 'x-powered-by', pattern: /ubuntu/i,  os: 'Ubuntu Linux' },
        { header: 'x-powered-by', pattern: /debian/i,  os: 'Debian Linux' },
    ];

    /* ── Known favicon hashes (mmh3) ───────────────────────── */
    const FAVICON_DB = {
        '1165839474': { tech: 'WordPress',     confidence: 'high' },
        '1509554215': { tech: 'Joomla',        confidence: 'high' },
        '1337306826': { tech: 'Drupal',        confidence: 'high' },
        '-177732578': { tech: 'Magento',       confidence: 'high' },
        '1354213159': { tech: 'Laravel',       confidence: 'medium' },
        '-1241858149':{ tech: 'Shopify',       confidence: 'medium' },
        '-335242539': { tech: 'PrestaShop',    confidence: 'medium' },
        '443772150':  { tech: 'Jenkins',       confidence: 'high' },
        '81586312':   { tech: 'GitLab',        confidence: 'high' },
        '442749392':  { tech: 'Zabbix',        confidence: 'high' },
        '1275377343': { tech: 'phpMyAdmin',    confidence: 'high' },
        '368792497':  { tech: 'cPanel',        confidence: 'high' },
        '1483120789': { tech: 'Plesk',         confidence: 'high' },
        '1243225579': { tech: 'Grafana',       confidence: 'medium' },
        '1115771048': { tech: 'Discourse',     confidence: 'high' },
        '176305324':  { tech: 'Confluence',    confidence: 'high' },
        '1204388364': { tech: 'Atlassian Jira',confidence: 'high' },
        '-1046275872':{ tech: 'SonarQube',     confidence: 'medium' },
        '2094669375': { tech: 'Nginx Default', confidence: 'low' },
        '466049243':  { tech: 'Apache Default',confidence: 'low' },
    };

    /* ── API ────────────────────────────────────────────────── */
    const API_BASE    = 'http://127.0.0.1:30300';
    const DB_API_BASE = 'http://127.0.0.1:30301';
    const POLL_INTERVAL = 2000;
    const POLL_TIMEOUT  = 1800000;

    /* ── State ──────────────────────────────────────────────── */
    let _target     = '';
    let _scanning   = false;
    let _pollTimer  = null;
    let _pollStart  = 0;
    let _currentJob = null;

    /* ── DOM helpers ────────────────────────────────────────── */
    const $ = id => document.getElementById(id);

    function _esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function _toast(msg, type) {
        if (typeof UI !== 'undefined' && UI.toast) { UI.toast(msg, type); }
        else { console.log(`[${type}] ${msg}`); }
    }

    function _confidenceClass(conf) {
        const c = String(conf || 'low').toLowerCase();
        if (c === 'high')   return 'conf-high';
        if (c === 'medium') return 'conf-medium';
        return 'conf-low';
    }

    function _confidenceBadge(conf) {
        const c = String(conf || 'low').toLowerCase();
        const cls = c === 'high' ? 'ok' : c === 'medium' ? 'warn' : 'dim';
        return `<span class="tf-badge ${cls}" style="font-size:9px;">${c.toUpperCase()}</span>`;
    }

    /* ── Render helper: populate a category table ──────────── */
    function _renderTable(categoryId, rows) {
        const tbody = $(`tf-table-${categoryId}`);
        if (!tbody) return;

        const badge = $(`tf-badge-${categoryId}`);
        if (badge) {
            badge.textContent = rows.length;
            badge.className = 'tf-badge ' + (rows.length ? 'ok' : 'dim');
        }

        const catEl  = tbody.closest('.tf-category');
        const body   = catEl ? catEl.querySelector('.tf-category-body') : null;
        const chev   = catEl ? catEl.querySelector('.dns-section-chevron') : null;
        const isFav  = categoryId === 'favicon';

        if (!rows.length) {
            tbody.innerHTML = `<tr class="tf-empty-row"><td colspan="6">No technologies detected in this category</td></tr>`;
            if (!isFav && body) {
                body.style.display = 'none';
                if (chev) chev.style.transform = 'rotate(-90deg)';
            }
            return;
        }

        const LAST_COLS = new Set(['evidence', 'raw', 'url']);
        tbody.innerHTML = rows.map(r => {
            const cols = Object.keys(r);
            return `<tr>${cols.map((c, i) => {
                if (c === 'confidence') return `<td>${_confidenceBadge(r[c])}</td>`;
                if (c === 'vulnerable') {
                    const isVuln = String(r[c]).toUpperCase() === 'YES';
                    return `<td><span class="tf-badge ${isVuln ? 'warn' : 'dim'}" style="font-size:9px;">${_esc(String(r[c]))}</span></td>`;
                }
                const val = _esc(String(r[c] || '—'));
                // Last-col (evidence/url) gets title tooltip for full text
                if (LAST_COLS.has(c)) return `<td title="${val}">${val}</td>`;
                return `<td>${val}</td>`;
            }).join('')}</tr>`;
        }).join('');

        if (body) {
            body.style.display = '';
            if (chev) chev.style.transform = '';
        }
    }

    /* ── Collect context data from target URL ──────────────── */
    async function _fetchTargetData(url) {
        try {
            const resp = await fetch(`https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const html = await resp.text();
            return html;
        } catch (e) {
            // Fallback: fetch directly (may fail CORS)
            try {
                const r2 = await fetch(url, { mode: 'cors' });
                return await r2.text();
            } catch (e2) {
                throw new Error(`Cannot fetch target: ${e2.message}`);
            }
        }
    }

    function _parseHeadersFromResponse(resp) {
        const headers = {};
        resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        return headers;
    }

    function _extractCookies(html, headers) {
        // Try Set-Cookie header first
        const setCookie = headers['set-cookie'];
        const cookies = [];
        if (setCookie) {
            setCookie.split('\n').forEach(c => {
                const name = c.split('=')[0]?.trim();
                if (name) cookies.push({ name, raw: c });
            });
        }
        // Also search for common cookie patterns in HTML (meta, JS)
        const metaCookies = html.match(/name=["']cookie["'][^>]*content=["']([^"']+)["']/i);
        if (metaCookies) {
            metaCookies[1].split(';').forEach(c => {
                const name = c.split('=')[0]?.trim();
                if (name && !cookies.find(x => x.name === name)) {
                    cookies.push({ name, raw: c.trim() });
                }
            });
        }
        return cookies;
    }

    function _extractMetaTags(html) {
        const metas = [];
        const re = /<meta\s+([^>]+)>/gi;
        let m;
        while ((m = re.exec(html)) !== null) {
            const attrs = m[1];
            const name = attrs.match(/(?:name|property)="([^"]+)"/i);
            const content = attrs.match(/content="([^"]+)"/i);
            if (name && content) {
                metas.push({ name: name[1], content: content[1] });
            }
        }
        return metas;
    }

    function _extractComments(html) {
        const comments = [];
        const re = /<!--([\s\S]*?)-->/g;
        let m;
        while ((m = re.exec(html)) !== null) {
            const text = m[1].trim();
            if (text) comments.push(text);
        }
        return comments;
    }

    /* ── Core analysis ──────────────────────────────────────── */
    function _runAnalysis(ctx) {
        const results = {
            'web-framework':    [],
            'frontend-library': [],
            'cms':              [],
            'favicon':          [],
            'backend-lang':     [],
            'os':               [],
        };

        // ── 1-3, 7: Signature-based detection ──────────────────
        ['web-framework', 'frontend-library', 'cms'].forEach(cat => {
            (SIGNATURES[cat] || []).forEach(sig => {
                try {
                    const r = sig.test(ctx);
                    if (r && r.detected) {
                        const entry = {
                            name:       sig.name,
                            version:    r.version || '?',
                            confidence: r.confidence || 'high',
                            evidence:   r.evidence || 'Signature match',
                            ...(r.status ? { status: r.status } : {}),
                        };
                        results[cat].push(entry);
                    }
                } catch (e) {
                    // Silently skip failed tests
                }
            });
        });

        // ── 4. Cookie-based framework hints ────────────────────
        ctx.parsedCookies.forEach(c => {
            for (const cs of COOKIE_SIGNATURES) {
                if (cs.pattern.test(c.name)) {
                    if (!results['web-framework'].find(e => e.name === cs.framework) &&
                        !results['cms'].find(e => e.name === cs.framework) &&
                        !results['frontend-library'].find(e => e.name === cs.framework)) {
                        const targetCat = cs.category === 'cms' ? 'cms' : cs.category === 'frontend-library' ? 'frontend-library' : 'web-framework';
                        results[targetCat].push({
                            name:       cs.framework,
                            version:    '?',
                            confidence: 'medium',
                            evidence:   `Cookie: ${c.name}`,
                        });
                    }
                }
            }
        });

        // ── 5. CMS detection from meta generator tags ─────────
        ctx.metaTags.forEach(mt => {
            if (/generator/i.test(mt.name)) {
                const gen = mt.content.toLowerCase();
                if (gen.includes('wordpress') && !results.cms.find(e => e.name === 'WordPress')) {
                    results.cms.push({ name: 'WordPress', version: (mt.content.match(/[\d.]+/) || ['?'])[0], confidence: 'high', evidence: `Meta generator: ${mt.content}` });
                }
                if (gen.includes('drupal') && !results.cms.find(e => e.name === 'Drupal')) {
                    results.cms.push({ name: 'Drupal', version: (mt.content.match(/[\d.]+/) || ['?'])[0], confidence: 'high', evidence: `Meta generator: ${mt.content}` });
                }
                if (gen.includes('joomla') && !results.cms.find(e => e.name === 'Joomla')) {
                    results.cms.push({ name: 'Joomla', version: (mt.content.match(/[\d.]+/) || ['?'])[0], confidence: 'high', evidence: `Meta generator: ${mt.content}` });
                }
            }
        });

        // ── 10. Backend Language Detection ────────────────────
        BACKEND_SIGNATURES.forEach(bs => {
            const val = ctx.headers[bs.header];
            if (val && bs.pattern.test(val)) {
                const version = (val.match(/[\d.]+/) || ['?'])[0];
                if (!results['backend-lang'].find(e => e.name === bs.lang)) {
                    results['backend-lang'].push({
                        name:       bs.lang,
                        version:    version,
                        confidence: 'high',
                        evidence:   `${bs.header}: ${val.trim()}`,
                    });
                }
            }
        });

        // ── 10b. PHP detection from cookies ───────────────────
        if (ctx.cookies.includes('PHPSESSID') && !results['backend-lang'].find(e => e.name.startsWith('PHP'))) {
            results['backend-lang'].push({
                name:       'PHP',
                version:    '?',
                confidence: 'high',
                evidence:   'PHPSESSID cookie present',
            });
        }

        // ── 11. OS Fingerprinting ─────────────────────────────
        OS_SIGNATURES.forEach(os => {
            const val = ctx.headers[os.header];
            if (val && os.pattern.test(val)) {
                if (!results['os'].find(e => e.detected === os.os)) {
                    results['os'].push({
                        banner:     `${os.header}: ${val.trim()}`,
                        detected:   os.os,
                        confidence: 'high',
                        raw:        val.trim(),
                    });
                }
            }
        });

        // ── Deduplicate: keep highest confidence per name ────
        ['web-framework', 'frontend-library', 'cms', 'error-page', 'backend-lang'].forEach(cat => {
            const seen = {};
            results[cat] = results[cat].filter(e => {
                const key = e.name;
                if (seen[key]) {
                    // Keep higher confidence
                    const order = { high: 3, medium: 2, low: 1 };
                    if (order[e.confidence] > order[seen[key].confidence]) {
                        Object.assign(seen[key], e);
                    }
                    return false;
                }
                seen[key] = e;
                return true;
            });
        });

        return results;
    }

    /* ── Compute md5 → mmh3 for favicon ────────────────────── */
    /* ── We use a simple mmh3 JS implementation for the hash ── */
    function _mmh3(buf) {
        // MurmurHash3 x86 32-bit
        let h1 = 0;
        const len = buf.length;
        let i = 0;
        while (i + 3 < len) {
            const k1 = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24);
            i += 4;
            let k = k1 * 0xcc9e2d51 >>> 0;
            k = ((k << 15) | (k >>> 17)) >>> 0;
            k = k * 0x1b873593 >>> 0;
            h1 = ((h1 ^ k) >>> 0);
            h1 = ((h1 << 13) | (h1 >>> 19)) >>> 0;
            h1 = ((h1 * 5) + 0xe6546b64) >>> 0;
        }
        let tail = 0;
        const rem = len - i;
        if (rem >= 3) { tail ^= buf[i+2] << 16; }
        if (rem >= 2) { tail ^= buf[i+1] << 8; }
        if (rem >= 1) { tail ^= buf[i]; tail = tail * 0xcc9e2d51 >>> 0; tail = ((tail << 15) | (tail >>> 17)) >>> 0; tail = tail * 0x1b873593 >>> 0; h1 ^= tail; }
        h1 ^= len;
        h1 = ((h1 ^ (h1 >>> 16)) >>> 0) * 0x85ebca6b >>> 0;
        h1 = ((h1 ^ (h1 >>> 13)) >>> 0) * 0xc2b2ae35 >>> 0;
        h1 = (h1 ^ (h1 >>> 16)) >>> 0;
        return h1 | 0;
    }

    async function _fetchFavicon(url) {
        try {
            const favUrl = url.endsWith('/favicon.ico') ? url : (new URL('/favicon.ico', url)).href;
            const resp = await fetch(favUrl);
            if (!resp.ok) return null;
            const blob = await resp.blob();
            const buf = await blob.arrayBuffer();
            const hash = _mmh3(new Uint8Array(buf));
            return { hash, url: favUrl };
        } catch (e) {
            return null;
        }
    }

    function _renderFaviconResults(favData, results) {
        if (!favData) {
            $('tf-favicon-hash-display').textContent = '—';
            $('tf-favicon-match').textContent = 'No favicon accessible';
            return;
        }
        $('tf-favicon-hash-display').textContent = favData.hash;
        $('tf-favicon-img').src = favData.url;
        $('tf-favicon-img').style.display = 'block';
        $('tf-favicon-placeholder').style.display = 'none';

        const match = FAVICON_DB[favData.hash];
        if (match) {
            $('tf-favicon-match').textContent = `${match.tech} (${match.confidence})`;
            $('tf-favicon-shodan').style.display = 'inline';
            $('tf-favicon-shodan').href = `https://www.shodan.io/search?query=http.favicon.hash%3A${favData.hash}`;
            results.favicon = [{
                technology:  match.tech,
                hash:        favData.hash,
                confidence:  match.confidence,
            }];
        } else {
            $('tf-favicon-match').textContent = 'Unknown / Unmatched';
        }

        $('tf-favicon-hash').textContent = favData.hash;
        $('tf-favicon-hash').className = 'tf-summary-value mono';
    }

    /* ── Button state ───────────────────────────────────────── */
    function _setBtnState(scanning) {
        const scanningHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite">
                 <circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6"
                         stroke-dasharray="10 6" stroke-linecap="round"/>
               </svg> SCANNING…`;
        const idleHTML = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.4"/><path d="M11 11l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg> Fingerprint`;
        const btn = $('tf-scan-btn');
        if (btn) {
            btn.disabled      = scanning;
            btn.style.opacity = scanning ? '0.55' : '';
            btn.innerHTML     = scanning ? scanningHTML : idleHTML;
        }
        const stopBtn = $('tf-stop-btn');
        if (stopBtn) stopBtn.disabled = !scanning;
    }

    function stopScan() {
        if (!_scanning) return;
        _stopPolling();
        _scanning = false;
        _currentJob = null;
        _setBtnState(false);
        _appendScanResult(false, 'Scan stopped');
        _toast('Tech fingerprint scan stopped', 'warn');
    }

    function resetScan() {
        if (_scanning) stopScan();

        const target = $('tf-target');
        const proxy = $('tf-proxy');
        if (target) target.value = '';
        if (proxy) proxy.value = '';

        _currentJob = null;
        _clearOutput();
        _setBtnState(false);

        const summary = $('tf-summary');
        const toolbar = $('tf-toolbar');
        if (summary) summary.style.display = 'none';
        if (toolbar) toolbar.style.display = 'none';

        const info = $('tf-scan-info');
        if (info) info.textContent = 'No scan data — enter a target and click Fingerprint';

        document.querySelectorAll('#panel-tech-fingerprint .tf-badge').forEach(badge => {
            badge.textContent = '0';
        });
        document.querySelectorAll('#panel-tech-fingerprint .tf-table tbody').forEach(tbody => {
            const columns = tbody.closest('table')?.querySelectorAll('thead th').length || 1;
            tbody.innerHTML = `<tr class="tf-empty-row"><td colspan="${columns}">No technologies detected in this category</td></tr>`;
        });

        const filter = $('tf-filter');
        const category = $('tf-category-filter');
        if (filter) filter.value = '';
        if (category) category.value = 'all';

        const favicon = $('tf-favicon-img');
        const faviconPlaceholder = $('tf-favicon-placeholder');
        const faviconHash = $('tf-favicon-hash-display');
        const faviconMatch = $('tf-favicon-match');
        const faviconShodan = $('tf-favicon-shodan');
        if (favicon) {
            favicon.src = '';
            favicon.style.display = 'none';
        }
        if (faviconPlaceholder) faviconPlaceholder.style.display = 'flex';
        if (faviconHash) faviconHash.textContent = '—';
        if (faviconMatch) faviconMatch.textContent = '—';
        if (faviconShodan) faviconShodan.style.display = 'none';

        _openDefaultView();
        _toast('Technology fingerprint results cleared', 'info');
    }

    /* ── Output helpers ─────────────────────────────────────── */
    function _outputEl() { return document.querySelector('#panel-tech-fingerprint .output-wrap') || $('tf-output'); }

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
        if (el) el.innerHTML = '<span class="output-placeholder">// Output will appear here when scan is running...</span>';
    }

    /* ── Stop polling ───────────────────────────────────────── */
    function _stopPolling() {
        if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    }

    function _onScanEnd() {
        _stopPolling();
        _scanning   = false;
        _currentJob = null;
        _setBtnState(false);
    }

    /* ── Render results from DB ─────────────────────────────── */
    async function _fetchAndRenderFromDB(domain) {
        const normDomain = String(domain || '').trim().toLowerCase();

        const scansResp = await fetch(`${DB_API_BASE}/api/scans`);
        if (!scansResp.ok) throw new Error(`/api/scans: ${scansResp.status}`);
        const scansData = await scansResp.json().catch(() => ({}));
        if (!scansData.success || !scansData.scans?.length) throw new Error('No scan found in database');

        const normaliseTarget = value => {
            const raw = String(value || '').trim().toLowerCase();
            try { return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname; }
            catch (_) { return raw.replace(/^https?:\/\//, '').split('/')[0]; }
        };
        const matchingScans = scansData.scans.filter(s => normaliseTarget(s.target) === normaliseTarget(normDomain));
        const candidates = [...matchingScans, ...scansData.scans.filter(s => !matchingScans.includes(s))];
        let latestScanId = null;
        let scanData = null;
        let modules = {};
        for (const scan of candidates) {
            const scanResp = await fetch(`${DB_API_BASE}/api/scan/${scan.id}`);
            if (!scanResp.ok) continue;
            const candidateData = await scanResp.json().catch(() => ({}));
            const candidateModules = candidateData.modules || candidateData.data?.modules || {};
            const hasTechTables = ['tech_technologies', 'tech_headers', 'tech_cms', 'tech_waf',
                'tech_favicon', 'tech_retire_js', 'tech_vulnerabilities']
                .some(name => Array.isArray(candidateModules?.[name]?.rows) && candidateModules[name].rows.length);
            if (hasTechTables || scan === candidates[candidates.length - 1]) {
                latestScanId = scan.id;
                scanData = candidateData;
                modules = candidateModules;
                if (hasTechTables) break;
            }
        }
        if (!latestScanId) throw new Error('No technology fingerprint scan found in database');
        const loadRows = async tableName => {
            const embedded = modules?.[tableName]?.rows;
            if (Array.isArray(embedded)) return embedded;
            const response = await fetch(`${DB_API_BASE}/api/list/${tableName}?scan_id=${encodeURIComponent(latestScanId)}&limit=500000`);
            if (!response.ok) return [];
            const payload = await response.json().catch(() => ({}));
            return Array.isArray(payload.rows) ? payload.rows : [];
        };

        const [
            techRows, wafRows, headerRows, cmsRows,
            faviconRows, retireRows, vulnRows
        ] = await Promise.all([
            loadRows('tech_technologies'),
            loadRows('tech_waf'),
            loadRows('tech_headers'),
            loadRows('tech_cms'),
            loadRows('tech_favicon'),
            loadRows('tech_retire_js'),
            loadRows('tech_vulnerabilities'),
        ]);

        const totalRows = techRows.length + wafRows.length + headerRows.length +
                          cmsRows.length + faviconRows.length + retireRows.length + vulnRows.length;

        if (!totalRows) {
            _appendLabeled('DATABASE', 'No fingerprint rows found in database', OUT_RED);
            return false;
        }

        const TECH_CAT_MAP = {
            'web frameworks':        'web-framework',
            'javascript frameworks': 'frontend-library',
            'javascript libraries':  'frontend-library',
            'ui frameworks':         'frontend-library',
            'css frameworks':        'frontend-library',
            'cms':                   'cms',
            'blogs':                 'cms',
            'ecommerce':             'cms',
            'programming languages': 'backend-lang',
            'operating systems':     'os',
            'web servers':           'web-server',
            'reverse proxies':       'web-server',
            'cdn':                   'cdn',
            'databases':             'backend-lang',
            'paas':                  'web-server',
            'hosting':               'web-server',
            'security':              'security-misc',
            'analytics':             'security-misc',
            'tag managers':          'security-misc',
            'miscellaneous':         'security-misc',
        };

        const results = {
            'web-framework':    [],
            'frontend-library': [],
            'cms':              [],
            'backend-lang':     [],
            'os':               [],
            'favicon':          [],
            'security-header':  [],
            'security-misc':    [],
            'web-server':       [],
            'cdn':              [],
            'waf':              [],
            'retire-js':        [],
            'vuln':             [],
        };

        function _resolveCategory(raw) {
            if (!raw) return '';
            let cat = raw;
            if (typeof cat === 'string') {
                const trimmed = cat.trim();
                if (trimmed.startsWith('[')) {
                    try {
                        const arr = JSON.parse(trimmed);
                        cat = Array.isArray(arr) ? arr[0] : trimmed;
                    } catch (_) { cat = trimmed; }
                }
            } else if (Array.isArray(cat)) {
                cat = cat[0] || '';
            }
            return String(cat).toLowerCase().trim();
        }

        techRows.forEach(row => {
            const rawCat = row.category || row.categories || '';
            const cat = TECH_CAT_MAP[_resolveCategory(rawCat)] || 'web-framework';
            results[cat].push({
                name:       row.name       || '',
                version:    row.version    || '?',
                confidence: row.confidence || 'medium',
                evidence:   row.detected_via || row.raw_value || '',
            });
        });

        headerRows.forEach(row => {
            results['security-header'].push({
                name:       row.name           || '',
                header:     row.detected_via   || '',
                value:      row.raw_value      || '',
            });
        });

        cmsRows.forEach(row => {
            if (row.cms_detected && String(row.cms_detected) !== '0' && String(row.cms_detected) !== 'false') {
                results['cms'].push({
                    name:       row.cms_name       || '',
                    version:    row.cms_version    || '?',
                    confidence: 'high',
                    evidence:   row.detection_method || '',
                });
            }
        });

        faviconRows.forEach(row => {
            if (row.technology_name) {
                results['favicon'].push({
                    technology:  row.technology_name,
                    hash:        row.mmh3 || '',
                    confidence:  row.technology_category || 'high',
                });
            }
            if (row.favicon_found) {
                const hashEl  = $('tf-favicon-hash-display');
                const matchEl = $('tf-favicon-match');
                const imgEl   = $('tf-favicon-img');
                const phEl    = $('tf-favicon-placeholder');
                const shEl    = $('tf-favicon-shodan');
                if (hashEl) hashEl.textContent = row.mmh3 || '—';
                if (matchEl) matchEl.textContent = row.technology_name || 'Unknown';
                if (row.favicon_url) {
                    if (imgEl) { imgEl.src = row.favicon_url; imgEl.style.display = ''; }
                    if (phEl)  phEl.style.display = 'none';
                }
                if (shEl && row.shodan_query) {
                    shEl.href = `https://www.shodan.io/search?query=${encodeURIComponent(row.shodan_query)}`;
                    shEl.style.display = '';
                }
                const hashSmall = $('tf-favicon-hash');
                if (hashSmall) hashSmall.textContent = row.mmh3 || '—';
            }
        });

        wafRows.forEach(row => {
            if (row.waf_detected && String(row.waf_detected) !== '0') {
                const names = Array.isArray(row.waf_names) ? row.waf_names : [];
                names.forEach(n => {
                    results['waf'].push({
                        name:       n,
                        type:       'WAF',
                        confidence: 'high',
                        evidence:   'WAF fingerprint match',
                    });
                });
                if (!names.length) {
                    results['waf'].push({
                        name:       'Unknown WAF',
                        type:       'WAF',
                        confidence: 'medium',
                        evidence:   row.generic_reason || 'Generic WAF response',
                    });
                }
            }
        });

        retireRows.forEach(row => {
            results['retire-js'].push({
                library:    row.library  || '',
                version:    row.version  || '?',
                vulnerable: row.has_vulnerabilities ? 'YES' : 'no',
                url:        row.script_url || '',
            });
        });

        vulnRows.forEach(row => {
            results['vuln'].push({
                library:  row.library  || '',
                version:  row.version  || '?',
                severity: row.severity || '?',
                summary:  row.summary  || '',
                cve:      Array.isArray(row.cve) ? row.cve.join(', ') : (row.cve || ''),
            });
        });

        _renderTable('web-framework',    results['web-framework']);
        _renderTable('frontend-library', results['frontend-library']);
        _renderTable('cms',              results['cms']);
        _renderTable('backend-lang',     results['backend-lang']);
        _renderTable('os',               results['os']);
        _renderTable('security-header',  results['security-header']);
        _renderTable('security-misc',    results['security-misc']);
        _renderTable('web-server',       results['web-server']);
        _renderTable('cdn',              results['cdn']);
        _renderTable('waf',              results['waf']);
        _renderTable('retire-js',        results['retire-js']);
        _renderTable('vuln',             results['vuln']);

        const wafBadge = $('tf-badge-waf');
        if (wafBadge) wafBadge.textContent = results['waf'].length;
        const wafBadge2 = $('tf-badge-waf-detected');
        if (wafBadge2) wafBadge2.textContent = results['waf'].length;

        const retireBadge = $('tf-badge-retire-js');
        if (retireBadge) retireBadge.textContent = results['retire-js'].length;

        const vulnBadge = $('tf-badge-vuln');
        if (vulnBadge) vulnBadge.textContent = results['vuln'].length;

        const allCounted = [
            ...results['web-framework'], ...results['frontend-library'],
            ...results['cms'], ...results['backend-lang'], ...results['os'],
            ...results['security-header'], ...results['security-misc'],
            ...results['web-server'], ...results['cdn'], ...results['waf'],
        ];
        const hiCount = allCounted.filter(r => (r.confidence || '').toLowerCase() === 'high').length;
        const pct = allCounted.length ? Math.round((hiCount / allCounted.length) * 100) : 0;

        const tfTotal = $('tf-total-techs');
        const tfConf  = $('tf-confidence');
        const tfOS    = $('tf-server-os');
        const tfLang  = $('tf-backend-lang');
        const tfCms   = $('tf-cms');

        if (tfTotal) tfTotal.textContent = totalRows;
        if (tfConf)  tfConf.textContent  = allCounted.length ? `${pct}%` : '0%';
        if (tfOS)    tfOS.textContent    = results['os'][0]?.name || '—';
        if (tfLang)  tfLang.textContent  = results['backend-lang'].map(l => l.name).join(', ') || '—';
        if (tfCms)   tfCms.textContent   = results['cms'].map(c => c.name).join(', ') || '—';

        const summary = $('tf-summary'); if (summary) summary.style.display = 'grid';
        const toolbar = $('tf-toolbar'); if (toolbar) toolbar.style.display = 'flex';

        _appendLabeled('DATABASE', `${totalRows} results loaded and rendered`, OUT_GREEN);
        return true;
    }

    /* ── Status polling ─────────────────────────────────────── */
    async function _poll(jobId) {
        if (Date.now() - _pollStart > POLL_TIMEOUT) {
            _appendScanResult(false, 'Poll timeout: scan took too long.');
            _onScanEnd();
            return;
        }

        try {
            const resp = await fetch(`${API_BASE}/api/tech/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

            const status = data.status;

            // Stream stdout lines
            const el = _outputEl();
            if (data.stdout && el) {
                const pre = _outputPre();
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

            if (status === 'done') {

                if (!data.db_ready) {
                    _appendScanResult(false, 'Database is not ready. database-manager.py may have failed.');
                    _toast('Scan failed: database not ready', 'error');
                    _onScanEnd();
                    return;
                }

                _appendScanResult(true, data.output_file || 'Completed');
                try {
                    const rendered = await _fetchAndRenderFromDB(data.domain);
                    if (rendered === false) {
                        _onScanEnd();
                        return;
                    }
                } catch (dbErr) {
                    window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
                    _onScanEnd();
                    return;
                }
                window.markPanelComplete?.('panel-tech-fingerprint', 'Technology Fingerprint');
                _toast(`Tech fingerprint completed: ${data.domain}`, 'ok');
                _onScanEnd();
                return;
            }

            if (status === 'error') {
                _appendScanResult(false, data.stderr || 'unknown error');
                _toast('Scan ended with an error', 'error');
                _onScanEnd();
                return;
            }

            // Still running
            _pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);

        } catch (err) {
            _appendScanResult(false, `Poll error: ${err.message}`);
            _onScanEnd();
        }
    }

    /* ── Main scan function ─────────────────────────────────── */
    async function scan(targetUrl) {
        if (_scanning) return;

        // Input: tf-target inputundan al
        const inputEl = $('tf-target');
        const raw     = (targetUrl || (inputEl ? inputEl.value : '') || '').trim();
        if (!raw) { _toast('Please enter a target URL', 'warn'); return; }

        const domain = raw.replace(/^https?:\/\//, '').split('/')[0];

        _scanning = true;
        _setBtnState(true);
        _clearOutput();

        const summary = $('tf-summary'); if (summary) summary.style.display = 'none';
        const toolbar = $('tf-toolbar'); if (toolbar) toolbar.style.display = 'none';

        _appendLabeled('TARGET', domain, OUT_GREEN);
        const previewCmd = `python3 tech_fingerprint.py -d ${domain} --all`;

        try {
            // ── 1. Register target
            const targetPayload = { url: raw.startsWith('http') ? raw : `https://${raw}` };
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(targetPayload),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);

            // ── 2. Start tech scan
            const proxyEl = $('tf-proxy');
            const scanPayload = {};
            if (proxyEl && proxyEl.value.trim()) scanPayload.proxy = proxyEl.value.trim();

            const sResp = await fetch(`${API_BASE}/api/tech/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(scanPayload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `tech/scan: ${sResp.status}`);

            _currentJob = sData.job_id;
            _appendLabeled('COMMAND', sData.cmd || previewCmd, OUT_GREEN);
            _appendLabeled('JOB ID', _currentJob, OUT_GREEN);

            // ── 3. Start polling
            _pollStart = Date.now();
            _poll(_currentJob);

        } catch (err) {
            _appendScanResult(false, err.message);
            _appendLine('Is the API backend running?  →  python3 connection.py', 'var(--text-dim)');
            _toast(`Error: ${err.message}`, 'error');
            _onScanEnd();
        }
    }

    /* ── Sub-tab switching — headers.js ilə eyni pattern ──── */
    function switchSubTab(tabId, btn) {
        document.querySelectorAll('.tf-module .tls-sub-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('#tf-subtab-bar .tls-subtab-btn').forEach(b => b.classList.remove('active'));
        const target = document.getElementById(tabId);
        if (target) target.classList.add('active');
        if (btn) btn.classList.add('active');
    }

    function _openDefaultView() {
        const firstBtn = document.querySelector('#tf-subtab-bar .tls-subtab-btn[data-tftab]');
        const tabId = firstBtn && firstBtn.getAttribute('data-tftab');
        if (firstBtn && tabId) switchSubTab(tabId, firstBtn);

        const paramsHead = $('tf-target-params-head');
        paramsHead?.closest('.dns-section')?.classList.remove('collapsed');
        const paramsChevron = paramsHead?.querySelector('.dns-section-chevron');
        if (paramsChevron) paramsChevron.style.transform = '';

        document.querySelectorAll('.tf-module .tf-category').forEach(catEl => {
            const body = catEl.querySelector('.tf-category-body');
            const chev = catEl.querySelector('.dns-section-chevron');
            if (body) body.style.display = '';
            if (chev) chev.style.transform = '';
        });
    }

    /* ── Init ──────────────────────────────────────────────── */
    function init() {
        if (document.getElementById('tf-load-db-btn')?.dataset.bound === 'true') return;
        const loadDbBtn = $('tf-load-db-btn');
        if (loadDbBtn) loadDbBtn.dataset.bound = 'true';

        const scanBtn = $('tf-scan-btn');
        if (scanBtn) scanBtn.addEventListener('click', () => scan());
        const stopBtn = $('tf-stop-btn');
        if (stopBtn) stopBtn.addEventListener('click', stopScan);
        const resetBtn = $('tf-reset-btn');
        if (resetBtn) resetBtn.addEventListener('click', resetScan);

        if (loadDbBtn) loadDbBtn.addEventListener('click', async () => {
            loadDbBtn.disabled = true;
            try {
                const target = $('tf-target')?.value.trim() || '';
                const loaded = await _fetchAndRenderFromDB(target);
                if (loaded !== false) {
                    window.markPanelComplete?.('panel-tech-fingerprint', 'Technology Fingerprint');
                    _toast('Technology fingerprint results loaded from database', 'ok');
                }
            } catch (err) {
                window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
                console.error('[TechFingerprint.loadFromDatabase]', err);
            } finally {
                loadDbBtn.disabled = false;
            }
        });

        _openDefaultView();

        document.querySelectorAll('#tf-subtab-bar .tls-subtab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tabId = btn.getAttribute('data-tftab');
                if (tabId) switchSubTab(tabId, btn);
            });
        });

        _openDefaultView();

        // Filter input
        const filterInput = $('tf-filter');
        const catFilter   = $('tf-category-filter');
        if (filterInput && catFilter) {
            function applyFilter() {
                const search = filterInput.value.toLowerCase();
                const cat    = catFilter.value;
                document.querySelectorAll('.tf-category').forEach(el => {
                    const catMatch = cat === 'all' || el.dataset.category === cat;
                    const textMatch = !search || el.textContent.toLowerCase().includes(search);
                    el.style.display = (catMatch && textMatch) ? '' : 'none';
                });
            }
            filterInput.addEventListener('input', applyFilter);
            catFilter.addEventListener('change', applyFilter);
        }
    }

    /* ── Public: accordion toggle — HTML onclick-dən çağırılır ── */
    function toggleCategory(headEl) {
        const cat  = headEl.closest('.tf-category');
        const body = cat ? cat.querySelector('.tf-category-body') : null;
        if (!body) return;
        const isVisible = getComputedStyle(body).display !== 'none';
        body.style.display = isVisible ? 'none' : '';
        const chevron = headEl.querySelector('.dns-section-chevron');
        if (chevron) chevron.style.transform = isVisible ? 'rotate(-90deg)' : '';
    }

    return { init, scan, stopScan, resetScan, toggleCategory, loadFromDatabase: _fetchAndRenderFromDB };
})();

// DOM hazır olana qədər gözlə — panel dinamik inject olunduqdan sonra init çağır
(function _waitForPanel() {
    if (document.getElementById('tf-scan-btn')) {
        TechFingerprint.init();
    } else {
        setTimeout(_waitForPanel, 50);
    }
})();