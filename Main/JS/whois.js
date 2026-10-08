const WHOIS_RENDER_CSS = `
.wh-kv-list { padding: 4px 0 6px; }
.wh-kv {
    display: grid;
    grid-template-columns: 170px minmax(0, 1fr);
    gap: 14px;
    align-items: start;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
}
.wh-kv:last-child { border-bottom: none; }
.wh-k {
    font-family: var(--head);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.6px;
    color: var(--text-dim);
    text-transform: uppercase;
    padding-top: 4px;
}
.wh-v {
    font-family: var(--mono);
    font-size: 11.5px;
    color: var(--text-hi);
    line-height: 1.6;
    min-width: 0;
    word-break: break-word;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
}
.wh-na { color: var(--text-dim); opacity: 0.7; }
.wh-sub { color: var(--text-dim); font-size: 10.5px; }

.wh-chips { display: flex; flex-wrap: wrap; gap: 6px; min-width: 0; }
.wh-chip {
    display: inline-flex;
    align-items: center;
    font-family: var(--mono);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.2px;
    line-height: 1.5;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--bg-deep);
    color: var(--text-sec);
    max-width: 100%;
    word-break: break-all;
}
.wh-chip.mute { color: var(--text-dim); }
.wh-chip.info { color: var(--accent); border-color: var(--accent-dim); background: var(--accent-glow); }
.wh-chip.ok   { color: #3ddc84; border-color: rgba(61, 220, 132, 0.32); background: rgba(61, 220, 132, 0.08); }
.wh-chip.warn { color: #d09030; border-color: #7a4a10; background: rgba(160, 120, 32, 0.12); }
.wh-chip.bad  { color: #ff6b5e; border-color: rgba(255, 77, 77, 0.38); background: rgba(255, 77, 77, 0.09); }

.dns-section-badge.wh-good { color: #3ddc84; border-color: rgba(61, 220, 132, 0.35); background: rgba(61, 220, 132, 0.08); }
.dns-section-badge.wh-bad  { color: #ff6b5e; border-color: rgba(255, 77, 77, 0.4); background: rgba(255, 77, 77, 0.09); }
.anomaly-stat-val.wh-good  { color: #3ddc84; }
.anomaly-stat-val.wh-bad   { color: #ff6b5e; }

#whois-dates-summary .anomaly-stat-val { font-size: clamp(15px, 2.1vw, 22px); }
#whois-cross-org { font-size: 13px; line-height: 1.35; word-break: break-word; }
#whois-hist-first-seen { font-size: clamp(15px, 2.1vw, 22px); }

.wh-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 28px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-card);
}
.wh-meta-item { display: flex; align-items: center; gap: 9px; min-width: 0; }
.wh-meta-k {
    font-family: var(--head);
    font-size: 9.5px;
    font-weight: 700;
    letter-spacing: 0.9px;
    color: var(--accent-dim);
    text-transform: uppercase;
    flex-shrink: 0;
}
.wh-meta-v {
    font-family: var(--mono);
    font-size: 11.5px;
    color: var(--text-sec);
    min-width: 0;
    word-break: break-all;
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
}

.wh-banner { min-width: 0; display: flex; flex-direction: column; gap: 8px; }
.wh-banner-title {
    font-family: var(--head);
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    color: var(--text-sec);
}
.wh-banner-text { font-size: 11.5px; line-height: 1.6; }

.wh-contact {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    min-width: 0;
}
.wh-contact-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 9px 12px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
}
.wh-contact-role {
    font-family: var(--head);
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--accent);
}
.wh-contact-body { padding: 4px 0; }
.wh-contact-row {
    display: grid;
    grid-template-columns: 74px minmax(0, 1fr);
    gap: 10px;
    padding: 6px 12px;
    font-size: 11.5px;
}
.wh-contact-label {
    font-family: var(--head);
    font-size: 9.5px;
    font-weight: 600;
    letter-spacing: 0.7px;
    text-transform: uppercase;
    color: var(--text-dim);
    padding-top: 3px;
}
.wh-contact-val {
    font-family: var(--mono);
    color: var(--text-sec);
    line-height: 1.55;
    word-break: break-word;
    min-width: 0;
}
.wh-contact-val.redacted { color: var(--text-dim); font-style: italic; opacity: 0.75; }

.wh-ip { border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.wh-ip:last-child { border-bottom: none; }
.wh-ip-head {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px 10px;
    padding: 14px 16px 8px;
}
.wh-ip-addr {
    font-family: var(--mono);
    font-size: 16px;
    font-weight: 700;
    color: var(--text-hi);
    word-break: break-all;
}

.wh-row {
    display: flex;
    align-items: flex-start;
    padding: 9px 16px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 11.5px;
    transition: background 0.12s;
}
.wh-row:hover { background: var(--bg-hover); }
.wh-row:last-child { border-bottom: none; }
.wh-cell {
    padding: 0 9px;
    line-height: 1.6;
    min-width: 0;
    color: var(--text-sec);
    word-break: break-word;
}
.wh-cell.key    { color: var(--text-hi); font-weight: 600; }
.wh-cell.dim    { color: var(--text-dim); }
.wh-cell.accent { color: var(--accent); font-weight: 600; }
.wh-cell.bad    { color: #ff6b5e; font-weight: 600; }
.wh-cell.brk    { word-break: break-all; }
.wh-evidence > div { padding: 1px 0; }

.wh-json { color: var(--text-sec); }
.wh-j-key { color: var(--accent); }
.wh-j-str { color: #9fd3a8; }
.wh-j-num { color: #6fc0f0; }
.wh-j-lit { color: #d09030; }

@media (max-width: 768px) {
    .wh-kv { grid-template-columns: 1fr; gap: 4px; }
}
`;

const WhoisFmt = (() => {

    const IANA_REGISTRARS = {
        '2':    'Network Solutions, LLC',
        '69':   'Tucows Domains Inc.',
        '81':   'Gandi SAS',
        '146':  'GoDaddy.com, LLC',
        '292':  'MarkMonitor Inc.',
        '1068': 'NameCheap, Inc.',
        '1910': 'CloudFlare, Inc.',
    };

    const REDACTED_RE = /redacted|withheld|not disclosed|data protected|statutory masking|masked for privacy/i;
    const NA = '<span class="wh-na">--</span>';

    function esc(v) {
        return String(v === null || v === undefined ? '' : v)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function isEmpty(v) {
        if (v === null || v === undefined) return true;
        if (Array.isArray(v)) return v.length === 0;
        const s = String(v).trim().toLowerCase();
        return s === '' || s === '--' || s === 'null' || s === 'none' || s === 'undefined';
    }

    function text(v) {
        return isEmpty(v) ? NA : esc(v);
    }

    function date(v) {
        return isEmpty(v) ? '--' : String(v).trim().split(/[ T]/)[0];
    }

    function list(v) {
        if (Array.isArray(v)) return v.map(x => String(x).trim()).filter(Boolean);
        if (isEmpty(v)) return [];
        return String(v).split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
    }

    function chip(label, tone, title) {
        return `<span class="wh-chip${tone ? ' ' + tone : ''}"${title ? ` title="${esc(title)}"` : ''}>${esc(label)}</span>`;
    }

    function chips(items, toneFn) {
        if (!items.length) return NA;
        return `<div class="wh-chips">${items.map(i => chip(i, toneFn ? toneFn(i) : '')).join('')}</div>`;
    }

    function el(id) {
        return document.getElementById(id);
    }

    function setHtml(id, html) {
        const node = el(id);
        if (node) node.innerHTML = html;
    }

    function setText(id, value) {
        const node = el(id);
        if (node) node.textContent = value;
    }

    function badge(id, label, tone) {
        const node = el(id);
        if (!node) return;
        node.textContent = label;
        node.className = 'dns-section-badge' + (tone ? ' ' + tone : '');
    }

    function humanizeStatus(raw) {
        let s = String(raw).replace(/\s*\(?https?:\/\/\S+\)?/gi, '').trim();
        s = s.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
        if (!s) return '';
        if (s.toLowerCase() === 'ok') return 'OK';
        return s.toLowerCase().replace(/\b[a-z]/g, c => c.toUpperCase());
    }

    function statuses(raw) {
        const seen = new Set();
        list(raw).forEach(item => {
            const label = humanizeStatus(item);
            if (label) seen.add(label);
        });
        return Array.from(seen);
    }

    function statusTone(label) {
        if (/delete|redemption|hold|revoked|expired/i.test(label)) return 'bad';
        if (/pending/i.test(label)) return 'warn';
        if (/^ok$|^active$/i.test(label)) return 'ok';
        if (/prohibited|lock/i.test(label)) return 'info';
        return 'mute';
    }

    function dnssecTone(value) {
        const s = String(value).toLowerCase();
        if (s.startsWith('unsigned') || s === 'no' || s === 'false') return 'warn';
        if (s.startsWith('signed') || s === 'yes' || s === 'true') return 'ok';
        return 'mute';
    }

    function daysClass(days) {
        const n = Number(days);
        if (days === null || days === undefined || days === '' || isNaN(n)) return '';
        if (n < 30) return ' danger';
        if (n < 90) return ' warn';
        return '';
    }

    function registrar(name, ianaId) {
        let id = isEmpty(ianaId) ? '' : String(ianaId).trim();
        let label = isEmpty(name) ? '' : String(name).trim();
        if (/^\d+$/.test(label)) {
            if (!id) id = label;
            label = '';
        }
        if (!label && id && IANA_REGISTRARS[id]) label = IANA_REGISTRARS[id];
        return { name: label, id };
    }

    function contactValue(raw) {
        if (isEmpty(raw)) return { html: NA, state: 'empty', title: '' };
        const full = String(raw).trim();
        const kept = [];
        full.split(/\s*,\s*/).filter(Boolean).forEach(part => {
            if (!REDACTED_RE.test(part) && !kept.includes(part)) kept.push(part);
        });
        if (!kept.length) return { html: 'Redacted for privacy', state: 'redacted', title: full };
        return { html: esc(kept.join(', ')), state: 'public', title: full };
    }

    function roleLabel(role) {
        const s = String(role).replace(/[_-]+/g, ' ').trim();
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    function row(label, valueHtml) {
        return `<div class="wh-kv"><span class="wh-k">${esc(label)}</span><div class="wh-v">${valueHtml}</div></div>`;
    }

    function cell(content, style, cls) {
        return `<div class="wh-cell${cls ? ' ' + cls : ''}" style="${style}">${content}</div>`;
    }

    function tableRow(cells) {
        return `<div class="wh-row">${cells.join('')}</div>`;
    }

    function empty(message) {
        return `<div class="data-empty"><span>${esc(message)}</span></div>`;
    }

    function highlightJson(value) {
        const json = JSON.stringify(value, null, 2);
        const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
        let out = '';
        let last = 0;
        let m;
        while ((m = re.exec(json)) !== null) {
            out += esc(json.slice(last, m.index));
            if (m[1] !== undefined) {
                out += `<span class="${m[2] ? 'wh-j-key' : 'wh-j-str'}">${esc(m[1])}</span>${esc(m[2] || '')}`;
            } else if (m[3] !== undefined) {
                out += `<span class="wh-j-lit">${m[3]}</span>`;
            } else {
                out += `<span class="wh-j-num">${m[0]}</span>`;
            }
            last = re.lastIndex;
        }
        return out + esc(json.slice(last));
    }

    return {
        esc, isEmpty, text, date, list, chip, chips, el, setHtml, setText, badge,
        statuses, statusTone, dnssecTone, daysClass, registrar, contactValue,
        roleLabel, row, cell, tableRow, empty, highlightJson, NA,
    };
})();

const WhoisIP = {
    init() {
        const navItem = document.querySelector('[data-status="panel-whois-ip"]');
        if (navItem) {
            navItem.removeAttribute('data-status');
            navItem.setAttribute('data-panel', 'panel-whois-ip');
        }
        WhoisIP.injectStyles();
    },

    injectStyles() {
        if (document.getElementById('_whois_render_style')) return;
        const style = document.createElement('style');
        style.id = '_whois_render_style';
        style.textContent = WHOIS_RENDER_CSS;
        document.head.appendChild(style);
    },

    renderData(data) {
        if (!data) return;
        WhoisIP.renderDomain(data);
        WhoisIP.renderPrivacy(data);
        WhoisIP.renderContacts(data);
        WhoisIP.renderRaw(data);
        WhoisIP.renderIps(data);
        WhoisIP.renderGeo(data);
        WhoisIP.renderCdn(data);
        WhoisIP.renderHttp(data);
        WhoisIP.renderBlacklist(data);
        WhoisIP.renderHistory(data);
        WhoisIP.renderCross(data);
    },

    renderDomain(data) {
        const F = WhoisFmt;
        const w = data.whois;
        if (!w) return;

        F.badge('whois-domain-badge', 'LOADED', 'ok');
        F.setText('whois-created', F.date(w.created));
        F.setText('whois-updated', F.date(w.updated));
        F.setText('whois-expires', F.date(w.expires));

        const days = w.days_until_expiry;
        const daysEl = F.el('whois-days-expiry');
        if (daysEl) {
            daysEl.textContent = days !== null && days !== undefined && days !== '' ? days : '--';
            daysEl.className = 'anomaly-stat-val' + F.daysClass(days);
        }

        const domainName = data.domain || '';
        const tld = data.tld ? F.chip('.' + String(data.tld).replace(/^\./, ''), 'mute') : '';
        F.setHtml('whois-domain-name', domainName ? `<span>${F.esc(domainName)}</span>${tld}` : F.NA);

        const states = F.statuses(w.status);
        F.setHtml('whois-status', F.chips(states, F.statusTone));

        const reg = F.registrar(w.registrar, w.registrar_iana_id);
        if (reg.name) {
            F.setHtml('whois-registrar', `<span>${F.esc(reg.name)}</span>`);
        } else if (reg.id) {
            F.setHtml('whois-registrar', F.chip('Name not provided by registry', 'mute'));
        } else {
            F.setHtml('whois-registrar', F.NA);
        }
        F.setHtml('whois-iana', reg.id ? `<span>${F.esc(reg.id)}</span>` : F.NA);

        const ns = F.list(w.name_servers).map(n => n.toLowerCase().replace(/\.$/, ''));
        F.setHtml('whois-ns', F.chips(ns, () => 'mute'));

        F.setHtml('whois-dnssec', F.isEmpty(w.dnssec) ? F.NA : F.chip(String(w.dnssec), F.dnssecTone(w.dnssec)));
        F.setHtml('whois-sources', F.chips(F.list(w.sources), () => 'mute'));
    },

    renderPrivacy(data) {
        const F = WhoisFmt;
        const pr = (data.whois && data.whois.privacy) || data.privacy;
        if (!pr) return;

        const banner = F.el('privacy-banner');
        const icon = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M8 2l6 12H2L8 2z" stroke="currentColor" stroke-width="1.3"/><path d="M8 7v3M8 11.5v.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>';

        if (pr.enabled) {
            F.badge('whois-privacy-badge', 'ACTIVE', 'warn');
            const indicators = F.list(pr.indicators).map(i => i.toLowerCase());
            const note = F.isEmpty(pr.note) ? 'Registrant details are masked by a privacy or proxy service.' : pr.note;
            if (banner) {
                banner.classList.add('warn');
                banner.innerHTML = `${icon}<div class="wh-banner"><div class="wh-banner-title">Privacy protection detected</div><div class="wh-banner-text">${F.esc(note)}</div>${indicators.length ? F.chips(indicators, () => 'warn') : ''}</div>`;
            }
        } else {
            F.badge('whois-privacy-badge', 'NONE', 'wh-good');
            if (banner) {
                banner.classList.remove('warn');
                banner.innerHTML = `${icon}<div class="wh-banner"><div class="wh-banner-title">No privacy protection detected</div><div class="wh-banner-text">Registrant data may be publicly visible.</div></div>`;
            }
        }

        const emails = F.list(pr.visible_emails);
        const wrap = F.el('whois-privacy-emails-wrap');
        if (wrap && emails.length) {
            wrap.style.display = 'block';
            F.setHtml('whois-privacy-emails', F.chips(emails, () => 'info'));
        }
    },

    renderContacts(data) {
        const F = WhoisFmt;
        const w = data.whois;
        if (!w || !w.contacts) return;

        const grid = document.querySelector('.whois-contacts-grid');
        if (!grid) return;

        const preferred = ['registrant', 'admin', 'tech', 'billing'];
        const extra = Object.keys(w.contacts).filter(r => !preferred.includes(r));
        const fields = [
            ['Name',    'name'],
            ['Org',     'organization'],
            ['Address', 'address'],
            ['Country', 'country'],
            ['Phone',   'phone'],
            ['Email',   'email'],
        ];

        const cards = [];
        preferred.concat(extra).forEach(role => {
            const contact = w.contacts[role];
            if (!contact || typeof contact !== 'object' || Object.keys(contact).length === 0) return;

            const values = fields.map(([label, key]) => ({ label, v: F.contactValue(contact[key]) }));
            const filled   = values.filter(x => x.v.state !== 'empty');
            const redacted = filled.filter(x => x.v.state === 'redacted').length;

            let status = '';
            if (filled.length && redacted === filled.length) status = F.chip('REDACTED', 'warn');
            else if (redacted > 0) status = F.chip('PARTIAL', 'mute');
            else if (filled.length) status = F.chip('PUBLIC', 'ok');

            const rows = values.map(x => {
                const cls = x.v.state === 'redacted' ? ' redacted' : '';
                const title = x.v.title ? ` title="${F.esc(x.v.title)}"` : '';
                return `<div class="wh-contact-row"><span class="wh-contact-label">${x.label}</span><span class="wh-contact-val${cls}"${title}>${x.v.html}</span></div>`;
            }).join('');

            cards.push(`<div class="wh-contact"><div class="wh-contact-head"><span class="wh-contact-role">${F.esc(F.roleLabel(role))}</span>${status}</div><div class="wh-contact-body">${rows}</div></div>`);
        });

        grid.innerHTML = cards.length
            ? cards.join('')
            : '<div class="data-empty" style="grid-column:1/-1;"><span>No contact data available</span></div>';
    },

    renderRaw(data) {
        const F = WhoisFmt;
        const pre = F.el('whois-complete-json');
        if (pre) {
            pre.innerHTML = F.highlightJson(data);
            pre.classList.remove('output-placeholder');
            pre.classList.add('wh-json');
        }
        F.badge('whois-complete-badge', 'LOADED', 'ok');
    },

    renderIps(data) {
        const F = WhoisFmt;
        if (!data.ips || !data.ips.length) return;

        F.badge('ip-intel-badge', `${data.ips.length} IP${data.ips.length > 1 ? 's' : ''}`, 'ok');

        const yesNo = (flag, label) => F.chip(`${label}: ${flag ? 'YES' : 'NO'}`, flag ? 'warn' : 'mute');

        const blocks = data.ips.map(ip => {
            const asnRaw = F.isEmpty(ip.asn) ? '' : String(ip.asn);
            const asn = asnRaw ? (/^as/i.test(asnRaw) ? asnRaw.toUpperCase() : 'AS' + asnRaw) : '';

            const head = [
                `<span class="wh-ip-addr">${F.text(ip.ip)}</span>`,
                asn ? F.chip(asn, 'info') : '',
                F.isEmpty(ip.country_code) ? '' : F.chip(ip.country_code, 'mute'),
                F.isEmpty(ip.usage_type) ? '' : F.chip(ip.usage_type, 'mute'),
            ].join('');

            const sources = Array.isArray(ip.source) ? ip.source : F.list(ip.source);
            const location = [ip.city, ip.region, ip.country].filter(v => !F.isEmpty(v)).join(', ');

            const items = [
                ['Organization',      F.isEmpty(ip.org || ip.as_name) ? '' : F.esc(ip.org || ip.as_name)],
                ['ISP',               F.isEmpty(ip.isp) ? '' : F.esc(ip.isp)],
                ['AS Name',           F.isEmpty(ip.as_name) ? '' : F.esc(ip.as_name)],
                ['Location',          location ? F.esc(location) : ''],
                ['Timezone',          F.isEmpty(ip.timezone) ? '' : F.esc(ip.timezone)],
                ['PTR / Reverse DNS', F.isEmpty(ip.ptr) ? '' : F.esc(ip.ptr)],
                ['CIDR',              F.isEmpty(ip.cidr) ? '' : F.esc(ip.cidr)],
                ['RDAP Range',        F.isEmpty(ip.rdap_range) ? '' : F.esc(ip.rdap_range)],
                ['RDAP Country',      F.isEmpty(ip.rdap_country) ? '' : F.esc(ip.rdap_country)],
                ['Sources',           sources.length ? F.chips(sources, () => 'mute') : ''],
            ].filter(([, html]) => html);

            items.push(['Flags', `<div class="wh-chips">${yesNo(ip.proxy_or_vpn, 'VPN/PROXY')}${yesNo(ip.hosting, 'HOSTING')}${yesNo(ip.mobile, 'MOBILE')}</div>`]);

            return `<div class="wh-ip"><div class="wh-ip-head">${head}</div>${items.map(([label, html]) => F.row(label, html)).join('')}</div>`;
        });

        F.setHtml('whois-ip-list', blocks.join(''));
    },

    renderGeo(data) {
        const geoIp = (data.ips || []).find(ip => (ip.lat != null && ip.lon != null) || (ip.latitude != null && ip.longitude != null));
        const geoEmpty   = document.getElementById('whois-geo-empty');
        const geoFrame   = document.getElementById('whois-geo-map-frame');
        const geoLinkRow = document.getElementById('whois-geo-link-row');
        const geoLink    = document.getElementById('whois-geo-link');
        const geoBadge   = document.getElementById('whois-geo-badge');
        const geoCoords  = document.getElementById('whois-geo-coords');
        const geoPlace   = document.getElementById('whois-geo-place');

        const latRaw = geoIp ? (geoIp.lat != null ? geoIp.lat : geoIp.latitude) : null;
        const lonRaw = geoIp ? (geoIp.lon != null ? geoIp.lon : geoIp.longitude) : null;
        const latN = parseFloat(latRaw);
        const lonN = parseFloat(lonRaw);

        if (geoIp && !isNaN(latN) && !isNaN(lonN)) {
            const delta = 0.35;
            const bbox = `${(lonN - delta).toFixed(4)},${(latN - delta).toFixed(4)},${(lonN + delta).toFixed(4)},${(latN + delta).toFixed(4)}`;
            const embedUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${latN.toFixed(5)},${lonN.toFixed(5)}`;
            const externalUrl = `https://www.openstreetmap.org/?mlat=${latN.toFixed(5)}&mlon=${lonN.toFixed(5)}#map=10/${latN.toFixed(5)}/${lonN.toFixed(5)}`;

            if (geoFrame)   { geoFrame.src = embedUrl; geoFrame.style.display = 'block'; }
            if (geoEmpty)   geoEmpty.style.display = 'none';
            if (geoLinkRow) geoLinkRow.style.display = 'block';
            if (geoLink)    geoLink.href = externalUrl;
            WhoisFmt.badge('whois-geo-badge', 'LOADED', 'ok');
            if (geoCoords)  geoCoords.textContent = `${latN.toFixed(4)}, ${lonN.toFixed(4)}`;
            if (geoPlace)   geoPlace.textContent = [geoIp.city, geoIp.region, geoIp.country].filter(Boolean).join(', ') || '--';
        } else {
            if (geoFrame)   { geoFrame.style.display = 'none'; geoFrame.src = ''; }
            if (geoEmpty)   { geoEmpty.style.display = 'flex'; geoEmpty.innerHTML = '<span>No coordinates available for this IP</span>'; }
            if (geoLinkRow) geoLinkRow.style.display = 'none';
            WhoisFmt.badge('whois-geo-badge', 'N/A', 'dim');
        }
    },

    renderCdn(data) {
        const F = WhoisFmt;
        const info = data.cdn_advanced || data.cdn;
        if (!info) return;

        if (info.behind_cdn) F.badge('cdn-detect-badge', 'DETECTED', 'ok');
        else F.badge('cdn-detect-badge', 'CLEAN', 'wh-good');

        const metaRow = F.el('cdn-meta-row');
        if (metaRow) metaRow.style.display = 'flex';

        const waf = F.list(info.waf_detected);
        F.setHtml('cdn-waf', waf.length ? F.chips(waf, () => 'warn') : F.chip('None detected', 'mute'));
        F.setHtml('cdn-anycast', info.anycast === null || info.anycast === undefined
            ? F.NA
            : F.chip(info.anycast ? 'Yes' : 'No', info.anycast ? 'info' : 'mute'));

        const body = F.el('cdn-table-body');
        if (!body) return;

        if (info.vendors && info.vendors.length) {
            body.innerHTML = info.vendors.map(vendor => {
                const raw = info.evidence && info.evidence[vendor];
                const evidence = Array.isArray(raw) ? raw : (raw ? [raw] : []);
                const lines = evidence.length
                    ? `<div class="wh-evidence">${evidence.map(e => `<div>${F.esc(e)}</div>`).join('')}</div>`
                    : F.NA;
                return F.tableRow([
                    F.cell(F.chip(vendor, 'info'), 'flex:1;'),
                    F.cell(lines, 'flex:2;', 'dim'),
                ]);
            }).join('');
        } else {
            body.innerHTML = F.empty(info.note || 'No CDN detected');
        }
    },

    renderHttp(data) {
        const F = WhoisFmt;
        if (!data.http || !data.http.length) return;

        const h = data.http[0];
        const code = Number(h.status);
        let tone = '';
        let badgeTone = '';
        if (code >= 200 && code < 300) { tone = 'ok'; badgeTone = 'wh-good'; }
        else if (code >= 300 && code < 400) { tone = 'info'; badgeTone = 'ok'; }
        else if (code >= 400) { tone = 'bad'; badgeTone = 'wh-bad'; }

        F.badge('whois-http-badge', h.status ? String(h.status) : 'LOADED', badgeTone);
        F.setHtml('http-status', h.status ? F.chip(String(h.status), tone) : F.NA);
        F.setHtml('http-final-url', F.text(h.final_url || h.url));

        const body = F.el('http-headers-body');
        if (!body) return;

        const entries = h.headers && typeof h.headers === 'object' ? Object.entries(h.headers) : [];
        body.innerHTML = entries.length
            ? entries.map(([key, val]) => F.tableRow([
                F.cell(F.esc(key), 'flex:1.2;', 'key'),
                F.cell(F.esc(Array.isArray(val) ? val.join(', ') : val), 'flex:2;', 'brk'),
            ])).join('')
            : F.empty('No headers returned');
    },

    renderBlacklist(data) {
        const F = WhoisFmt;
        const bl = data.blacklist;
        if (!bl) return;

        const hits = Array.isArray(bl.hits) ? bl.hits : [];
        if (hits.length) F.badge('whois-bl-badge', `${hits.length} HIT${hits.length > 1 ? 'S' : ''}`, 'wh-bad');
        else F.badge('whois-bl-badge', 'CLEAN', 'wh-good');

        F.setText('whois-bl-score', bl.score !== null && bl.score !== undefined ? bl.score : '--');

        const risk = F.isEmpty(bl.risk) ? '--' : String(bl.risk).toUpperCase();
        const riskEl = F.el('whois-bl-risk');
        if (riskEl) {
            riskEl.textContent = risk;
            let cls = '';
            if (/HIGH|CRITICAL/.test(risk)) cls = ' wh-bad';
            else if (/MEDIUM|MODERATE/.test(risk)) cls = ' warn';
            else if (/LOW|NONE|CLEAN/.test(risk)) cls = ' wh-good';
            riskEl.className = 'anomaly-stat-val' + cls;
        }

        const listedEl = F.el('whois-bl-listed');
        if (listedEl) {
            listedEl.textContent = String(hits.length);
            listedEl.className = 'anomaly-stat-val' + (hits.length ? ' wh-bad' : ' wh-good');
        }
        F.setText('whois-bl-ips', Array.isArray(bl.ips_checked) ? bl.ips_checked.length : '--');

        const body = F.el('whois-bl-body');
        if (!body) return;

        body.innerHTML = hits.length
            ? hits.map(hit => F.tableRow([
                F.cell(F.text(hit.list), 'flex:1.5;', 'bad'),
                F.cell(F.text(hit.query), 'flex:1;', 'dim'),
                F.cell(F.text(hit.response), 'width:80px;', 'dim'),
                F.cell(F.isEmpty(hit.type) ? F.NA : F.chip(hit.type, 'warn'), 'width:80px;'),
            ])).join('')
            : F.empty('No blacklist hits found');
    },

    renderHistory(data) {
        const F = WhoisFmt;
        const hist = data.historical;
        if (!hist) return;

        const events = Array.isArray(hist.rdap_events) ? hist.rdap_events : [];
        const snaps = Array.isArray(hist.snapshots) ? hist.snapshots : [];

        if (snaps.length) F.badge('whois-history-badge', `${snaps.length} SNAP`, 'ok');
        else if (events.length) F.badge('whois-history-badge', `${events.length} EVT`, 'ok');
        else F.badge('whois-history-badge', '--', 'dim');

        F.setText('whois-hist-events', events.length || '--');
        F.setText('whois-hist-snapshots', snaps.length || '--');

        const reg = events.find(e => e.action === 'registration');
        F.setText('whois-hist-first-seen', reg ? F.date(reg.date) : '--');

        const rows = [];
        events.forEach(ev => rows.push({
            date: F.date(ev.date),
            action: F.isEmpty(ev.action) ? 'event' : String(ev.action),
            registrar: '',
            ns: '',
        }));
        snaps.forEach(snap => rows.push({
            date: F.date(snap.date),
            action: snap.status && snap.status.length ? F.statuses(snap.status)[0] || 'snapshot' : 'snapshot',
            registrar: F.isEmpty(snap.registrar) ? '' : String(snap.registrar),
            ns: F.list(snap.name_servers).join(', '),
        }));

        const body = F.el('whois-history-body');
        if (!body) return;

        const tone = action => {
            if (/regist|creat/i.test(action)) return 'ok';
            if (/expir|delet|transfer/i.test(action)) return 'warn';
            return 'mute';
        };

        body.innerHTML = rows.length
            ? rows.map(r => F.tableRow([
                F.cell(F.esc(r.date), 'width:110px;', 'dim'),
                F.cell(F.chip(r.action, tone(r.action)), 'flex:1;'),
                F.cell(r.registrar ? F.esc(r.registrar) : F.NA, 'flex:1.5;'),
                F.cell(r.ns ? F.esc(r.ns) : F.NA, 'flex:1;', 'dim'),
            ])).join('')
            : F.empty('No historical records available');
    },

    renderCross(data) {
        const F = WhoisFmt;
        const cs = data.cross_search;
        if (!cs) return;

        const related = Array.isArray(cs.related_domains) ? cs.related_domains : [];
        const count = cs.related_count || related.length;

        if (count > 0) F.badge('whois-cross-badge', `${count} FOUND`, 'ok');
        else F.badge('whois-cross-badge', 'NONE', 'dim');

        F.setText('whois-cross-domains', count || '0');
        F.setText('whois-cross-pivots', Array.isArray(cs.pivots_used) ? cs.pivots_used.length : '--');

        const who = cs.registrant_org || cs.registrant_email;
        const whoState = F.contactValue(who);
        F.setText('whois-cross-org', whoState.state === 'public' ? String(whoState.title) : (whoState.state === 'redacted' ? 'Redacted' : '--'));

        const body = F.el('whois-cross-body');
        if (!body) return;

        body.innerHTML = related.length
            ? related.map(rel => F.tableRow([
                F.cell(F.text(rel.domain), 'flex:2;', 'accent'),
                F.cell(F.text(rel.pivot), 'flex:1;', 'dim'),
                F.cell(F.text(rel.value), 'flex:1.5;', 'brk'),
                F.cell(F.text(rel.source), 'width:90px;', 'dim'),
            ])).join('')
            : F.empty('No related domains found');
    },
};

WhoisIP.init();

const WhoisScanController = (() => {

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

    const DEFAULT_WHOIS_TAB = 'whois-sub-domain';

    function _activateWhoisTab(tabId) {
        const target = document.getElementById(tabId);
        if (!target) return;
        document.querySelectorAll('.whois-sub-panel').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('#whois-subtab-bar .whois-subtab-btn').forEach(b =>
            b.classList.toggle('active', b.getAttribute('data-whoistab') === tabId));
        target.classList.add('active');
    }

    function showDefaultTab() {
        _activateWhoisTab(DEFAULT_WHOIS_TAB);
        const section = document.getElementById('sec-whois-domain');
        if (section) section.classList.remove('collapsed');
    }

    function _outputEl() { return $('whois-output-wrap'); }

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

    function _appendSummary(items, title) {
        const pre = _outputPre();
        if (!pre) return;
        const width = Math.max(...items.map(i => i[0].length));
        const head = document.createElement('span');
        head.style.color = OUT_GREEN;
        head.style.fontWeight = '600';
        head.textContent = '[ DATABASE ]';
        const headText = document.createElement('span');
        headText.style.color = OUT_VALUE;
        headText.textContent = ` ${title}\n`;
        pre.appendChild(head);
        pre.appendChild(headText);
        items.forEach((item, idx) => {
            const last = idx === items.length - 1;
            const branch = document.createElement('span');
            branch.style.color = 'var(--text-dim)';
            branch.textContent = `  ${last ? '└─' : '├─'} ${item[0].padEnd(width)}  `;
            const count = document.createElement('span');
            count.style.color = item[1] > 0 ? (item[2] === 'bad' ? OUT_RED : OUT_GREEN) : 'var(--text-dim)';
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

    function _resetUI() {
        _clearOutput();
        _resetTracker();
        const emptyData = '<div class="data-empty"><span>Run enumeration to retrieve data</span></div>';
        const els = ['whois-ip-list', 'cdn-table-body', 'http-headers-body', 'whois-bl-body', 'whois-cross-body', 'whois-history-body'];
        els.forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = emptyData; });
        const contactsGrid = document.querySelector('.whois-contacts-grid');
        if (contactsGrid) contactsGrid.innerHTML = '<div class="data-empty" style="grid-column:1/-1;"><span>Run enumeration to retrieve contact details</span></div>';
        const badges = ['whois-domain-badge', 'whois-privacy-badge', 'ip-intel-badge', 'whois-geo-badge', 'cdn-detect-badge', 'whois-http-badge', 'whois-bl-badge', 'whois-cross-badge', 'whois-history-badge', 'whois-complete-badge'];
        badges.forEach(id => { const badge = document.getElementById(id); if (badge) { badge.textContent = '--'; badge.className = 'dns-section-badge dim'; } });
        const vals = ['whois-domain-name', 'whois-created', 'whois-updated', 'whois-expires', 'whois-days-expiry', 'whois-status', 'whois-registrar', 'whois-iana', 'whois-ns', 'whois-dnssec', 'whois-sources', 'cdn-waf', 'cdn-anycast', 'http-status', 'http-final-url', 'whois-bl-score', 'whois-bl-risk', 'whois-bl-listed', 'whois-bl-ips', 'whois-cross-domains', 'whois-cross-pivots', 'whois-cross-org', 'whois-hist-events', 'whois-hist-snapshots', 'whois-hist-first-seen', 'whois-geo-coords', 'whois-geo-place'];
        vals.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '--'; });
        const geoFrame = document.getElementById('whois-geo-map-frame');
        if (geoFrame) { geoFrame.style.display = 'none'; geoFrame.src = ''; }
        const geoEmpty = document.getElementById('whois-geo-empty');
        if (geoEmpty) { geoEmpty.style.display = 'flex'; geoEmpty.innerHTML = '<span>Run enumeration to retrieve geolocation</span>'; }
        const geoLinkRow = document.getElementById('whois-geo-link-row');
        if (geoLinkRow) geoLinkRow.style.display = 'none';
        const metaRow = document.getElementById('cdn-meta-row');
        if (metaRow) metaRow.style.display = 'none';
        const emailsWrap = document.getElementById('whois-privacy-emails-wrap');
        if (emailsWrap) emailsWrap.style.display = 'none';
        const banner = document.getElementById('privacy-banner');
        if (banner) {
             banner.className = 'dns-info-banner';
             banner.innerHTML = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M8 2l6 12H2L8 2z" stroke="currentColor" stroke-width="1.3"/><path d="M8 7v3M8 11.5v.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg> Privacy Check: Analyzing WHOIS output for GDPR, WhoisGuard, and redacted fields...';
        }
        const jsonEl = document.getElementById('whois-complete-json');
        if (jsonEl) {
             jsonEl.textContent = '// Complete JSON result will appear here...';
             jsonEl.classList.add('output-placeholder');
        }
    }

    function _toast(msg, type) {
        if (typeof UI !== 'undefined' && UI.toast) { UI.toast(msg, type); return; }
        console.log(`[${type}] ${msg}`);
    }

    function _setBtnState(scanning) {
        const startBtn = $('whois-start-btn');
        const stopBtn  = $('whois-stop-btn');
        if (startBtn) {
            startBtn.disabled      = scanning;
            startBtn.style.opacity = scanning ? '0.55' : '';
            startBtn.innerHTML = scanning
                ? `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite">
                     <circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6"
                             stroke-dasharray="10 6" stroke-linecap="round"/>
                   </svg> SCANNING…`
                : `<svg width="13" height="13" viewBox="0 0 16 16" fill="none">
                     <circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.4"/>
                     <path d="M11 11l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
                   </svg> Start`;
        }
        if (stopBtn) stopBtn.disabled = !scanning;
    }

    function _collectInputs() {
        const v = id => ($(`${id}`)?.value?.trim() || '');
        const domainRaw = v('whois-input-domain') || v('dns-input-domain') || v('input-domain');
        const proxy     = v('whois-input-proxy')  || v('dns-input-proxy')  || v('input-proxy');
        const domain    = domainRaw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
        return { domain, proxy };
    }

    function _buildTargetPayload(vals) {
        if (!vals.domain) return null;
        const payload = { url: `https://${vals.domain}` };
        if (vals.proxy) payload.proxy = vals.proxy;
        return payload;
    }

    const KNOWN_MODULES = [
        { id: 'whois',        label: 'Domain WHOIS / RDAP'    },
        { id: 'ip_intel',     label: 'IP Intelligence'         },
        { id: 'cdn',          label: 'CDN Detection'           },
        { id: 'blacklist',    label: 'Blacklist / Reputation'  },
        { id: 'historical',   label: 'Historical WHOIS'        },
        { id: 'cross_search', label: 'Registrant Cross-Search' },
    ];

    let _trackerBuilt = false;

    function _buildTracker() {
        const grid = $('whois-tracker-grid');
        if (!grid) return;
        grid.innerHTML = '';
        KNOWN_MODULES.forEach(m => {
            const el = document.createElement('div');
            el.className = 'tracker-module';
            el.id        = `whois-tmod-${m.id}`;
            el.innerHTML = `
                <div class="tracker-dot"></div>
                <span class="tracker-module-name">${m.label}</span>
                <span class="tracker-check">✔</span>
            `;
            grid.appendChild(el);
        });
        _trackerBuilt = true;
    }

    function _showTracker() {
        const tracker = $('whois-module-tracker');
        if (!tracker) return;
        if (!_trackerBuilt) _buildTracker();
        tracker.style.display = 'block';
    }

    function _updateTracker(modulesDone, status) {
        _showTracker();
        const doneSet   = new Set(modulesDone || []);
        let lastDoneIdx = -1;
        KNOWN_MODULES.forEach((m, i) => { if (doneSet.has(m.id)) lastDoneIdx = i; });
        KNOWN_MODULES.forEach((m, i) => {
            const el = $(`whois-tmod-${m.id}`);
            if (!el) return;
            el.classList.remove('done', 'running');
            if (doneSet.has(m.id)) {
                el.classList.add('done');
            } else if (status === 'running' && i === lastDoneIdx + 1) {
                el.classList.add('running');
            }
        });
        const countEl = $('whois-tracker-count');
        if (countEl) countEl.textContent = `${doneSet.size} / ${KNOWN_MODULES.length} completed`;
    }

    function _resetTracker() {
        _trackerBuilt = false;
        const tracker = $('whois-module-tracker');
        if (tracker) tracker.style.display = 'none';
        const grid = $('whois-tracker-grid');
        if (grid) grid.innerHTML = '';
    }

    async function _fetchAndRenderFromDB(domain) {
        try {
            let resp = await fetch(`${DB_API_BASE}/api/whois/results`);
            let data = await resp.json().catch(() => ({}));

            if (!data || !data.success || !data.data) {
                resp = await fetch(`${DB_API_BASE}/api/whois/load`);
                data = await resp.json().catch(() => ({}));
            }

            if (data && data.success && data.data) {
                const d = data.data;
                WhoisIP.renderData(d);

                const size = v => Array.isArray(v) ? v.length : 0;
                const contacts = d.whois && d.whois.contacts
                    ? Object.values(d.whois.contacts).filter(c => c && Object.keys(c).length).length
                    : 0;
                const cdn = d.cdn_advanced || d.cdn || {};
                const http = Array.isArray(d.http) && d.http[0] && d.http[0].headers
                    ? Object.keys(d.http[0].headers).length
                    : 0;
                const hist = d.historical || {};

                _appendSummary([
                    ['Contacts',        contacts],
                    ['IP Addresses',    size(d.ips)],
                    ['CDN Vendors',     size(cdn.vendors)],
                    ['HTTP Headers',    http],
                    ['Blacklist Hits',  size(d.blacklist && d.blacklist.hits), 'bad'],
                    ['Related Domains', size(d.cross_search && d.cross_search.related_domains)],
                    ['History Records', size(hist.rdap_events) + size(hist.snapshots)],
                ], data.source === 'db' ? 'Loaded from database' : 'Loaded from JSON file');
                window.markPanelComplete?.('panel-whois-ip', 'WHOIS / IP');
                return true;
            } else {
                window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
                return false;
            }
        } catch (err) {
            window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
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
            const resp = await fetch(`${API_BASE}/api/whois/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

            const status = data.status;
            _updateTracker(data.modules_done || [], status);

            if (data.stderr) {
                let pre = _outputEl()?.querySelector('pre');
                if (!pre) { _appendLine('', ''); pre = _outputEl()?.querySelector('pre'); }
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
                    _appendScanResult(false, 'Database is not ready.');
                    _toast('Scan failed: database not ready', 'error');
                    _onScanEnd();
                    return;
                }

                _appendScanResult(true, data.output_file || 'Completed');
                await _fetchAndRenderFromDB(data.domain);
                window.markPanelComplete?.('panel-whois-ip', 'WHOIS / IP');
                _toast(`WHOIS scan completed: ${data.domain}`, 'ok');
                _onScanEnd();
                return;
            }

            if (status === 'error') {
                _appendScanResult(false, data.stderr || 'unknown error');
                _toast('WHOIS scan ended with an error', 'error');
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

        const vals          = _collectInputs();
        const targetPayload = _buildTargetPayload(vals);

        if (!targetPayload) {
            _toast('Please enter a domain name', 'warn');
            return;
        }

        _scanning = true;
        _aborted  = false;
        _setBtnState(true);
        _resetUI();

        const domain = vals.domain;

        const previewCmd = `python whois-checker.py -d ${domain} --json`;

        _appendLabeled('TARGET', domain, OUT_GREEN);

        try {
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(targetPayload),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);

            const scanPayload = {};
            if (vals.proxy) scanPayload.proxy = vals.proxy;
            const sResp = await fetch(`${API_BASE}/api/whois/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(scanPayload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `whois/scan: ${sResp.status}`);

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
        _toast('WHOIS scan stopped', 'warn');
        _onScanEnd();
    }

    function exportResults() {
        const complete = document.getElementById('whois-complete-json')?.textContent;
        if (!complete || complete.startsWith('//')) { _toast('No scan data to export.', 'warn'); return; }
        const blob = new Blob([complete], { type: 'application/json' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'whois-results.json'; a.click();
        URL.revokeObjectURL(url);
    }

    function init() {
        if (!document.getElementById('_whois_sc_style')) {
            const s = document.createElement('style');
            s.id = '_whois_sc_style';
            s.textContent = `
                @keyframes spin { to { transform: rotate(360deg); } }
                @keyframes whoisFadeIn { from { opacity: 0.3; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
                .whois-sub-panel { display: none !important; }
                .whois-sub-panel.active { display: block !important; animation: whoisFadeIn 0.25s ease; }
                #whois-subtab-bar .whois-subtab-btn {
                    background: transparent !important; border: none !important;
                    border-bottom: 2px solid transparent !important; border-radius: 0 !important;
                    color: var(--text-dim) !important; font-family: var(--ui); font-size: 10.5px;
                    font-weight: 500; padding: 5px 12px; cursor: pointer; outline: none;
                    transition: color 0.2s, border-color 0.2s, background 0.2s;
                    letter-spacing: 0.02em; white-space: nowrap;
                }
                #whois-subtab-bar .whois-subtab-btn:hover { color: var(--text-sec) !important; background: rgba(240,192,48,0.04) !important; }
                #whois-subtab-bar .whois-subtab-btn.active { color: var(--accent) !important; border-bottom-color: var(--accent) !important; background: rgba(240,192,48,0.06) !important; }
                #whois-workers-group { display: flex; gap: 4px; flex-wrap: wrap; }
                #whois-workers-group .dns-thread-btn { background: var(--bg-card) !important; border: 1px solid var(--border) !important; border-radius: var(--radius-sm) !important; color: var(--text-dim) !important; font-family: var(--mono); font-size: 11px; padding: 3px 10px; cursor: pointer; transition: all 0.15s; }
                #whois-workers-group .dns-thread-btn:hover { border-color: var(--accent-dim) !important; color: var(--text-sec) !important; }
                #whois-workers-group .dns-thread-btn.dns-thread-btn-active { background: var(--bg-selected) !important; border-color: var(--accent-dim) !important; color: var(--accent) !important; }
            `;
            document.head.appendChild(s);
        }

        document.addEventListener('click', e => {
            const subtabBtn = e.target.closest('.whois-subtab-btn');
            if (subtabBtn) {
                e.preventDefault();
                const tabId = subtabBtn.getAttribute('data-whoistab');
                if (tabId) _activateWhoisTab(tabId);
                return;
            }

            const btn = e.target.closest('button');
            if (!btn) return;
            if (btn.closest('#whois-workers-group')) {
                e.preventDefault();
                document.querySelectorAll('#whois-workers-group .dns-thread-btn').forEach(b => b.classList.remove('dns-thread-btn-active'));
                btn.classList.add('dns-thread-btn-active');
                return;
            }
            if (btn.id === 'whois-start-btn')  { e.preventDefault(); startScan(); }
            if (btn.id === 'whois-stop-btn')   { e.preventDefault(); stopScan(); }
            if (btn.id === 'whois-load-db-btn') { e.preventDefault(); _fetchAndRenderFromDB(document.getElementById('whois-input-domain')?.value.trim() || ''); }
            if (btn.id === 'whois-export-btn') { e.preventDefault(); exportResults(); }
            if (btn.id === 'whois-reset-btn')  {
                e.preventDefault();
                if (_scanning) { _aborted = true; _onScanEnd(); }
                _resetUI();
                showDefaultTab();
                _toast('WHOIS scan results cleared', 'info');
            }
        });

        showDefaultTab();
    }

    return { init, startScan, stopScan, showDefaultTab, loadFromDatabase: _fetchAndRenderFromDB };
})();

WhoisScanController.init();