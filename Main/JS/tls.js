const TLS = (() => {

    const API_BASE      = 'http://127.0.0.1:30300';
    const DB_API_BASE   = 'http://127.0.0.1:30301';
    const POLL_INTERVAL = 2000;
    const POLL_TIMEOUT  = 1800000;

    const state = {
        running:     false,
        target:      null,
        scanData:    null,
        _pollTimer:  null,
        _pollStart:  0,
        _currentJob: null,
        _aborted:    false,
    };

    function esc(s) {
        return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    function _toast(msg, type) {
        if (typeof UI !== 'undefined' && UI.toast) { UI.toast(msg, type); return; }
        console.log(`[${type}] ${msg}`);
    }

    function _outputEl() { return document.getElementById('tls-output-wrap'); }

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

    function _setBadge(id, text, cls) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.className = 'dns-section-badge ' + (cls || 'dim');
    }

    function _activateTab(id) {
        document.querySelectorAll('#panel-tls .tls-sub-panel').forEach(s => {
            s.classList.toggle('active', s.id === id);
        });
        document.querySelectorAll('#tls-subtab-bar .tls-subtab-btn').forEach(b => {
            b.classList.toggle('active', b.getAttribute('data-subtab') === id);
        });
    }

    function _openSection(id) { _activateTab(id); }

    function _openDefaultView() {
        const firstBtn = document.querySelector('#tls-subtab-bar .tls-subtab-btn[data-subtab]');
        const tabId = firstBtn && firstBtn.getAttribute('data-subtab');
        if (!tabId) return;
        _activateTab(tabId);
        document.querySelectorAll('#panel-tls .dns-section.collapsed').forEach(sec => sec.classList.remove('collapsed'));
    }

    function _gradeCls(g) { return g === 'A' ? 'ok' : g === 'B' ? 'warn' : g ? 'fail' : 'dim'; }

    function _kv(label, valHtml, valCls) {
        return `<div class="tls-kv">
            <span class="tls-kv-label">${label}</span>
            <span class="tls-kv-val ${valCls||''}">${valHtml}</span>
        </div>`;
    }

    function _block(title, inner, extra) {
        return `<div class="tls-block${extra?' '+extra:''}">
            <div class="tls-block-title">${title}</div>
            ${inner}
        </div>`;
    }

    /* ──────────────────────────────────────────
       CERTIFICATE DETAILS
    ────────────────────────────────────────── */
    function renderCertDetails(data) {
        const body = document.getElementById('tls-cert-body');
        if (!body) return;

        const raw = data?.results?.certificates || data?.certificates;
        if (!raw || !(raw.chain || []).length) {
            body.innerHTML = '<div class="tls-empty"><span>No certificate data returned</span></div>';
            return;
        }

        const chain      = raw.chain;
        const assessment = raw.assessment || {};
        const ocsp       = raw.ocsp || {};
        const ct         = raw.ct  || {};
        const grade      = assessment.grade || '—';

        _setBadge('tls-cert-badge', grade, _gradeCls(grade));
        _openSection('tls-sec-cert-details');

        const validCount   = chain.filter(c => !c.expired && !c.not_yet_valid).length;
        const expiredCount = chain.filter(c => c.expired).length;

        let html = `
        <div class="tls-stat-row">
            <div class="tls-stat">
                <div class="tls-stat-val ${_gradeCls(grade)}">${esc(grade)}</div>
                <div class="tls-stat-label">Grade</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val">${chain.length}</div>
                <div class="tls-stat-label">Chain Depth</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ok">${validCount}</div>
                <div class="tls-stat-label">Valid</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${expiredCount ? 'fail' : 'ok'}">${expiredCount}</div>
                <div class="tls-stat-label">Expired</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${assessment.chain_complete !== false ? 'ok' : 'fail'}">${assessment.chain_complete !== false ? '✓' : '✗'}</div>
                <div class="tls-stat-label">Chain OK</div>
            </div>
        </div>`;

        /* Certificate chain visual */
        let chainHtml = '<div class="cert-chain">';
        chain.forEach((cert, i) => {
            const role      = cert.role || (i === 0 ? 'leaf' : 'intermediate');
            const daysLeft  = cert.days_remaining;
            const daysCls   = daysLeft < 30 ? 'fail' : daysLeft < 90 ? 'warn' : 'ok';
            const pct       = typeof daysLeft === 'number' ? Math.max(0, Math.min(100, Math.round(daysLeft / 3.65))) : 75;

            chainHtml += `
            <div class="cert-chain-node">
                <div class="cert-chain-icon">
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                        <path d="M8 2L2 5v4c0 3 2.5 5 6 6 3.5-1 6-3 6-6V5L8 2z" stroke="currentColor" stroke-width="1.3"/>
                    </svg>
                </div>
                <div>
                    <div class="cert-chain-cn">${esc(cert.subject?.CN || 'Certificate ' + i)}</div>
                    <div class="cert-chain-meta">${esc(cert.issuer?.CN || '—')} · ${esc(cert.key?.type||'?')} ${cert.key?.bits||'?'} bit</div>
                </div>
                <span class="cert-role-tag ${role}">${role}</span>
            </div>`;

            if (i < chain.length - 1) {
                chainHtml += `<div class="cert-chain-connector">
                    <svg width="12" height="14" viewBox="0 0 12 14" fill="none">
                        <path d="M6 1v12M3 10l3 3 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>`;
            }
        });
        chainHtml += '</div>';
        html += _block('Certificate Chain', chainHtml);

        /* Leaf cert details */
        const leaf = chain[0];
        if (leaf) {
            const daysLeft = leaf.days_remaining;
            const daysCls  = daysLeft < 30 ? 'fail' : daysLeft < 90 ? 'warn' : 'ok';
            const pct      = typeof daysLeft === 'number' ? Math.max(0, Math.min(100, Math.round(daysLeft / 3.65))) : 75;

            let kvs = '';
            kvs += _kv('Subject CN',          esc(leaf.subject?.CN || '—'), '');
            kvs += _kv('Issuer CN',            esc(leaf.issuer?.CN  || '—'), '');
            kvs += _kv('Serial Number',        esc(leaf.serial      || '—'), 'dim');
            kvs += _kv('Valid From',           esc(leaf.not_before  || '—'), '');
            kvs += _kv('Valid Until',          `<span class="${daysCls}">${esc(leaf.not_after||'—')}</span>`, '');
            kvs += _kv('Days Remaining', `
                <div class="validity-bar-wrap">
                    <div class="validity-bar"><div class="validity-bar-fill ${daysCls}" style="width:${pct}%"></div></div>
                    <span class="validity-bar-label">${typeof daysLeft === 'number' ? daysLeft + ' days remaining' : 'Expired'}</span>
                </div>`, '');
            kvs += _kv('Public Key',           `<span class="${leaf.key?.weak ? 'fail' : 'ok'}">${esc(leaf.key?.type||'—')} ${leaf.key?.bits||'?'} bits</span>`, '');
            kvs += _kv('Signature Algorithm',  esc(leaf.signature_algorithm || '—'), '');
            kvs += _kv('Self-Signed',          leaf.self_signed ? '<span class="fail">Yes</span>' : '<span class="ok">No</span>', '');
            kvs += _kv('SANs',                 esc((leaf.sans||[]).map(s=>s.value).join(', ')||'—'), 'dim');
            kvs += _kv('SCT Count',            leaf.sct_count != null ? `<span class="${leaf.sct_count >= 2 ? 'ok' : 'warn'}">${leaf.sct_count}</span>` : '—', '');
            kvs += _kv('SHA-256 Fingerprint',  esc(leaf.fingerprints?.sha256||'—'), 'dim');
            html += _block('Leaf Certificate', kvs);
        }

        /* OCSP */
        const ocspStatus = ocsp.status || '—';
        const ocspCls    = ocspStatus === 'good' ? 'ocsp-good' : ocspStatus === 'revoked' ? 'ocsp-revoked' : '';
        let ocspKvs = '';
        ocspKvs += _kv('Status',      `<span class="${ocspCls}">${esc(ocspStatus)}</span>`, '');
        ocspKvs += _kv('Responder',   esc(ocsp.responder    || '—'), 'dim');
        ocspKvs += _kv('This Update', esc(ocsp.this_update  || '—'), 'dim');
        ocspKvs += _kv('Next Update', esc(ocsp.next_update  || '—'), 'dim');
        html += _block('OCSP / Revocation', ocspKvs);

        /* CT */
        const ctEntries = ct.entries || [];
        let ctKvs = '';
        ctKvs += _kv('Queried Domain', esc(ct.queried_domain || '—'), 'dim');
        ctKvs += _kv('Source',         esc(ct.source         || '—'), 'dim');
        ctKvs += _kv('Total Found',    ct.total_found != null ? `<span class="${ct.total_found > 0 ? 'ok' : 'warn'}">${ct.total_found}</span>` : '—', '');
        ctEntries.forEach((e, i) => {
            ctKvs += _kv(`Entry ${i+1}`, `${esc(e.common_name||'—')} · ${esc(e.issuer||'—')} · ${esc(e.not_before||'—')}`, 'dim');
        });
        html += _block('Certificate Transparency', ctKvs);

        body.innerHTML = html;
    }

    /* ──────────────────────────────────────────
       PROTOCOL SUPPORT
    ────────────────────────────────────────── */
    function renderProtoSupport(data) {
        const body = document.getElementById('tls-proto-body');
        if (!body) return;

        const raw = data?.results?.protocols || data?.protocols;
        if (!raw || !(raw.protocols||[]).length) {
            body.innerHTML = '<div class="tls-empty"><span>No protocol data returned</span></div>';
            return;
        }

        const protocols  = raw.protocols;
        const handshake  = raw.handshake  || {};
        const alpn       = raw.alpn       || {};
        const assessment = raw.assessment || {};
        const grade      = assessment.grade || '—';

        const activeCount = protocols.filter(p => p.supported).length;
        const hasInsecure = protocols.some(p => p.supported && ['SSLv2','SSLv3','TLSv1.0','TLSv1.1'].includes(p.version));

        _setBadge('tls-proto-badge', `${activeCount} active`, hasInsecure ? 'fail' : 'ok');
        _openSection('tls-sec-proto-support');

        const protoCardCls = p => {
            if (!p.supported) return '';
            if (['SSLv2','SSLv3'].includes(p.version))      return 'fail';
            if (['TLSv1.0','TLSv1.1'].includes(p.version)) return 'warn';
            return 'ok';
        };
        const protoTagCls = p => {
            if (!p.supported) return 'disabled';
            if (['SSLv2','SSLv3'].includes(p.version))      return 'fail';
            if (['TLSv1.0','TLSv1.1'].includes(p.version)) return 'warn';
            return 'ok';
        };

        let html = `
        <div class="tls-stat-row">
            <div class="tls-stat">
                <div class="tls-stat-val ${_gradeCls(grade)}">${esc(grade)}</div>
                <div class="tls-stat-label">Grade</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${hasInsecure ? 'fail' : 'ok'}">${activeCount}</div>
                <div class="tls-stat-label">Active</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val dim">${protocols.length - activeCount}</div>
                <div class="tls-stat-label">Disabled</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${alpn.http2_supported ? 'ok' : 'warn'}">${alpn.http2_supported ? 'YES' : 'NO'}</div>
                <div class="tls-stat-label">HTTP/2</div>
            </div>
        </div>`;

        /* Protocol matrix */
        const matrixHtml = `
        <div class="tls-desc">TLS 1.3 and 1.2 are recommended. TLS 1.0/1.1 are deprecated (RFC 8996). SSLv2/SSLv3 are broken.</div>
        <div class="proto-matrix">
            ${protocols.map(p => `
            <div class="proto-card ${protoCardCls(p)}">
                <div class="proto-card-ver">${esc(p.version)}</div>
                <span class="proto-tag ${protoTagCls(p)}">${p.supported ? 'Supported' : 'Disabled'}</span>
                <div class="proto-card-reason">${esc(p.rating_reason || (p.supported ? '' : 'Not offered'))}</div>
            </div>`).join('')}
        </div>`;
        html += _block('Protocol Matrix', matrixHtml);

        /* Handshake */
        let hsKvs = '';
        hsKvs += _kv('Negotiated Version', `<span class="ok">${esc(handshake.negotiated_version||'—')}</span>`, '');
        hsKvs += _kv('Cipher Suite',       esc(handshake.cipher?.name||'—'), '');
        hsKvs += _kv('Bits',               handshake.cipher?.bits ? handshake.cipher.bits + ' bits' : '—', 'dim');
        hsKvs += _kv('Handshake Time',     handshake.handshake_time_ms ? handshake.handshake_time_ms.toFixed(2) + ' ms' : '—', 'dim');
        html += _block('Negotiated Handshake', hsKvs);

        /* ALPN */
        let alpnKvs = '';
        alpnKvs += _kv('HTTP/2 (h2)',  alpn.http2_supported  ? '<span class="ok">Supported</span>'      : '<span class="warn">Not advertised</span>', '');
        alpnKvs += _kv('HTTP/1.1',     alpn.http11_supported ? '<span class="ok">Supported</span>'      : '<span class="dim">Not advertised</span>', '');
        const alpnProtos = alpn.supported_protocols || [];
        alpnKvs += _kv('Advertised',   esc(alpnProtos.join(', ') || 'None detected'), 'dim');
        (assessment.notes||[]).forEach(n => { alpnKvs += _kv('Note', esc(n), 'dim'); });
        html += _block('ALPN Protocols', alpnKvs);

        /* Warnings */
        const warns = [...(assessment.warnings||[]), ...(assessment.issues||[])];
        if (warns.length) {
            const warnHtml = warns.map(w => `<div class="tls-warn-row warn"><span class="w-tag">warn</span><span class="w-text">${esc(w)}</span></div>`).join('');
            html += _block('Warnings', warnHtml);
        }

        body.innerHTML = html;
    }

    /* ──────────────────────────────────────────
       CIPHER ALGORITHMS
    ────────────────────────────────────────── */
    function renderCipherAlgos(data) {
        const body = document.getElementById('tls-cipher-body');
        if (!body) return;

        const raw = data?.results?.ciphers || data?.ciphers;
        if (!raw) {
            body.innerHTML = '<div class="tls-empty"><span>No cipher data returned</span></div>';
            return;
        }

        const allCiphers  = raw.ciphers || [];
        const cls         = raw.classification || {};
        const pfsAnalysis = raw.pfs_analysis   || {};
        const assessment  = raw.assessment     || {};
        const supported   = allCiphers.filter(c => c.supported);

        if (!supported.length) {
            body.innerHTML = '<div class="tls-empty"><span>No supported ciphers detected</span></div>';
            return;
        }

        const grade       = assessment.grade || '—';
        const pfsCount    = pfsAnalysis.pfs_count    ?? 0;
        const nonPfsCount = pfsAnalysis.non_pfs_count ?? 0;
        const total       = pfsCount + nonPfsCount || 1;

        _setBadge('tls-cipher-badge', `${supported.length} found`, _gradeCls(grade));
        _openSection('tls-sec-cipher-algos');

        let html = `
        <div class="tls-stat-row">
            <div class="tls-stat">
                <div class="tls-stat-val ${_gradeCls(grade)}">${esc(grade)}</div>
                <div class="tls-stat-label">Grade</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val">${supported.length}</div>
                <div class="tls-stat-label">Supported</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ok">${pfsCount}</div>
                <div class="tls-stat-label">PFS</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${nonPfsCount > 0 ? 'warn' : 'ok'}">${nonPfsCount}</div>
                <div class="tls-stat-label">Non-PFS</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val dim">${allCiphers.length - supported.length}</div>
                <div class="tls-stat-label">Rejected</div>
            </div>
        </div>`;

        /* PFS vs Non-PFS preference bar */
        const pfsPct    = Math.round((pfsCount / total) * 100);
        const nonPfsPct = 100 - pfsPct;
        const barHtml = `
        <div class="pref-bar-wrap">
            <div class="pref-bar-track">
                <div class="pref-bar-pfs" style="width:${pfsPct}%"></div>
                <div class="pref-bar-non" style="width:${nonPfsPct}%"></div>
            </div>
            <div class="pref-bar-legend">
                <span><span class="dot" style="background:var(--green)"></span>${pfsCount} PFS ciphers (${pfsPct}%)</span>
                <span><span class="dot" style="background:#f85149"></span>${nonPfsCount} non-PFS (${nonPfsPct}%)</span>
            </div>
        </div>`;
        html += _block('PFS Distribution', barHtml);

        /* Cipher inventory table */
        const tableHtml = `
        <div class="tls-desc">AEAD ciphers (GCM, ChaCha20-Poly1305) are preferred. CBC and static RSA key exchange are deprecated.</div>
        <table class="cipher-table">
            <thead><tr>
                <th>Cipher Suite</th>
                <th>Protocol</th>
                <th>Bits</th>
                <th>PFS</th>
                <th>Strength</th>
            </tr></thead>
            <tbody>
            ${supported.map(c => `
            <tr>
                <td class="cipher-name-cell">${esc(c.name)}</td>
                <td>${esc(c.protocol_version||c.protocol||'—')}</td>
                <td>${c.bits||'—'}</td>
                <td>${c.pfs !== undefined ? (c.pfs ? '<span class="cipher-pfs-yes">YES</span>' : '<span class="cipher-pfs-no">NO</span>') : '—'}</td>
                <td><span class="cipher-strength ${c.strength||'dim'}">${esc(c.strength||'—')}</span></td>
            </tr>`).join('')}
            </tbody>
        </table>`;
        html += _block('Accepted Cipher Suites', tableHtml);

        /* Categories */
        const CAT_LABEL = {
            tls13: 'TLS 1.3', ecdhe_aead: 'ECDHE + AEAD', ecdhe_cbc: 'ECDHE + CBC',
            dhe_aead: 'DHE + AEAD', dhe_cbc: 'DHE + CBC', rsa_aead: 'RSA + AEAD (no PFS)',
            rsa_cbc: 'RSA + CBC (no PFS)', static_ecdh: 'Static ECDH', weak: 'Weak',
        };
        let catHtml = '';
        Object.entries(cls).forEach(([cat, ciphers]) => {
            if (!Array.isArray(ciphers) || !ciphers.length) return;
            catHtml += `<div class="cipher-cat-label">${esc(CAT_LABEL[cat]||cat)}<span style="margin-left:auto;font-weight:400;opacity:.5;">${ciphers.length} suite${ciphers.length > 1 ? 's' : ''}</span></div>`;
            ciphers.forEach(c => {
                catHtml += `<div class="tls-kv" style="padding:7px 14px;">
                    <span class="tls-kv-label" style="font-family:var(--mono);font-size:10.5px;">${esc(c.name)}</span>
                    <span class="tls-kv-val dim">${esc(c.protocol_version||c.protocol||'—')} · ${c.bits||'—'} bits · ${c.handshake_time_ms ? c.handshake_time_ms.toFixed(2) + ' ms' : '—'}</span>
                </div>`;
            });
        });
        if (catHtml) html += `<div class="tls-block"><div class="tls-block-title">By Category</div></div>${catHtml}`;

        /* Warnings */
        const warns = [...(assessment.warnings||[])];
        const notes = [...(assessment.notes||[])];
        if (warns.length || notes.length) {
            const warnHtml = [
                ...warns.map(w => `<div class="tls-warn-row warn"><span class="w-tag">warn</span><span class="w-text">${esc(w)}</span></div>`),
                ...notes.map(n => `<div class="tls-warn-row note"><span class="w-tag">note</span><span class="w-text">${esc(n)}</span></div>`),
            ].join('');
            html += _block('Assessment Notes', warnHtml);
        }

        body.innerHTML = html;
    }

    /* ──────────────────────────────────────────
       PFS & GROUPS
    ────────────────────────────────────────── */
    function renderPfsGroups(data) {
        const body = document.getElementById('tls-pfs-body');
        if (!body) return;

        const rawPfs    = data?.results?.pfs    || data?.pfs;
        const rawGroups = data?.results?.groups  || data?.groups;

        if (!rawPfs && !rawGroups) {
            body.innerHTML = '<div class="tls-empty"><span>No PFS / group data returned</span></div>';
            return;
        }

        const pfsSupport  = rawPfs?.pfs_support         || {};
        const ecdhCurves  = rawPfs?.ecdh_curves          || {};
        const dheParams   = rawPfs?.dhe_params            || {};
        const cipherPref  = rawPfs?.cipher_preference    || {};
        const sessionRes  = rawPfs?.session_resumption   || {};
        const pfsAssess   = rawPfs?.assessment            || {};

        const groups      = rawGroups?.groups             || [];
        const grpCls      = rawGroups?.classification     || {};
        const grpStrength = rawGroups?.strength_analysis  || {};
        const grpAssess   = rawGroups?.assessment         || {};
        const grpDhe      = rawGroups?.dhe_params         || {};

        const pfsAvail    = pfsSupport.pfs_available;
        const pfsGrade    = pfsAssess.grade || '—';
        const supported   = groups.filter(g => g.supported);

        const strongEcdhe   = [].concat(grpCls.strong_ecdhe   || []);
        const obsoleteEcdhe = [].concat(grpCls.obsolete_ecdhe || []);
        const weakEcdhe     = [].concat(grpCls.weak_ecdhe     || []);

        _setBadge('tls-pfs-badge', pfsAvail ? 'Supported' : 'Not supported', pfsAvail ? 'ok' : 'fail');
        _openSection('tls-sec-pfs-groups');

        let html = `
        <div class="tls-stat-row">
            <div class="tls-stat">
                <div class="tls-stat-val ${_gradeCls(pfsGrade)}">${esc(pfsGrade)}</div>
                <div class="tls-stat-label">Grade</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${pfsAvail ? 'ok' : 'fail'}">${pfsAvail ? 'YES' : 'NO'}</div>
                <div class="tls-stat-label">PFS</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val">${supported.length}</div>
                <div class="tls-stat-label">Groups</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${strongEcdhe.length ? 'ok' : 'warn'}">${strongEcdhe.length}</div>
                <div class="tls-stat-label">Strong</div>
            </div>
            <div class="tls-stat">
                <div class="tls-stat-val ${obsoleteEcdhe.length ? 'warn' : 'ok'}">${obsoleteEcdhe.length}</div>
                <div class="tls-stat-label">Obsolete</div>
            </div>
        </div>`;

        /* KEX methods */
        const pfsKexList    = pfsSupport.pfs_supported_kex     || [];
        const nonPfsKexList = pfsSupport.non_pfs_supported_kex || [];
        let kexHtml = '<div class="kex-grid">';
        pfsKexList.forEach(k => {
            kexHtml += `<div class="kex-pill pfs"><span class="kex-dot"></span>${esc(k)}</div>`;
        });
        nonPfsKexList.forEach(k => {
            kexHtml += `<div class="kex-pill non-pfs"><span class="kex-dot"></span>${esc(k)}</div>`;
        });
        kexHtml += '</div>';
        let kexKvs = '';
        kexKvs += _kv('PFS Key Exchanges',   esc(pfsKexList.join(', ')    || 'None'), pfsKexList.length ? 'ok' : 'fail');
        kexKvs += _kv('Non-PFS Exchanges',   esc(nonPfsKexList.join(', ') || 'None'), nonPfsKexList.length ? 'warn' : 'ok');
        kexKvs += _kv('PFS Preferred',       cipherPref.pfs_preferred !== undefined ? (cipherPref.pfs_preferred ? '<span class="ok">Yes</span>' : '<span class="warn">No</span>') : '—', '');
        kexKvs += _kv('PFS Cipher Count',    `${cipherPref.pfs_cipher_count ?? '—'} PFS · ${cipherPref.non_pfs_cipher_count ?? '—'} non-PFS`, 'dim');
        kexKvs += _kv('DHE Supported',       dheParams.dhe_supported ? '<span class="ok">Yes</span>' : '<span class="dim">No</span>', '');
        kexKvs += _kv('DHE Key Bits',        dheParams.dhe_bits ? dheParams.dhe_bits + ' bits' : 'Unknown', 'dim');
        html += _block('Key Exchange Methods', kexHtml + kexKvs);

        /* Curves */
        let curveHtml = '<div class="curve-grid">';
        strongEcdhe.forEach(g => {
            curveHtml += `<div class="curve-card strong">
                <div class="curve-name">${esc(g.name)}</div>
                <div class="curve-bits">${g.key_bits ? g.key_bits + ' bits' : '—'} · ${esc(g.protocol||'—')} · ${g.handshake_time_ms ? g.handshake_time_ms.toFixed(2) + ' ms' : '—'}</div>
                <span class="curve-label strong">Strong</span>
            </div>`;
        });
        obsoleteEcdhe.forEach(g => {
            curveHtml += `<div class="curve-card obsolete">
                <div class="curve-name">${esc(g.name)}</div>
                <div class="curve-bits">${g.key_bits ? g.key_bits + ' bits' : '—'} · ${esc(g.protocol||'—')}</div>
                <span class="curve-label obsolete">Obsolete</span>
            </div>`;
        });
        weakEcdhe.forEach(g => {
            curveHtml += `<div class="curve-card weak">
                <div class="curve-name">${esc(g.name)}</div>
                <div class="curve-bits">${g.key_bits ? g.key_bits + ' bits' : '—'}</div>
                <span class="curve-label weak">Weak</span>
            </div>`;
        });
        curveHtml += '</div>';
        let curveKvs = '';
        curveKvs += _kv('Best Curve',       esc(ecdhCurves.best_curve || '—'), 'ok');
        curveKvs += _kv('Strong Curves',    esc((ecdhCurves.strong_curves  ||[]).join(', ')||'—'), 'ok');
        curveKvs += _kv('Obsolete Curves',  esc((ecdhCurves.obsolete_curves||[]).join(', ')||'None'), (ecdhCurves.obsolete_curves||[]).length ? 'warn' : 'ok');
        curveKvs += _kv('Weak Curves',      esc((ecdhCurves.weak_curves    ||[]).join(', ')||'None'), (ecdhCurves.weak_curves||[]).length ? 'fail' : 'ok');
        html += _block('ECDHE Curves', curveHtml + curveKvs);

        /* Session resumption */
        let sessHtml = '<div class="resumption-row">';
        if (sessionRes.session_id_supported) {
            sessHtml += `<div class="resumption-badge"><span class="r-dot"></span>Session ID</div>`;
        }
        if (sessionRes.session_ticket_supported) {
            sessHtml += `<div class="resumption-badge"><span class="r-dot"></span>Session Ticket</div>`;
        }
        sessHtml += '</div>';
        let sessKvs = '';
        sessKvs += _kv('Mode',           esc(sessionRes.resumption_mode||'—'), 'dim');
        sessKvs += _kv('Ticket Lifetime',sessionRes.ticket_lifetime_hours ? sessionRes.ticket_lifetime_hours + ' hours' : '—', 'dim');
        html += _block('Session Resumption', sessHtml + sessKvs);

        /* Warnings */
        const warns = [...(pfsAssess.warnings||[]), ...(grpAssess.warnings||[])];
        const notes = [...(pfsAssess.notes||[]),    ...(grpAssess.notes||[])];
        if (warns.length || notes.length) {
            const warnHtml = [
                ...warns.map(w => `<div class="tls-warn-row warn"><span class="w-tag">warn</span><span class="w-text">${esc(w)}</span></div>`),
                ...notes.map(n => `<div class="tls-warn-row note"><span class="w-tag">note</span><span class="w-text">${esc(n)}</span></div>`),
            ].join('');
            html += _block('Assessment Notes', warnHtml);
        }

        body.innerHTML = html;
    }

    function renderAll(data) {
        renderCertDetails(data);
        renderProtoSupport(data);
        renderCipherAlgos(data);
        renderPfsGroups(data);
    }

    function updateSummaryBar(data) {
        const badge = document.querySelector('[data-panel="panel-tls"] .nav-count') ||
                      document.querySelector('.nav-item[data-panel="panel-tls"] .nav-count');
        if (!badge) return;
        const issues = (data?.misconfigurations || []).length;
        badge.textContent = issues ? `${issues} issues` : 'OK';
    }

    function _stopPolling() {
        if (state._pollTimer) { clearTimeout(state._pollTimer); state._pollTimer = null; }
    }

    function _onScanEnd() {
        _stopPolling();
        state.running     = false;
        state._aborted    = false;
        state._currentJob = null;
        updateScanBtn(false);
    }

    async function _getRows(modules, tableName, scanId) {
        const direct = modules?.[tableName]?.rows;
        if (Array.isArray(direct)) return direct;
        try {
            const resp = await fetch(`${DB_API_BASE}/api/list/${tableName}?scan_id=${encodeURIComponent(scanId)}&limit=500000`);
            if (!resp.ok) return [];
            const data = await resp.json().catch(() => ({}));
            return Array.isArray(data.rows) ? data.rows : [];
        } catch { return []; }
    }

    async function _loadAndRenderResults(jobData = {}) {
        try {
            const domain = typeof jobData === 'string' ? jobData : (jobData.domain || state.target);
            let richData = null;
            const summaryResp = await fetch(
                `${DB_API_BASE}/api/tls/summary?target=${encodeURIComponent(domain || '')}`
            );
            const summaryData = await summaryResp.json().catch(() => ({}));
            if (summaryResp.ok && summaryData?.success) richData = summaryData;

            if (richData) {
                const resultSet = richData.results || richData;
                const hasRows = ['certificates', 'protocols', 'ciphers', 'pfs', 'groups']
                    .some(key => {
                        const value = resultSet[key];
                        return Array.isArray(value) ? value.length > 0
                            : Boolean(value && typeof value === 'object' && Object.keys(value).length);
                    });
                if (!hasRows) throw new Error('No TLS results found in database');
                state.scanData = richData;
                renderAll(richData);
                updateSummaryBar(richData);
                _appendLabeled('DATABASE', 'Results loaded and rendered', OUT_GREEN);
                window.markPanelComplete?.('panel-tls', 'TLS');
            } else {
                throw new Error(summaryData?.error || 'No TLS results found in database');
            }
        } catch (err) {
            window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
            return false;
        }
        return true;
    }

    async function _poll(jobId) {
        if (state._aborted) { _onScanEnd(); return; }
        if (Date.now() - state._pollStart > POLL_TIMEOUT) {
            _appendScanResult(false, 'Scan timed out (30 minutes).');
            _onScanEnd(); return;
        }
        try {
            const resp = await fetch(`${API_BASE}/api/tls/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);
            const status = data.status;
            if (status === 'done') {
                if (!data.db_ready) {
                    _appendScanResult(false, 'Database is not ready.');
                    _toast('Scan failed: database not ready', 'error');
                    _onScanEnd(); return;
                }
                _appendScanResult(true, data.output_file || 'Completed');
                const rendered = await _loadAndRenderResults(data);
                if (!rendered) {
                    _onScanEnd();
                    return;
                }
                window.markPanelComplete?.('panel-tls', 'TLS');
                _toast(`TLS scan completed: ${data.domain}`, 'ok');
                _onScanEnd(); return;
            }
            if (status === 'error') {
                _appendScanResult(false, data.stderr || 'unknown error');
                _toast('Scan ended with an error', 'error');
                _onScanEnd(); return;
            }
            state._pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);
        } catch (err) {
            _appendScanResult(false, `Poll error: ${err.message}`);
            _onScanEnd();
        }
    }

    function _collectTLSInputs() {
        const domainRaw = document.getElementById('tls-input-domain')?.value?.trim()
                       || State?.get?.('targetUrl') || State?.get?.('domain') || '';
        const activeBtn = document.querySelector('#tls-threads-group .dns-thread-btn-active');
        return {
            domain:  domainRaw.replace(/^https?:\/\//i,'').replace(/\/.*$/,'').trim(),
            threads: activeBtn ? parseInt(activeBtn.dataset.val) : 3,
        };
    }

    async function startScan() {
        const inputs = _collectTLSInputs();
        if (!inputs.domain) { _toast('Please enter a domain name', 'warn'); return; }
        if (state.running)  return;
        state.running  = true;
        state._aborted = false;
        state.target   = inputs.domain;
        updateScanBtn(true);
        _clearOutput();
        const targetPayload = { url: inputs.domain.startsWith('http') ? inputs.domain : `https://${inputs.domain}` };
        _appendLabeled('TARGET', inputs.domain, OUT_GREEN);
        try {
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(targetPayload),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);
            const scanPayload = {};
            if (inputs.threads) scanPayload.threads = inputs.threads;
            const sResp = await fetch(`${API_BASE}/api/tls/scan`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanPayload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `tls/scan: ${sResp.status}`);
            state._currentJob = sData.job_id;
            if (sData.cmd) _appendLabeled('COMMAND', sData.cmd, OUT_GREEN);
            _appendLabeled('JOB ID', state._currentJob, OUT_GREEN);
            state._pollStart = Date.now();
            _poll(state._currentJob);
        } catch (err) {
            _appendScanResult(false, err.message);
            _appendLine('Is the API backend running?  →  python3 connection.py', 'var(--text-dim)');
            _toast(`Error: ${err.message}`, 'error');
            _onScanEnd();
        }
    }

    function stopScan() {
        if (!state.running) return;
        state._aborted = true;
        _appendScanResult(false, 'Stopped by user.');
        _toast('TLS scan stopped.', 'warn');
        _onScanEnd();
    }

    function updateScanBtn(running) {
        const btn  = document.getElementById('tls-scan-btn');
        const stop = document.getElementById('tls-stop-btn');
        if (btn)  btn.disabled  = running;
        if (stop) stop.disabled = !running;
        if (!btn) return;
        const label     = running ? 'SCANNING…' : 'Scan TLS / Certificates';
        const textNodes = [...btn.childNodes].filter(n => n.nodeType === Node.TEXT_NODE);
        if (textNodes.length) textNodes[textNodes.length - 1].textContent = ' ' + label;
        else btn.appendChild(document.createTextNode(' ' + label));
    }

    const EMPTY_STATES = [
        { body: 'tls-cert-body',   badge: 'tls-cert-badge',   text: 'Run a scan to see certificate details',
          svg: '<path d="M12 2L4 6v6c0 5.5 3.5 10 8 12 4.5-2 8-6.5 8-12V6L12 2z" stroke="currentColor" stroke-width="1.2"/>' },
        { body: 'tls-proto-body',  badge: 'tls-proto-badge',  text: 'Run a scan to see protocol support',
          svg: '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.2"/><path d="M2 12h20M12 2c-3 3-4.5 6-4.5 10s1.5 7 4.5 10" stroke="currentColor" stroke-width="1.2"/>' },
        { body: 'tls-cipher-body', badge: 'tls-cipher-badge', text: 'Run a scan to see cipher algorithms',
          svg: '<rect x="2" y="5" width="8" height="14" rx="1" stroke="currentColor" stroke-width="1.2"/><rect x="14" y="5" width="8" height="14" rx="1" stroke="currentColor" stroke-width="1.2"/><path d="M10 12h4" stroke="currentColor" stroke-width="1.2"/>' },
        { body: 'tls-pfs-body',    badge: 'tls-pfs-badge',    text: 'Run a scan to see PFS and cryptographic groups',
          svg: '<rect x="6" y="11" width="12" height="9" rx="1" stroke="currentColor" stroke-width="1.2"/><path d="M8 11V7a4 4 0 0 1 8 0v4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>' },
    ];

    function resetAll() {
        if (state._currentJob) state._aborted = true;
        _stopPolling();
        state.running     = false;
        state._currentJob = null;
        state.scanData    = null;
        state.target      = null;
        updateScanBtn(false);
        _clearOutput();
        EMPTY_STATES.forEach(s => {
            const body = document.getElementById(s.body);
            if (body) {
                body.innerHTML = `<div class="tls-empty"><svg width="32" height="32" viewBox="0 0 24 24" fill="none">${s.svg}</svg><span>${s.text}</span></div>`;
            }
            _setBadge(s.badge, '--', 'dim');
        });
        _openDefaultView();
    }

    function _bindButtons() {
        [
            ['tls-scan-btn',  startScan],
            ['tls-stop-btn',  stopScan],
            ['tls-reset-btn', resetAll],
        ].forEach(([id, handler]) => {
            const el = document.getElementById(id);
            if (el && !el._tlsBound) { el.addEventListener('click', handler); el._tlsBound = true; }
        });
        const loadDb = document.getElementById('tls-load-db-btn');
        if (loadDb && !loadDb._tlsBound) {
            loadDb.addEventListener('click', async () => {
                loadDb.disabled = true;
                try {
                    const domain = document.getElementById('tls-input-domain')?.value.trim() || '';
                    await _loadAndRenderResults(domain);
                } finally {
                    loadDb.disabled = false;
                }
            });
            loadDb._tlsBound = true;
        }
        document.getElementById('tls-threads-group')?.querySelectorAll('.dns-thread-btn').forEach(btn => {
            if (!btn._tlsThreadBound) {
                btn.addEventListener('click', () => {
                    document.querySelectorAll('#tls-threads-group .dns-thread-btn').forEach(b => b.classList.remove('dns-thread-btn-active'));
                    btn.classList.add('dns-thread-btn-active');
                });
                btn._tlsThreadBound = true;
            }
        });
    }

    function init() {
        _bindButtons();
        _openDefaultView();
    }

    document.addEventListener('click', function (e) {
        const btn = e.target.closest('button');
        if (!btn) return;
        const id = btn.id;
        if (id === 'tls-scan-btn')  { e.stopPropagation(); startScan();  }
        if (id === 'tls-stop-btn')  { e.stopPropagation(); stopScan();   }
        if (id === 'tls-reset-btn') { e.stopPropagation(); resetAll();   }
        if (id === 'tls-load-db-btn') {
            e.stopPropagation();
            btn.disabled = true;
            const domain = document.getElementById('tls-input-domain')?.value.trim() || '';
            _loadAndRenderResults(domain).finally(() => { btn.disabled = false; });
        }
        if (btn.closest('#tls-threads-group')) {
            document.querySelectorAll('#tls-threads-group .dns-thread-btn')
                .forEach(b => b.classList.remove('dns-thread-btn-active'));
            btn.classList.add('dns-thread-btn-active');
        }
        if (btn.closest('#tls-subtab-bar')) {
            const subtabId = btn.getAttribute('data-subtab');
            if (subtabId) _activateTab(subtabId);
        }
    }, true);

    return { init, startScan, stopScan, resetAll, renderAll };

})();