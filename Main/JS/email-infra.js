const EmailInfra = (() => {

    const PROVIDER_SIGNATURES = [
        { provider: 'Google Workspace (G Suite)',       mxPattern: /google\.com$|googlemail\.com$/,          spfInclude: /_spf\.google\.com/i,            dkimSelector: 'google',      confidence: 'high' },
        { provider: 'Microsoft 365 (Office 365)',       mxPattern: /protection\.outlook\.com$|mail\.protection\.outlook\.com$/, spfInclude: /spf\.protection\.outlook\.com/i, dkimSelector: 'selector1-*', confidence: 'high' },
        { provider: 'Proofpoint',                       mxPattern: /pphosted\.com$|proofpoint\.net$/,        spfInclude: /_spf\.pphosted\.com/i,          dkimSelector: 'pp',          confidence: 'high' },
        { provider: 'Mimecast',                         mxPattern: /mimecast\.com$/,                         spfInclude: /_spf\.mimecast\.com/i,          dkimSelector: 'mimecast',    confidence: 'high' },
        { provider: 'Cisco Email Security (IronPort)',  mxPattern: /ironport\.com$|esa\./,                   spfInclude: null,                            dkimSelector: null,          confidence: 'medium' },
        { provider: 'Barracuda',                        mxPattern: /barracuda\.com$|barracudanetworks\.com/, spfInclude: /_spf\.barracudanetworks\.com/i, dkimSelector: null,          confidence: 'medium' },
        { provider: 'Zoho Mail',                        mxPattern: /zoho\.com$|zohomail\.com$/,              spfInclude: /_spf\.zoho\.com/i,             dkimSelector: 'zoho',        confidence: 'high' },
        { provider: 'FastMail',                         mxPattern: /fastmail\.com$|messagingengine\.com$/,   spfInclude: /_spf\.fastmail\.com/i,          dkimSelector: 'fastmail',    confidence: 'medium' },
        { provider: 'Rackspace Email',                  mxPattern: /emailsrvr\.com$/,                        spfInclude: /_spf\.emailsrvr\.com/i,         dkimSelector: null,          confidence: 'medium' },
        { provider: 'Yandex Mail',                      mxPattern: /yandex\.net$|mx\.yandex\.ru/,           spfInclude: /_spf\.yandex\.net/i,            dkimSelector: 'yandex',      confidence: 'high' },
        { provider: 'Mail.ru',                          mxPattern: /mail\.ru$/,                              spfInclude: /_spf\.mail\.ru/i,               dkimSelector: 'mailru',      confidence: 'medium' },
        { provider: 'GoDaddy Email (Workspace)',        mxPattern: /secureserver\.net$/,                     spfInclude: null,                            dkimSelector: null,          confidence: 'medium' },
        { provider: 'DreamHost',                        mxPattern: /dreamhost\.com$/,                        spfInclude: /_spf\.dreamhost\.com/i,         dkimSelector: null,          confidence: 'low' },
        { provider: 'Self-Hosted (Generic Postfix)',    mxPattern: /^mail\./,                                spfInclude: null,                            dkimSelector: null,          confidence: 'low' },
    ];

    const EXCHANGE_SERVICE_PORTS = [
        { service: 'SMTP',         port: 25,  protocol: 'SMTP' },
        { service: 'SMTPS',        port: 465, protocol: 'SMTPS' },
        { service: 'SMTP STARTTLS',port: 587, protocol: 'SMTP' },
        { service: 'IMAP',         port: 143, protocol: 'IMAP' },
        { service: 'IMAPS',        port: 993, protocol: 'IMAPS' },
        { service: 'POP3',         port: 110, protocol: 'POP3' },
        { service: 'POP3S',        port: 995, protocol: 'POP3S' },
        { service: 'HTTP',         port: 80,  protocol: 'HTTP' },
        { service: 'HTTPS',        port: 443, protocol: 'HTTPS' },
    ];

    const EXCHANGE_CONFIG_ENDPOINTS = [
        { service: 'Autodiscover XML',          path: '/autodiscover/autodiscover.xml',               provider: 'Exchange / M365' },
        { service: 'Autodiscover JSON',          path: '/autodiscover/autodiscover.json',              provider: 'Exchange / M365' },
        { service: 'OWA (Outlook Web App)',      path: '/owa/',                                        provider: 'Exchange On-Premises' },
        { service: 'ECP (Exchange Control Panel)',path: '/ecp/',                                       provider: 'Exchange On-Premises' },
        { service: 'EWS (Exchange Web Services)',path: '/ews/exchange.asmx',                           provider: 'Exchange On-Premises / M365' },
        { service: 'MAPI over HTTP',             path: '/mapi/',                                       provider: 'Exchange 2013+ / M365' },
        { service: 'ActiveSync',                 path: '/microsoft-server-activesync',                 provider: 'Exchange / M365' },
        { service: 'RPC over HTTP (Outlook Anywhere)', path: '/rpc/',                                  provider: 'Exchange On-Premises' },
        { service: 'Autoconfig (Mozilla)',       path: '/.well-known/autoconfig/mail/config-v1.1.xml', provider: 'Thunderbird / Mozilla' },
    ];

    const RELAY_SERVICES = [
        { txtPattern: /include:spf\.amazonses\.com/i,      service: 'Amazon SES',         note: 'Transactional email service' },
        { txtPattern: /include:mailgun\.org/i,             service: 'Mailgun',            note: 'Transactional email service' },
        { txtPattern: /include:sendgrid\.net|include:sendgrid\.com/i, service: 'SendGrid',note: 'Transactional email service' },
        { txtPattern: /include:spf\.mandrillapp\.com/i,   service: 'Mandrill',           note: 'Transactional (MailChimp)' },
        { txtPattern: /include:sparkpostmail\.com/i,       service: 'SparkPost',          note: 'Transactional email service' },
        { txtPattern: /include:spf\.postmarkapp\.com/i,   service: 'Postmark',           note: 'Transactional email service' },
        { txtPattern: /include:mailjet\.com|_spf\.mailjet\.com/i, service: 'Mailjet',    note: 'Transactional / Marketing' },
        { txtPattern: /include:sendpulse\.com|_spf\.sendpulse\.com/i, service: 'SendPulse', note: 'Marketing email' },
        { txtPattern: /include:mailchimp\.com|_spf\.mailchimp\.com/i, service: 'Mailchimp', note: 'Marketing email' },
        { txtPattern: /include:sendinblue\.com|_spf\.sendinblue\.com|_spf\.brevo\.com/i, service: 'Sendinblue / Brevo', note: 'Marketing email' },
        { txtPattern: /include:constantcontact\.com/i,    service: 'Constant Contact',   note: 'Marketing email' },
        { txtPattern: /include:convertkit\.com/i,         service: 'ConvertKit',         note: 'Marketing email' },
        { txtPattern: /include:aweber\.com/i,             service: 'AWeber',             note: 'Marketing email' },
        { txtPattern: /include:campaignmonitor\.com/i,    service: 'Campaign Monitor',   note: 'Marketing email' },
        { txtPattern: /include:getresponse\.com/i,        service: 'GetResponse',        note: 'Marketing email' },
        { txtPattern: /include:activecampaign\.com|_spf\.activecampaign\.com/i, service: 'ActiveCampaign', note: 'Marketing / Automation' },
        { txtPattern: /include:customeriomail\.com/i,     service: 'Customer.io',        note: 'Transactional / Marketing' },
        { txtPattern: /include:intercom\.com/i,           service: 'Intercom',           note: 'Customer messaging' },
        { txtPattern: /include:ses\.amazonaws\.com/i,     service: 'Amazon SES (DKIM)',  note: 'Transactional email' },
    ];

    const COMMON_MAIL_SUBDOMAINS = [
        'mail', 'smtp', 'mx', 'mx1', 'mx2', 'mx3', 'email', 'imap',
        'pop3', 'pop', 'webmail', 'mailgate', 'relay', 'mta',
        'outbound', 'inbound', 'smtp-relay', 'mailserver',
        'exchange', 'owa', 'outlook', 'mailgw', 'mail-relay',
    ];

    const KNOWN_MODULES = [
        { id: 'mx_records',     label: 'MX Records' },
        { id: 'exchange',       label: 'Exchange Servers' },
        { id: 'svc_config',     label: 'Service Configurations' },
        { id: 'spf_flattening', label: 'SPF Flattening' },
        { id: 'breaches',       label: 'Email Breaches' },
        { id: 'mail_security',  label: 'Mail Security' },
        { id: 'ntlm',           label: 'NTLM' },
    ];

    const API_BASE      = 'http://127.0.0.1:30300';
    const DB_API_BASE   = 'http://127.0.0.1:30301';
    const POLL_INTERVAL = 2000;
    const POLL_TIMEOUT  = 1800000;

    let _domain     = '';
    let _scanning   = false;
    let _pollTimer  = null;
    let _pollStart  = 0;
    let _currentJob = null;
    let _aborted    = false;

    const $ = id => document.getElementById(id);

    function _esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function _displayValue(value, fallback = '—') {
        if (value === null || value === undefined || value === '') return fallback;
        if (typeof value === 'object') {
            try { return JSON.stringify(value); } catch (error) { return String(value); }
        }
        return String(value);
    }

    function _outputEl() { return document.querySelector('.ei-output-wrap'); }

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
        if (!el) return;
        el.innerHTML = '';
        const pre = document.createElement('pre');
        pre.style.cssText = 'margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:11px;line-height:1.6;';
        el.appendChild(pre);
    }

    function _setBtnState(running) {
        const scanBtn = $('ei-scan-btn');
        const stopBtn = $('ei-stop-btn');
        const loadBtn = $('ei-load-db-btn');
        if (scanBtn) {
            scanBtn.disabled = running;
            scanBtn.style.opacity = running ? '.5' : '1';
        }
        if (stopBtn) {
            stopBtn.disabled = !running;
            stopBtn.style.opacity = running ? '1' : '.4';
        }
        if (loadBtn) {
            loadBtn.disabled = running;
            loadBtn.style.opacity = running ? '.5' : '1';
        }
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

    function _setSidebarCompletion(completed) {
        const item  = document.querySelector('.nav-item[data-panel="panel-email-infra"]');
        const count = item?.querySelector('.nav-count');
        if (!count) return;
        count.textContent = completed ? '✓' : '--';
        count.classList.toggle('dns-enum-complete', completed);
        count.setAttribute('aria-label', completed ? 'Email Infrastructure completed' : 'Email Infrastructure not completed');
    }

    function _resetTracker() {
        const grid    = $('ei-tracker-grid');
        const tracker = $('ei-module-tracker');
        if (!grid || !tracker) return;
        tracker.classList.add('visible');
        grid.innerHTML = KNOWN_MODULES.map(m => `
            <div class="tracker-module" id="eit-${m.id}">
                <div class="tracker-dot"></div>
                <span class="tracker-module-name">${m.label}</span>
                <span class="tracker-check">✔</span>
            </div>`).join('');
        _updateTrackerCount(0);
    }

    function _updateTracker(done, status) {
        done.forEach(id => {
            const el = $(`eit-${id}`);
            if (el && !el.classList.contains('done')) el.classList.add('done');
        });
        KNOWN_MODULES.forEach(m => {
            const el = $(`eit-${m.id}`);
            if (!el) return;
            if (status === 'running' && !el.classList.contains('done'))
                el.classList.add('running');
            if (el.classList.contains('done'))
                el.classList.remove('running');
        });
        _updateTrackerCount(done.length);
    }

    function _updateTrackerCount(done) {
        const c = $('ei-tracker-count');
        if (c) c.textContent = `${done} / ${KNOWN_MODULES.length} completed`;
    }

    function _toast(msg, type) {
        if (typeof UI !== 'undefined' && UI.toast) { UI.toast(msg, type); }
        else { console.log(`[${type}] ${msg}`); }
    }

    function _renderTable(categoryId, rows, columns) {
        const tbody = $(`ei-table-${categoryId}`);
        const badge = $(`ei-badge-${categoryId}`);
        if (!tbody) return;
        if (badge) {
            badge.textContent = rows.length;
            badge.className = 'ei-badge ' + (rows.length ? 'ok' : 'dim');
        }
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="${columns || 4}" style="text-align:center;color:var(--text-dim);padding:24px;opacity:.6;">No results for this category.</td></tr>`;
            return;
        }
        tbody.innerHTML = rows.map(r => {
            return `<tr>${Object.values(r).map(v => `<td>${_esc(String(v || '—'))}</td>`).join('')}</tr>`;
        }).join('');
    }

    function _badge(val, okText, warnText, dangerText) {
        if (val === okText)     return `<span class="ei-badge ok">${_esc(val)}</span>`;
        if (val === warnText)   return `<span class="ei-badge warn">${_esc(val)}</span>`;
        if (val === dangerText) return `<span class="ei-badge danger">${_esc(val)}</span>`;
        return `<span class="ei-badge">${_esc(val || '—')}</span>`;
    }

    async function _resolveDNS(domain, type) {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
        try {
            const resp = await fetch(url);
            const data = await resp.json();
            return data.Answer || [];
        } catch (e) { return []; }
    }

    async function _resolveDNSCloudflare(domain, type) {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
        try {
            const resp = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
            const data = await resp.json();
            return data.Answer || [];
        } catch (e) { return []; }
    }

    async function _fetchTXTRecords(domain) {
        let answers = await _resolveDNS(domain, 'TXT');
        if (!answers.length) answers = await _resolveDNSCloudflare(domain, 'TXT');
        return answers.map(a => a.data.replace(/^"|"$/g, ''));
    }

    async function _resolveIP(hostname) {
        const answers = await _resolveDNS(hostname, 'A');
        return answers.length ? answers[0].data : '—';
    }

    async function _flattenSPF(record, depth, visited, allIPs, lookupCount) {
        if (depth > 10) return;
        const parts = record.split(/\s+/);
        for (const part of parts) {
            if (part.startsWith('include:') || part.startsWith('redirect=')) {
                const incDomain = part.replace(/^include:|^redirect=/, '');
                if (visited.has(incDomain)) continue;
                visited.add(incDomain);
                lookupCount.count++;
                const txts = await _fetchTXTRecords(incDomain);
                const spf = txts.find(t => t.startsWith('v=spf1'));
                if (spf) {
                    allIPs.push({ chain: incDomain, record: spf, depth });
                    await _flattenSPF(spf, depth + 1, visited, allIPs, lookupCount);
                }
            } else if (part.startsWith('ip4:') || part.startsWith('ip6:')) {
                allIPs.push({ chain: _domain, record: part, depth: 0 });
            } else if (part.startsWith('a:') || part.startsWith('mx:') || part === 'a' || part === 'mx') {
                lookupCount.count++;
            }
        }
    }

    function _riskBadge(level) {
        const text = _displayValue(level, '');
        const l = text.toUpperCase();
        const cls = l === 'HIGH' || l === 'CRITICAL' ? 'danger' : l === 'MEDIUM' ? 'warn' : l === 'LOW' || l === 'NONE' ? 'ok' : '';
        return `<span class="ei-badge ${cls}">${_esc(_displayValue(level))}</span>`;
    }

    function _statusBadge(val) {
        const text = _displayValue(val, '');
        const v = text.toLowerCase();
        const cls = v === 'open' || v === 'enforce' || v === 'reject' ? 'ok'
                  : v === 'closed' || v === 'none' || v === 'missing' ? 'danger'
                  : v === 'testing' || v === 'quarantine' || v === 'softfail' ? 'warn' : '';
        return `<span class="ei-badge ${cls}">${_esc(_displayValue(val))}</span>`;
    }

    const MS_RISK_COLOR = { high: '#e06a3b', medium: '#d09030', low: '#3ddc84', info: '#7a8a99' };
    const MS_RISK_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
    const MS_RISK_RANK  = { high: 0, medium: 1, low: 2, info: 3 };

    function _detectMxProvider(host) {
        const h = String(host || '').toLowerCase();
        const sig = PROVIDER_SIGNATURES.find(s => s.provider.indexOf('Self-Hosted') !== 0 && s.mxPattern.test(h));
        return sig ? sig.provider : 'Unidentified';
    }

    function _clearRedesignedViews() {
        const empties = {
            'ei-mx-strip':             '',
            'ei-mx-list':              '<div class="ei-empty">Run a scan to see MX records.</div>',
            'ei-ms-hero':              '',
            'ei-ms-grid':              '<div class="ei-empty">Run a scan to see mail security controls.</div>',
            'ei-ms-findings':          '',
            'ei-ms-dane':              '',
            'ei-exchange-list':        '<div class="ei-empty">Run a scan to see exchange servers.</div>',
            'ei-exchange-endpoint-list': '<div class="ei-empty">Run a scan to see Exchange endpoints.</div>',
            'ei-exchange-config-list': '<div class="ei-empty">Run a scan to see configuration endpoints.</div>',
            'ei-svc-smtp-body':        '<div class="ei-empty svc-empty">No SMTP data found.</div>',
            'ei-svc-imap-body':        '<div class="ei-empty svc-empty">No IMAP data found.</div>',
            'ei-svc-imaps-body':       '<div class="ei-empty svc-empty">No IMAPS data found.</div>',
            'ei-svc-pop3-body':        '<div class="ei-empty svc-empty">No POP3 data found.</div>',
            'ei-svc-pop3s-body':       '<div class="ei-empty svc-empty">No POP3S data found.</div>',
            'ei-svc-sieve-body':       '<div class="ei-empty svc-empty">No ManageSieve data found.</div>',
            'ei-spf-chain-list':       '<div class="ei-empty">Run a scan to see resolved IP ranges.</div>',
            'ei-breach-list':          '<div class="ei-empty">Run a scan to see breach data.</div>',
            'ei-ntlm-ep-list':         '<div class="ei-empty">No NTLM endpoints found.</div>',
            'ei-ntlm-disc-list':       '<div class="ei-empty">No disclosure information found.</div>',
            'ei-ntlm-vuln-list':       '<div class="ei-empty">No vulnerabilities found.</div>',
        };
        Object.keys(empties).forEach(id => {
            const el = $(id);
            if (el) el.innerHTML = empties[id];
        });
    }

    function _renderMxRecords(dnsSec) {
        const mx = ((dnsSec && dnsSec.mx_records) || []).slice()
            .sort((a, b) => (a.priority ?? 9999) - (b.priority ?? 9999));
        const probes = {};
        (((dnsSec && dnsSec.subdomain_takeover) || {}).mx_hosts || []).forEach(h => { probes[h.host] = h; });

        const uniqueIps = new Set();
        mx.forEach(r => (r.ips || []).forEach(ip => uniqueIps.add(ip)));
        const topPriority = mx.length ? mx[0].priority : null;

        const sumMx = $('ei-sum-mx');
        if (sumMx) sumMx.textContent = mx.length;
        const badge = $('ei-badge-mx-records');
        if (badge) {
            badge.textContent = mx.length;
            badge.className = 'ei-badge ' + (mx.length ? 'ok' : 'dim');
        }

        const strip = $('ei-mx-strip');
        if (strip) {
            strip.innerHTML = mx.length ? `
                <div class="mx-stat"><span class="mx-stat-label">MX Records</span><span class="mx-stat-value">${mx.length}</span></div>
                <div class="mx-stat"><span class="mx-stat-label">Unique IPs</span><span class="mx-stat-value">${uniqueIps.size}</span></div>
                <div class="mx-stat"><span class="mx-stat-label">Best Priority</span><span class="mx-stat-value">${_esc(String(topPriority ?? '—'))}</span></div>
            ` : '';
        }

        const list = $('ei-mx-list');
        if (!list) return;
        if (!mx.length) {
            list.innerHTML = '<div class="ei-empty">No MX records found for this domain.</div>';
            return;
        }

        list.innerHTML = mx.map(r => {
            const isPrimary = r.priority === topPriority;
            const probe     = probes[r.host] || null;
            const ips       = (r.ips || []).map(ip => `<span class="mx-ip">${_esc(ip)}</span>`).join('') || '<span class="mx-ip">—</span>';
            const chips     = [`<span class="mx-chip">${_esc(_detectMxProvider(r.host))}</span>`];
            if (probe && probe.smtp_reachable === true)  chips.push('<span class="mx-chip ok">SMTP reachable</span>');
            if (probe && probe.smtp_reachable === false) chips.push('<span class="mx-chip danger">SMTP unreachable</span>');
            if (probe && probe.takeover_risk && probe.takeover_risk !== 'none') {
                chips.push(`<span class="mx-chip danger">Takeover: ${_esc(probe.takeover_risk)}</span>`);
            }
            return `
            <div class="mx-card ${isPrimary ? 'primary' : ''}">
                <div class="mx-prio"><span>Priority</span><b>${_esc(String(r.priority ?? '—'))}</b></div>
                <div class="mx-main">
                    <div class="mx-host">${_esc(r.host || '—')}<span class="mx-role ${isPrimary ? 'primary' : ''}">${isPrimary ? 'Primary' : 'Backup'}</span></div>
                    <div class="mx-ips">${ips}</div>
                </div>
                <div class="mx-side">${chips.join('')}</div>
            </div>`;
        }).join('');
    }

    function _renderExchange(exchange, serviceConfig, providerGateways) {
        const portHosts = (serviceConfig && serviceConfig.port_scan && serviceConfig.port_scan.hosts) || [];
        const provider  = (providerGateways && providerGateways.email_provider && providerGateways.email_provider.name) || '—';
        const exchangeFindings = Array.isArray(exchange && exchange.findings) ? exchange.findings : [];
        const exchangeEndpoints = [];
        exchangeFindings.forEach(finding => {
            (Array.isArray(finding.exposed_urls) ? finding.exposed_urls : []).forEach(url => {
                const endpoint = String(url || '').trim();
                if (!endpoint) return;
                exchangeEndpoints.push({
                    endpoint,
                    source: finding.source || 'Exchange',
                    severity: finding.severity || '—',
                    domain: finding.domain || '—',
                });
            });
        });

        const serverList = $('ei-exchange-list');
        const activeHosts = portHosts.filter(h => (h.ports || []).some(p => p.open));
        if (serverList) {
            serverList.innerHTML = activeHosts.length
                ? activeHosts.map(h => {
                    const openChips   = (h.ports || []).filter(p => p.open).map(p =>
                        `<span class="mx-chip ok">${_esc(p.label || String(p.port))}</span>`).join('');
                    const closedChips = (h.ports || []).filter(p => !p.open).map(p =>
                        `<span class="mx-chip">${_esc(p.label || String(p.port))}</span>`).join('');
                    return `
                    <div class="ex-server-card">
                        <div class="ex-server-main">
                            <div class="ex-server-host">${_esc(h.host || '—')}</div>
                            <div class="ex-server-meta"><span class="mx-chip">${_esc(provider)}</span></div>
                        </div>
                        <div class="ex-server-ports">${openChips}${closedChips}</div>
                    </div>`;
                }).join('')
                : '<div class="ei-empty">No exchange servers detected.</div>';
        }

        const autodiscover = (serviceConfig && serviceConfig.autodiscover) || {};
        const autoconfig   = (serviceConfig && serviceConfig.autoconfig)   || {};
        const configItems  = [];
        (autodiscover.urls || []).forEach(u => {
            configItems.push({ service: 'Autodiscover', endpoint: u.url || '—', status: u.status || '—', notes: 'Exchange / M365' });
        });
        if (autoconfig.available) {
            configItems.push({ service: 'Autoconfig', endpoint: autoconfig.url || '—', status: 'found', notes: 'Mozilla / Thunderbird' });
        }

        const configList = $('ei-exchange-config-list');
        if (configList) {
            configList.innerHTML = configItems.length
                ? configItems.map(r => `
                    <div class="ex-config-row">
                        <span class="ex-config-service">${_esc(r.service)}</span>
                        <span class="ex-config-endpoint">${_esc(r.endpoint)}</span>
                        ${_statusBadge(r.status)}
                        <span class="ex-config-notes">${_esc(r.notes)}</span>
                    </div>`).join('')
                : '<div class="ei-empty">No configuration endpoints found.</div>';
        }

        const endpointList = $('ei-exchange-endpoint-list');
        if (endpointList) {
            endpointList.innerHTML = exchangeEndpoints.length
                ? exchangeEndpoints.map(item => `
                    <div class="ex-config-row">
                        <span class="ex-config-service">${_esc(item.source)}</span>
                        <span class="ex-config-endpoint">${_esc(item.endpoint)}</span>
                        ${_riskBadge(item.severity)}
                        <span class="ex-config-notes">${_esc(item.domain)}</span>
                    </div>`).join('')
                : '<div class="ei-empty">No Exchange endpoints found.</div>';
        }

        const badge = $('ei-badge-exchange');
        if (badge) {
            const total = activeHosts.length + exchangeEndpoints.length;
            badge.textContent = total;
            badge.className = 'ei-badge ' + (total ? 'ok' : 'dim');
        }
        const sumEx = $('ei-sum-exchange');
        if (sumEx) sumEx.textContent = exchangeEndpoints.length || activeHosts.length || '—';
    }

    function _renderSpfFlat(dnsSec) {
        const spf = (dnsSec && dnsSec.spf) || {};
        const depth = (dnsSec && dnsSec.spf_lookup_depth) || {};
        const rawEl = $('ei-spf-flat-raw');
        if (rawEl) rawEl.textContent = spf.record || '— No SPF record found';

        const tree  = depth.tree || {};
        const rows  = [];
        const walk  = (node, chain, d) => {
            Object.entries(node).forEach(([key, sub]) => {
                rows.push({ chain: chain || key, cidr: key, lookups: d, exceeded: !!depth.exceeded });
                walk(sub, key, d + 1);
            });
        };
        walk(tree, '', 0);

        const chainList = $('ei-spf-chain-list');
        if (chainList) {
            chainList.innerHTML = rows.length
                ? rows.map(r => `
                    <div class="spf-chain-item">
                        <span class="spf-chain-domain">${_esc(r.chain || '—')}</span>
                        <span class="spf-chain-arrow">→</span>
                        <span class="spf-chain-ip">${_esc(r.cidr)}</span>
                        <span class="spf-chain-depth">Depth ${_esc(String(r.lookups))}</span>
                        <span class="ei-badge ${r.exceeded ? 'warn' : 'ok'}">${r.exceeded ? 'Exceeded' : 'OK'}</span>
                    </div>`).join('')
                : '<div class="ei-empty">No IP ranges resolved.</div>';
        }

        const analysis = $('ei-spf-flat-analysis');
        if (analysis) {
            const count    = depth.effective_lookup_count ?? '—';
            const exceeded = depth.exceeded;
            const color    = exceeded ? '#c07820' : 'var(--accent)';
            analysis.innerHTML = `<div style="font-size:12px;color:${color};padding:6px 0;">Effective DNS lookups: <b>${count} / 10</b>${exceeded ? ' — limit exceeded' : ''}</div>`;
        }
        const badge = $('ei-badge-spf-flat');
        if (badge) { badge.textContent = rows.length; badge.className = 'ei-badge ' + (rows.length ? 'ok' : 'dim'); }
        const sumSpf = $('ei-sum-spf-flat');
        if (sumSpf) sumSpf.textContent = (depth.effective_lookup_count ?? '—') + ' / 10';
    }

    function _renderBreaches(breaches) {
        const findings = (breaches && breaches.findings) || [];
        const list     = $('ei-breach-list');
        const badge    = $('ei-badge-email-breaches');
        const sumB     = $('ei-sum-breaches');

        if (!list) return;

        if (!findings.length) {
            list.innerHTML = '<div class="ei-empty">No breach data found for this domain.</div>';
            if (badge) { badge.textContent = '0'; badge.className = 'ei-badge dim'; }
            if (sumB) sumB.textContent = '0';
            return;
        }

        list.innerHTML = findings.map(f => {
            const dataClasses = Array.isArray(f.data_classes) ? f.data_classes : [];
            const dataChips   = dataClasses.map(d => `<span class="breach-data-chip">${_esc(d)}</span>`).join('');
            const comboLine   = !dataClasses.length ? (f.combo_line || '') : '';
            const records     = f.pwn_count != null ? Number(f.pwn_count).toLocaleString() : '—';
            return `
            <div class="breach-card">
                <div class="breach-card-head">
                    <span class="breach-name">${_esc(f.breach_name || f.breach_title || f.source || '—')}</span>
                    <span class="breach-date">${_esc(f.breach_date || '—')}</span>
                </div>
                <div class="breach-target">${_esc(f.email || f.domain || '—')}</div>
                ${dataChips ? `<div class="breach-data">${dataChips}</div>` : ''}
                ${comboLine ? `<div class="breach-combo">${_esc(comboLine)}</div>` : ''}
                <div class="breach-records"><em>Records affected:</em> ${_esc(records)}</div>
            </div>`;
        }).join('');

        if (badge) { badge.textContent = findings.length; badge.className = 'ei-badge ' + (findings.length ? 'ok' : 'dim'); }
        if (sumB) sumB.textContent = findings.length;
    }

    function _msCardHtml(c) {
        const meta = (c.meta || [])
            .map(m => `<span class="ms-meta-item"><em>${_esc(m[0])}</em>${_esc(String(m[1]))}</span>`)
            .join('');
        const value = c.value
            ? `<div class="ms-card-value">${_esc(c.value)}</div>`
            : '<div class="ms-card-value ms-card-value-empty">Not published</div>';
        return `
        <div class="ms-card ms-risk-${c.risk}">
            <div class="ms-card-head">
                <span class="ms-dot"></span>
                <span class="ms-card-title">${_esc(c.title)}</span>
                <span class="ms-status">${_esc(c.status)}</span>
            </div>
            ${value}
            ${meta ? `<div class="ms-meta">${meta}</div>` : ''}
            <div class="ms-card-foot">
                <span class="ms-risk-tag">${MS_RISK_LABEL[c.risk]} risk</span>
                ${c.note ? `<span class="ms-note">${_esc(c.note)}</span>` : ''}
            </div>
        </div>`;
    }

    function _msBuildCards(d) {
        const spf   = d.spf || {};
        const dkim  = d.dkim || {};
        const dks   = d.dkim_key_strength || {};
        const dmarc = d.dmarc || {};
        const mta   = d.mta_sts || {};
        const dane  = d.dane || {};
        const bimi  = d.bimi || {};
        const caa   = d.caa || {};
        const rpt   = d.tls_rpt || {};
        const depth = d.spf_lookup_depth || {};
        const take  = d.subdomain_takeover || {};
        const cards = [];

        const q = String(spf.all_qualifier || '').toLowerCase();
        let spfRisk = 'high', spfStatus = 'Missing';
        if (spf.record) {
            if (q === 'fail')          { spfRisk = 'low';    spfStatus = 'Hard fail (-all)'; }
            else if (q === 'softfail') { spfRisk = 'medium'; spfStatus = 'Soft fail (~all)'; }
            else                       { spfRisk = 'high';   spfStatus = q ? 'Permissive' : 'No all mechanism'; }
        }
        if (depth.exceeded && spfRisk === 'low') spfRisk = 'medium';
        cards.push({
            title: 'SPF', risk: spfRisk, status: spfStatus, value: spf.record || '',
            meta: [
                ['Includes', spf.include_count ?? 0],
                ['Lookups', `${depth.effective_lookup_count ?? '—'}/${depth.limit ?? 10}`],
            ],
            issues: [].concat(spf.issues || [], depth.issues || []),
        });

        const selectors = dkim.found_selectors || [];
        const strengths = dks.selectors || {};
        const weak = Object.keys(strengths).filter(k => strengths[k].strength === 'weak');
        const dkimLines = selectors.map(s => {
            const info = strengths[s];
            return info ? `${s} · ${String(info.key_type || '').toUpperCase()} ${info.key_bits || '?'}-bit (${info.strength})${info.revoked ? ' · revoked' : ''}` : s;
        });
        cards.push({
            title: 'DKIM',
            risk: !selectors.length ? 'high' : weak.length ? 'medium' : 'low',
            status: selectors.length ? (weak.length ? 'Weak keys' : 'Present') : 'Missing',
            value: dkimLines.join('\n'),
            meta: [['Selectors', selectors.length], ['Weak', weak.length], ['Revoked', Object.keys(strengths).filter(k => strengths[k].revoked).length]],
            issues: [].concat(dkim.issues || [], dks.issues || []),
        });

        const pol = String(dmarc.policy || '').toLowerCase();
        cards.push({
            title: 'DMARC',
            risk: !dmarc.record ? 'high' : pol === 'reject' ? 'low' : pol === 'quarantine' ? 'medium' : 'high',
            status: dmarc.record ? `p=${pol || 'none'}` : 'Missing',
            value: dmarc.record || '',
            meta: [
                ['Pct', dmarc.pct ?? '—'],
                ['Subdomain', dmarc.subdomain_policy || '—'],
                ['RUA', (dmarc.rua || []).length],
                ['RUF', (dmarc.ruf || []).length],
            ],
            issues: dmarc.issues || [],
        });

        cards.push({
            title: 'MTA-STS',
            risk: mta.mode === 'enforce' ? 'low' : mta.mode ? 'medium' : 'high',
            status: mta.mode ? mta.mode : 'Missing',
            value: mta.policy_file || mta.txt_record || '',
            meta: mta.mode ? [['Max age', mta.max_age ?? '—'], ['MX covered', (mta.mx_covered || []).length]] : [],
            issues: mta.issues || [],
        });

        const daneHosts = dane.mx_dane || [];
        const daneOn = daneHosts.filter(x => x.dane_enabled).length;
        cards.push({
            title: 'DANE / TLSA',
            risk: daneOn === daneHosts.length && daneHosts.length ? 'low' : 'medium',
            status: daneHosts.length ? `${daneOn}/${daneHosts.length} hosts` : 'Not checked',
            value: daneHosts.map(h => `${h.tlsa_name || h.host} · ${h.dane_enabled ? `${(h.records || []).length} TLSA` : 'no TLSA'}`).join('\n'),
            meta: [],
            issues: dane.issues || [],
        });

        cards.push({
            title: 'TLS-RPT',
            risk: rpt.record ? 'low' : 'info',
            status: rpt.record ? 'Present' : 'Missing',
            value: rpt.record || '',
            meta: [],
            issues: rpt.issues || [],
        });

        cards.push({
            title: 'BIMI',
            risk: bimi.record ? 'low' : 'info',
            status: bimi.record ? 'Present' : 'Missing',
            value: bimi.record || '',
            meta: bimi.record ? [['Logo', bimi.logo_url ? 'yes' : 'no'], ['VMC', bimi.vmc_url ? 'yes' : 'no']] : [],
            issues: bimi.issues || [],
        });

        const caaRecords = caa.records || [];
        cards.push({
            title: 'CAA',
            risk: caaRecords.length ? 'low' : 'medium',
            status: caaRecords.length ? `${caaRecords.length} records` : 'Missing',
            value: caaRecords.map(r => `${r.tag} ${r.value}${r.flags ? ` (flags ${r.flags})` : ''}`).join('\n'),
            meta: caaRecords.length ? [['Issuers', (caa.issuers || []).length], ['Wildcard', (caa.issue_wildcard || []).length], ['IODEF', (caa.iodef || []).length]] : [],
            issues: caa.issues || [],
        });

        const nullMx = d.null_mx || {};
        cards.push({
            title: 'Null MX',
            risk: nullMx.applicable && !nullMx.null_mx_present ? 'medium' : 'info',
            status: nullMx.null_mx_present ? 'Present' : (nullMx.applicable ? 'Not set' : 'Not applicable'),
            value: '',
            meta: [['Applicable', nullMx.applicable ? 'yes' : 'no'], ['Present', nullMx.null_mx_present ? 'yes' : 'no']],
            issues: nullMx.issues || [],
        });

        const takeHosts = take.mx_hosts || [];
        if (takeHosts.length) {
            const risky = takeHosts.filter(h => h.takeover_risk && h.takeover_risk !== 'none');
            cards.push({
                title: 'MX Takeover',
                risk: risky.length ? 'high' : 'low',
                status: risky.length ? `${risky.length} at risk` : 'No risk',
                value: takeHosts.map(h => `${h.host} → ${(h.a_records || []).join(', ') || 'no A record'} · ${h.known_provider || 'no known provider'} · ${h.takeover_risk || 'unknown'}`).join('\n'),
                meta: [['Hosts', takeHosts.length], ['Reachable', takeHosts.filter(h => h.smtp_reachable).length]],
                issues: take.issues || [],
            });
        }

        return cards;
    }

    function _renderMailSecurity(dnsSec) {
        const d     = dnsSec || {};
        const risk  = d.spoofing_risk || {};
        const cards = _msBuildCards(d);

        const grid = $('ei-ms-grid');
        if (grid) grid.innerHTML = cards.map(_msCardHtml).join('');

        const badge = $('ei-badge-mail-security');
        if (badge) { badge.textContent = cards.length; badge.className = 'ei-badge ok'; }

        const level = _displayValue(risk.level, '').toUpperCase();
        const levelRisk = (level === 'HIGH' || level === 'CRITICAL') ? 'high' : level === 'MEDIUM' ? 'medium' : 'low';
        const score = Number(risk.score);
        const counts = { high: 0, medium: 0, low: 0 };
        cards.forEach(c => { if (counts[c.risk] !== undefined) counts[c.risk]++; });

        const hero = $('ei-ms-hero');
        if (hero) {
            hero.innerHTML = `
                <div class="ms-hero-ring" style="--p:${isNaN(score) ? 0 : Math.min(score, 100)};--rc:${MS_RISK_COLOR[levelRisk]}">
                    <div class="ms-hero-ring-inner"><b>${isNaN(score) ? '—' : score}</b><span>/100</span></div>
                </div>
                <div class="ms-hero-info">
                    <div class="ms-hero-title">Email Spoofing Risk</div>
                    <div class="ms-hero-level" style="color:${MS_RISK_COLOR[levelRisk]}">${_esc(level || 'UNKNOWN')}</div>
                    <div class="ms-hero-sub">Based on SPF, DKIM and DMARC alignment and policy strength.</div>
                </div>
                <div class="ms-hero-counts">
                    <div class="ms-count ms-risk-high"><b>${counts.high}</b><span>High</span></div>
                    <div class="ms-count ms-risk-medium"><b>${counts.medium}</b><span>Medium</span></div>
                    <div class="ms-count ms-risk-low"><b>${counts.low}</b><span>Passed</span></div>
                </div>`;
        }

        const findings = [];
        cards.forEach(c => (c.issues || []).forEach(text => findings.push({ ctl: c.title, risk: c.risk === 'low' ? 'info' : c.risk, text })));
        findings.sort((a, b) => MS_RISK_RANK[a.risk] - MS_RISK_RANK[b.risk]);
        const fEl = $('ei-ms-findings');
        if (fEl) {
            fEl.innerHTML = findings.length
                ? findings.map(f => `
                    <div class="ms-finding ms-risk-${f.risk}">
                        <span class="ms-finding-risk">${MS_RISK_LABEL[f.risk]}</span>
                        <span class="ms-finding-ctl">${_esc(f.ctl)}</span>
                        <span class="ms-finding-text">${_esc(f.text)}</span>
                    </div>`).join('')
                : '<div class="ei-empty">No findings reported.</div>';
        }

        const dEl = $('ei-ms-dane');
        if (dEl) {
            const hosts = (d.dane && d.dane.mx_dane) || [];
            dEl.innerHTML = hosts.length
                ? hosts.map(h => {
                    const recs = (h.records || []).map(r =>
                        `<span class="mx-chip accent">U${_esc(String(r.usage ?? '?'))} · S${_esc(String(r.selector ?? '?'))} · M${_esc(String(r.matching_type ?? '?'))}</span>`
                    ).join('');
                    return `
                    <div class="ms-dane-row">
                        <span class="ms-dane-name">${_esc(h.tlsa_name || h.host || '—')}</span>
                        <span class="ms-dane-detail">${recs || '<span class="mx-chip danger">No TLSA record</span>'}</span>
                    </div>`;
                }).join('')
                : '<div class="ei-empty">No DANE data available.</div>';
        }

        const sumSec = $('ei-sum-security');
        if (sumSec) sumSec.innerHTML = _riskBadge(risk.level) + ` <span style="font-size:11px;opacity:.6;">${isNaN(score) ? '—' : score}/100</span>`;
    }

    function _renderSvcConfig(svcConfig, svcDetails) {
        const SERVICES = [
            { key: 'smtp',  bodyId: 'ei-svc-smtp-body',  ports: [25, 465, 587], type: 'standard' },
            { key: 'imap',  bodyId: 'ei-svc-imap-body',  ports: [143],          type: 'standard' },
            { key: 'imaps', bodyId: 'ei-svc-imaps-body', ports: [993],          type: 'tls'      },
            { key: 'pop3',  bodyId: 'ei-svc-pop3-body',  ports: [110],          type: 'standard' },
            { key: 'pop3s', bodyId: 'ei-svc-pop3s-body', ports: [995],          type: 'tls'      },
            { key: 'sieve', bodyId: 'ei-svc-sieve-body', ports: [4190, 2000],   type: 'sieve'    },
        ];

        const portScan = (svcConfig && svcConfig.port_scan && svcConfig.port_scan.hosts) || [];
        const portMap  = { smtp: 25, imap: 143, imaps: 993, pop3: 110, pop3s: 995, sieve: 4190 };
        let totalRows  = 0;

        function _svcStatusChip(open) {
            return open
                ? '<span class="mx-chip ok">Open</span>'
                : '<span class="mx-chip danger">Closed</span>';
        }

        function _svcRow(host, port, type, detail, portInfo) {
            const open = portInfo ? portInfo.open : (detail && detail.status === 'open');
            if (type === 'tls') {
                const tls    = (detail && detail.tls_version) || '—';
                const cipher = (detail && detail.cipher)      || '—';
                const cn     = (detail && detail.cert_cn)     || '—';
                const expiry = (detail && detail.cert_expiry) || '—';
                return `
                <div class="svc-host-row">
                    <div class="svc-host-left">
                        <span class="svc-host-name">${_esc(host)}</span>
                        <div class="svc-host-chips">
                            <span class="mx-chip">Port ${_esc(String(port))}</span>
                            ${tls !== '—' ? `<span class="mx-chip accent">${_esc(tls)}</span>` : ''}
                            ${_svcStatusChip(open)}
                        </div>
                    </div>
                    <div class="svc-detail-row">
                        ${cn     !== '—' ? `<span class="svc-kv"><em>CN</em>${_esc(cn)}</span>`         : ''}
                        ${cipher !== '—' ? `<span class="svc-kv"><em>Cipher</em>${_esc(cipher)}</span>` : ''}
                        ${expiry !== '—' ? `<span class="svc-kv"><em>Expiry</em>${_esc(expiry)}</span>` : ''}
                    </div>
                </div>`;
            }
            if (type === 'sieve') {
                const tls  = (detail && detail.tls)            || '—';
                const caps = (detail && detail.capabilities)   || '—';
                const sasl = (detail && detail.sasl)           || '—';
                const impl = (detail && detail.implementation) || '—';
                return `
                <div class="svc-host-row">
                    <div class="svc-host-left">
                        <span class="svc-host-name">${_esc(host)}</span>
                        <div class="svc-host-chips">
                            <span class="mx-chip">Port ${_esc(String(port))}</span>
                            ${tls !== '—' ? `<span class="mx-chip accent">${_esc(tls)}</span>` : ''}
                            ${_svcStatusChip(open)}
                        </div>
                    </div>
                    <div class="svc-detail-row">
                        ${impl !== '—' ? `<span class="svc-kv"><em>Impl</em>${_esc(impl)}</span>`   : ''}
                        ${sasl !== '—' ? `<span class="svc-kv"><em>SASL</em>${_esc(sasl)}</span>`   : ''}
                        ${caps !== '—' ? `<span class="svc-kv"><em>Caps</em>${_esc(caps)}</span>`   : ''}
                    </div>
                </div>`;
            }
            const tls    = (detail && detail.tls)          || '—';
            const auth   = (detail && detail.auth_methods) || '—';
            const banner = (detail && detail.banner)       || (portInfo && portInfo.label) || '—';
            const stls   = detail && detail.starttls != null ? detail.starttls : null;
            const stChip = stls === true  ? '<span class="mx-chip ok">STARTTLS</span>'
                         : stls === false ? '<span class="mx-chip">No STARTTLS</span>' : '';
            return `
            <div class="svc-host-row">
                <div class="svc-host-left">
                    <span class="svc-host-name">${_esc(host)}</span>
                    <div class="svc-host-chips">
                        <span class="mx-chip">Port ${_esc(String(port))}</span>
                        ${tls !== '—' ? `<span class="mx-chip accent">${_esc(tls)}</span>` : ''}
                        ${stChip}
                        ${_svcStatusChip(open)}
                    </div>
                </div>
                <div class="svc-detail-row">
                    ${auth   !== '—' ? `<span class="svc-kv"><em>Auth</em>${_esc(auth)}</span>`     : ''}
                    ${banner !== '—' ? `<span class="svc-kv"><em>Banner</em>${_esc(banner)}</span>` : ''}
                </div>
            </div>`;
        }

        SERVICES.forEach(({ key, bodyId, ports, type }) => {
            const body   = $(bodyId);
            if (!body) return;
            const detail = (svcDetails && svcDetails[key]) || null;
            const rows   = [];

            portScan.forEach(hostObj => {
                ports.forEach(p => {
                    const portInfo = (hostObj.ports || []).find(x => x.port === p);
                    if (!portInfo) return;
                    rows.push(_svcRow(hostObj.host || '—', p, type, detail, portInfo));
                });
            });

            if (detail && !rows.length) {
                rows.push(_svcRow(detail.host || '—', detail.port || portMap[key], type, detail, null));
            }

            body.innerHTML = rows.length
                ? rows.join('')
                : '<div class="ei-empty svc-empty">No data found.</div>';
            totalRows += rows.length;
        });

        const badge = $('ei-badge-svc-config');
        if (badge) { badge.textContent = totalRows; badge.className = 'ei-badge ' + (totalRows ? 'ok' : ''); }
    }

    function _renderNtlm(ntlm) {
        const findings = Array.isArray(ntlm.findings) ? ntlm.findings : [];
        const summaryEndpoints = Array.isArray(ntlm.summary && ntlm.summary.endpoints)
            ? ntlm.summary.endpoints
            : [];
        const endpointSource = findings.length ? findings : summaryEndpoints;
        const endpoints = endpointSource.map(f => ({
            url: f.url || f.endpoint || '—',
            method: f.method || f.source || '—',
            status: f.status || f.http_status || '—',
            auth_header: f.auth_header || f.www_authenticate || '',
            notes: f.path ? `Path: ${f.path}` : (f.notes || ''),
        }));
        const epList    = $('ei-ntlm-ep-list');
        if (epList) {
            epList.innerHTML = endpoints.length
                ? endpoints.map(e => `
                    <div class="ntlm-ep-row">
                        <div class="ntlm-ep-main">
                            <div class="ntlm-url">${_esc(e.url || '—')}</div>
                            ${e.notes ? `<div class="ntlm-note">${_esc(e.notes)}</div>` : ''}
                        </div>
                        <div class="ntlm-ep-chips">
                            <span class="mx-chip">${_esc(e.method || '—')}</span>
                            ${_statusBadge(e.status || '—')}
                            ${e.auth_header ? `<span class="mx-chip accent">${_esc(e.auth_header)}</span>` : ''}
                        </div>
                    </div>`).join('')
                : '<div class="ei-empty">No NTLM endpoints found.</div>';
        }

        const disclosure = [];
        const disclosureValues = new Set();
        const addDisclosure = item => {
            const value = _displayValue(item.value);
            const key = value.trim().toLowerCase();
            if (disclosureValues.has(key)) return;
            disclosureValues.add(key);
            disclosure.push({ ...item, value });
        };
        findings.forEach(f => {
            Object.entries(f.disclosures || {}).forEach(([field, value]) => {
                addDisclosure({
                    field,
                    value,
                    source: f.url || f.source || '—',
                    risk: f.severity || 'info',
                });
            });
        });
        if (!disclosure.length && Array.isArray(ntlm.disclosure)) {
            ntlm.disclosure.forEach(addDisclosure);
        }
        const discList   = $('ei-ntlm-disc-list');
        if (discList) {
            discList.innerHTML = disclosure.length
                ? disclosure.map(d => `
                    <div class="ntlm-disc-row">
                        <span class="ntlm-field">${_esc(d.field || '—')}</span>
                        <span class="ntlm-value">${_esc(d.value)}</span>
                        <span class="ntlm-source">${_esc(d.source || '—')}</span>
                        ${_riskBadge(d.risk || '—')}
                    </div>`).join('')
                : '<div class="ei-empty">No disclosure information found.</div>';
        }

        const vulnerabilities = [];
        Object.values((ntlm.summary && ntlm.summary.builds) || {}).forEach(build => {
            (build.cves || []).forEach(cve => {
                vulnerabilities.push({
                    ...cve,
                    cve: cve.cve || cve.id,
                    description: cve.description || cve.title,
                    component: build.label || build.build || 'Exchange',
                    recommendation: build.is_latest === false ? `Update from build ${build.build || 'the detected build'}.` : '',
                });
            });
        });
        vulnerabilities.push(...(ntlm.vulnerabilities || []));
        const vulns = vulnerabilities.slice().sort((a, b) => {
            const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
            const sa    = order[_displayValue(a.severity, '').toUpperCase()] ?? 99;
            const sb    = order[_displayValue(b.severity, '').toUpperCase()] ?? 99;
            if (sa !== sb) return sa - sb;
            return (parseFloat(b.cvss) || 0) - (parseFloat(a.cvss) || 0);
        });
        const vulnList = $('ei-ntlm-vuln-list');
        if (vulnList) {
            vulnList.innerHTML = vulns.length
                ? vulns.map(v => {
                    const sev = _displayValue(v.severity, '').toUpperCase();
                    const rc  = sev === 'CRITICAL' || sev === 'HIGH' ? '#e06a3b'
                              : sev === 'MEDIUM'                     ? '#d09030'
                              : sev === 'LOW'                        ? '#3ddc84' : '#7a8a99';
                    return `
                    <div class="ntlm-vuln-card" style="--rc:${rc}">
                        <div class="ntlm-vuln-head">
                            <a href="https://nvd.nist.gov/vuln/detail/${_esc(v.cve)}" target="_blank" rel="noopener" class="ntlm-cve">${_esc(v.cve || '—')}</a>
                            ${_riskBadge(v.severity)}
                            ${v.cvss      ? `<span class="ntlm-cvss">CVSS ${_esc(String(v.cvss))}</span>` : ''}
                            ${v.component ? `<span class="ntlm-component">${_esc(v.component)}</span>`      : ''}
                        </div>
                        ${v.description    ? `<div class="ntlm-vuln-desc">${_esc(v.description)}</div>` : ''}
                        ${v.recommendation ? `<div class="ntlm-vuln-rec"><em>Recommendation:</em> ${_esc(v.recommendation)}</div>` : ''}
                    </div>`;
                }).join('')
                : '<div class="ei-empty">No vulnerabilities found.</div>';
        }

        const total = endpoints.length + disclosure.length + vulns.length;
        const badge = $('ei-badge-ntlm');
        if (badge) { badge.textContent = total; badge.className = 'ei-badge ' + (total ? 'ok' : ''); }
    }

    function _decodeStoredValues(value) {
        if (Array.isArray(value)) return value.map(_decodeStoredValues);
        if (!value || typeof value !== 'object') {
            if (typeof value === 'string') {
                const trimmed = value.trim();
                if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
                    (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
                    try { return _decodeStoredValues(JSON.parse(trimmed)); } catch (error) { return value; }
                }
            }
            return value;
        }
        return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, _decodeStoredValues(item)]));
    }

    function _renderResults(data) {
        const domainKey  = Object.keys(data.results || {})[0] || '';
        const modules    = _decodeStoredValues((data.results && data.results[domainKey]) || {});
        const dnsSec     = modules.dns_sec        || {};
        const svcConfig  = modules.service_config || {};
        const providers  = modules.provider_gateways || {};
        const breaches   = modules.breaches       || {};

        const merged = Object.assign({}, dnsSec);

        _renderMxRecords(merged);
        _renderExchange(modules.exchange || {}, svcConfig, providers);
        _renderSvcConfig(svcConfig, modules.service_details || {});
        _renderSpfFlat(merged);
        _renderBreaches(breaches);
        _renderMailSecurity(merged);
        _renderNtlm(modules.ntlm || {});

        const summary = $('ei-summary');
        if (summary) summary.style.display = '';
    }

    async function _fetchAndRenderFromDB(domain) {
        try {
            const summaryResp = await fetch(`${DB_API_BASE}/api/email/summary`);
            if (!summaryResp.ok) throw new Error(`/api/email/summary: ${summaryResp.status}`);
            const summaryData = await summaryResp.json().catch(() => ({}));
            if (!summaryData.success) throw new Error(summaryData.error || 'No email data found');

            const loadedDomain = summaryData.scan?.target || domain || '';
            const targetEl = $('ei-target');
            if (targetEl && loadedDomain) targetEl.value = loadedDomain;
            _domain = loadedDomain;
            _renderResults(summaryData);

            _appendLabeled('DATABASE', 'Results loaded and rendered', OUT_GREEN);
            window.markPanelComplete?.('panel-email-infra', 'Email Infrastructure');
            return true;
        } catch (err) {
            window.reportDatabaseUnavailable?.(_appendLabeled, _toast);
            return false;
        }
    }

    async function _loadFromDatabase() {
        if (_scanning) return;
        _clearOutput();
        const loaded = await _fetchAndRenderFromDB(($('ei-target') || {}).value || '');
        if (loaded) {
            _setSidebarCompletion(true);
            _openDefaultView();
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
            const resp = await fetch(`${API_BASE}/api/email/job/${jobId}`);
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

            const status = data.status;
            _updateTracker(data.modules_done || [], status);

            if (data.stderr) {
                const el = _outputEl();
                const pre = _outputPre();
                if (el && pre) {
                    const shown   = parseInt(pre.dataset.shownLen || '0');
                    const newText = data.stderr.slice(shown);
                    if (newText) {
                        newText.split('\n').forEach(line => {
                            if (!line) return;
                            const span = document.createElement('span');
                            span.style.color = line.includes('✔') ? 'var(--green)'
                                             : line.includes('✘') ? '#c07820'
                                             : line.includes('⚠') ? '#d09030'
                                             : 'var(--text-sec)';
                            span.textContent = line + '\n';
                            pre.appendChild(span);
                        });
                        pre.dataset.shownLen = String(data.stderr.length);
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
                _toast(`Email infrastructure scan complete: ${_domain}`, 'ok');
                _onScanEnd();
                return;
            }

            if (status === 'error') {
                const rc  = data.returncode != null ? ` (exit code ${data.returncode})` : '';
                const msg = data.stderr
                    ? data.stderr
                    : `Script exited with no output${rc}. Check that email_infra.py exists and all dependencies are installed.`;
                _appendScanResult(false, msg);
                if (data.returncode != null && data.returncode !== 0)
                    _appendLabeled('EXIT CODE', String(data.returncode), OUT_RED);
                _toast('Email infrastructure scan ended with an error', 'error');
                _onScanEnd();
                return;
            }

            _pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);
        } catch (err) {
            _appendScanResult(false, `Poll error: ${err.message}`);
            _onScanEnd();
        }
    }

    async function scan(targetDomain) {
        if (_scanning) return;

        const targetEl = $('ei-target');
        const tfTarget = document.getElementById('tf-target');

        if (targetEl && tfTarget && !targetEl.value.trim() && tfTarget.value.trim())
            targetEl.value = tfTarget.value.trim();

        const raw = targetDomain || (targetEl ? targetEl.value : '');
        if (!raw.trim()) { _toast('Please enter a target domain', 'warn'); return; }

        _domain   = raw.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
        _scanning = true;
        _aborted  = false;
        _setBtnState(true);
        _clearOutput();
        _resetTracker();
        _setSidebarCompletion(false);
        _clearRedesignedViews();
        $('ei-summary').style.display = 'none';

        _appendLabeled('TARGET', _domain, OUT_GREEN);

        try {
            const tResp = await fetch(`${API_BASE}/api/target/set`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ url: `https://${_domain}` }),
            });
            const tData = await tResp.json().catch(() => ({}));
            if (!tResp.ok || !tData.success) throw new Error(tData.error || `target/set: ${tResp.status}`);

            const nsEl      = $('ei-input-nameserver');
            const nsVal     = nsEl ? nsEl.value.trim() || null : null;
            const activeBtn = document.querySelector('#ei-threads-group .dns-thread-btn-active');
            const threads   = activeBtn ? parseInt(activeBtn.dataset.val) : 3;

            const scanPayload = {};
            if (nsVal)   scanPayload.nameserver = nsVal;
            if (threads) scanPayload.threads    = threads;
            const optOn = id => $(id)?.checked === true;
            scanPayload.mail_dns_security  = optOn('ei-opt-dns-security');
            scanPayload.service_scanner    = optOn('ei-opt-service-scanner');
            scanPayload.exchange_endpoints = optOn('ei-opt-exchange');
            scanPayload.ntlm               = optOn('ei-opt-ntlm');

            const sResp = await fetch(`${API_BASE}/api/email/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify(scanPayload),
            });
            const sData = await sResp.json().catch(() => ({}));
            if (!sResp.ok || !sData.success) throw new Error(sData.error || `email/scan: ${sResp.status}`);

            _currentJob = sData.job_id;
            _pollStart  = Date.now();
            if (sData.cmd) _appendLabeled('COMMAND', sData.cmd, OUT_GREEN);
            _appendLabeled('JOB ID', _currentJob, OUT_GREEN);

            _pollTimer = setTimeout(() => _poll(_currentJob), POLL_INTERVAL);

        } catch (err) {
            _appendScanResult(false, err.message);
            _toast(`Error: ${err.message}`, 'error');
            _onScanEnd();
        }
    }

    function stopScan() {
        if (!_scanning) return;
        _aborted = true;
        _stopPolling();
        _appendScanResult(false, 'Stopped by user.');
        _toast('Scan stopped', 'warn');
        _onScanEnd();
    }

    function _openDefaultView() {
        const bar = $('ei-subtab-bar');
        const firstBtn = bar && bar.querySelector('.tls-subtab-btn[data-subtab]');
        if (!firstBtn) return;
        const cat = firstBtn.getAttribute('data-subtab');
        bar.querySelectorAll('.tls-subtab-btn').forEach(b => b.classList.remove('active'));
        firstBtn.classList.add('active');
        document.querySelectorAll('#ei-results .ei-section').forEach(sec => {
            sec.classList.toggle('active', sec.getAttribute('data-category') === cat);
        });
        document.querySelectorAll('#panel-email-infra .dns-section.collapsed').forEach(sec => sec.classList.remove('collapsed'));
    }

    function init() {
        const scanBtn = $('ei-scan-btn');
        if (scanBtn) scanBtn.addEventListener('click', () => {
            scan(($('ei-target') || {}).value || '');
        });

        const stopBtn = $('ei-stop-btn');
        if (stopBtn) stopBtn.addEventListener('click', stopScan);

        const resetBtn = $('ei-reset-btn');
        if (resetBtn) resetBtn.addEventListener('click', () => {
            if (_scanning) return;
            const targetEl = $('ei-target');
            const nsEl     = $('ei-input-nameserver');
            if (targetEl) targetEl.value = '';
            if (nsEl)     nsEl.value     = '';
            _clearOutput();
            const outEl = _outputEl();
            if (outEl) outEl.innerHTML = '<span class="ei-output-placeholder">// Output will appear here when scan is running...</span>';
            $('ei-summary').style.display = 'none';
            document.querySelectorAll('#ei-results .ei-table tbody').forEach(tb => { tb.innerHTML = ''; });
            document.querySelectorAll('.ei-badge').forEach(b => { b.textContent = '0'; b.className = 'ei-badge'; });
            const spfRaw = $('ei-spf-flat-raw');
            if (spfRaw) spfRaw.innerHTML = '<span class="ei-placeholder">// Resolved flat SPF record will appear here</span>';
            _clearRedesignedViews();
            const eiThreadGroup = $('ei-threads-group');
            if (eiThreadGroup) {
                eiThreadGroup.querySelectorAll('.dns-thread-btn').forEach(b => b.classList.remove('dns-thread-btn-active'));
                const defaultBtn = eiThreadGroup.querySelector('.dns-thread-btn[data-val="3"]');
                if (defaultBtn) defaultBtn.classList.add('dns-thread-btn-active');
            }
            const optDefaults = {
                'ei-opt-dns-security':    true,
                'ei-opt-service-scanner': true,
                'ei-opt-exchange':        true,
                'ei-opt-ntlm':            false,
            };
            Object.keys(optDefaults).forEach(id => { const el = $(id); if (el) el.checked = optDefaults[id]; });
            _setSidebarCompletion(false);
            _openDefaultView();
        });

        const loadBtn = $('ei-load-db-btn');
        if (loadBtn) loadBtn.addEventListener('click', _loadFromDatabase);

        const eiThreadGroup = $('ei-threads-group');
        if (eiThreadGroup) {
            eiThreadGroup.querySelectorAll('.dns-thread-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    eiThreadGroup.querySelectorAll('.dns-thread-btn').forEach(b => b.classList.remove('dns-thread-btn-active'));
                    btn.classList.add('dns-thread-btn-active');
                });
            });
        }

        const eiSubtabBar = $('ei-subtab-bar');
        if (eiSubtabBar) {
            eiSubtabBar.addEventListener('click', (e) => {
                const btn = e.target.closest('.tls-subtab-btn');
                if (!btn) return;
                const cat = btn.getAttribute('data-subtab');
                if (!cat) return;
                eiSubtabBar.querySelectorAll('.tls-subtab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                document.querySelectorAll('#ei-results .ei-section').forEach(s => {
                    s.classList.toggle('active', s.getAttribute('data-category') === cat);
                });
            });
        }

        $('ei-target')?.addEventListener('keydown', e => {
            if (e.key === 'Enter') scan(e.target.value);
        });

        _setBtnState(false);
        _openDefaultView();
    }

    return { init, scan, stopScan };
})();