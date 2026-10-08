const Social = (() => {
  'use strict';

  let _state = {
    status: 'IDLE',
    raw: null
  };

  const UI = {};

  const PLATFORM_SIGNATURES = {
    linkedin:   { patterns: [/linkedin\.com\/(company|in|school)\/[a-z0-9\-]+/i, /linkedin\.com/i],                           color: '#0a66c2', label: 'LinkedIn'    },
    twitter:    { patterns: [/twitter\.com\/[a-z0-9_]+/i, /x\.com\/[a-z0-9_]+/i],                                             color: '#1da1f2', label: 'X / Twitter' },
    github:     { patterns: [/github\.com\/[a-z0-9\-]+/i],                                                                    color: '#c9d1d9', label: 'GitHub'      },
    facebook:   { patterns: [/facebook\.com\/(company|pages|people|profile\.php)/i, /facebook\.com\/[a-z0-9\.]+/i, /fb\.com\//i], color: '#1877f2', label: 'Facebook'   },
    instagram:  { patterns: [/instagram\.com\/[a-z0-9_\.]+/i],                                                                color: '#e4405f', label: 'Instagram'   },
    youtube:    { patterns: [/youtube\.com\/(channel|c|user)\/[a-z0-9\-]+/i, /youtu\.be\//i],                                 color: '#ff0000', label: 'YouTube'     },
    telegram:   { patterns: [/t\.me\/[a-z0-9_]+/i],                                                                           color: '#26a5e4', label: 'Telegram'    },
    medium:     { patterns: [/medium\.com\/@?[a-z0-9\-]+/i],                                                                  color: '#00ab6c', label: 'Medium'      },
    crunchbase: { patterns: [/crunchbase\.com\/(organization|company)\/[a-z0-9\-]+/i],                                        color: '#0a66c2', label: 'Crunchbase'  },
    glassdoor:  { patterns: [/glassdoor\.com\/(Overview|Reviews)\/[a-z0-9\-]+/i],                                             color: '#0caa41', label: 'Glassdoor'   }
  };

  const SEVERITY_CLASS = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };

  const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

  const CRITICAL_PATTERNS = [
    ['Credentials', 'critical', 'Password assignment', /\b\w{0,30}(?:pass(?:word|wd)?|pwd)\s*[:=]\s*\S+/gi],
    ['Credentials', 'medium', 'Username assignment', /\b(?:username|user(?:name)?|login)\s*[:=]\s*\S+/gi],
    ['Credentials', 'high', 'Default credentials', /\b(?:admin\s*[:\/]\s*(?:admin|password|1234\d*)|root\s*[:\/]\s*(?:root|toor|password)|test\s*[:\/]\s*test)\b/gi],
    ['Credentials', 'critical', 'Credentials inside URL', /https?:\/\/[^\s\/:@]+:[^\s\/@]+@[^\s]+/gi],
    ['Credentials', 'high', 'Basic auth header', /\bBasic\s+[A-Za-z0-9+\/]{8,}={0,2}/g],
    ['Credentials', 'critical', 'Bearer token', /\bBearer\s+[A-Za-z0-9\-._~+\/]{16,}=*/gi],
    ['Credentials', 'critical', 'JSON Web Token', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}/g],
    ['Credentials', 'critical', 'Client secret assignment', /\b\w{0,30}(?:client[_-]?secret|app[_-]?secret|secret(?:[_-]?key)?)\s*[:=]\s*\S+/gi],
    ['Credentials', 'critical', 'API key assignment', /\b\w{0,30}api[_-]?key\s*[:=]\s*\S+/gi],
    ['Credentials', 'critical', 'Token assignment', /\b\w{0,30}(?:access|auth|refresh|session|csrf|xsrf|id)[_-]?token\s*[:=]\s*\S+/gi],
    ['Credentials', 'critical', 'Private key block', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g],
    ['Credentials', 'medium', 'Certificate block', /-----BEGIN (?:CERTIFICATE|PUBLIC KEY|CERTIFICATE REQUEST)-----/g],
    ['Credentials', 'medium', 'SSH public key', /\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+\/=]{20,}/g],
    ['Credentials', 'critical', 'Passphrase assignment', /\bpass(?:phrase|code)\s*[:=]\s*\S+/gi],
    ['Credentials', 'medium', 'Credentials mention', /\b(?:credentials?|creds)\b/gi],
    ['Credentials', 'low', 'MD5-length hex string', /\b[a-f0-9]{32}\b/gi],
    ['Credentials', 'low', 'SHA-1-length hex string', /\b[a-f0-9]{40}\b/gi],
    ['Credentials', 'medium', 'SHA-256-length hex string', /\b[a-f0-9]{64}\b/gi],
    ['Credentials', 'critical', 'Bcrypt hash', /\$2[abxy]\$\d{2}\$[A-Za-z0-9.\/]{53}/g],
    ['Credentials', 'high', 'OTP or PIN value', /\b(?:otp|pin|passcode|verification[_ -]?code)\s*[:=]\s*\d{4,8}\b/gi],

    ['API Keys', 'critical', 'AWS access key ID', /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b/g],
    ['API Keys', 'critical', 'AWS secret key', /\baws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*\S+/gi],
    ['API Keys', 'critical', 'Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/g],
    ['API Keys', 'medium', 'Google OAuth client ID', /\b\d{6,}-[a-z0-9]{20,}\.apps\.googleusercontent\.com\b/gi],
    ['API Keys', 'critical', 'GitHub token', /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g],
    ['API Keys', 'critical', 'GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g],
    ['API Keys', 'critical', 'GitLab token', /\bglpat-[A-Za-z0-9_\-]{16,}\b/g],
    ['API Keys', 'critical', 'Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g],
    ['API Keys', 'critical', 'Slack webhook', /hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/gi],
    ['API Keys', 'critical', 'Discord webhook', /discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/gi],
    ['API Keys', 'critical', 'Stripe live key', /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g],
    ['API Keys', 'medium', 'Stripe test key', /\b[sp]k_test_[A-Za-z0-9]{16,}\b/g],
    ['API Keys', 'high', 'Twilio account SID', /\bAC[a-f0-9]{32}\b/g],
    ['API Keys', 'critical', 'SendGrid API key', /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g],
    ['API Keys', 'high', 'Mailgun API key', /\bkey-[a-f0-9]{32}\b/g],
    ['API Keys', 'high', 'Mailchimp API key', /\b[a-f0-9]{32}-us\d{1,2}\b/g],
    ['API Keys', 'high', 'Facebook access token', /\bEAA[A-Za-z0-9]{20,}\b/g],
    ['API Keys', 'critical', 'Telegram bot token', /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g],
    ['API Keys', 'critical', 'Azure storage connection string', /\bDefaultEndpointsProtocol=https?;[^\s]*AccountKey=[^\s;]+/gi],
    ['API Keys', 'high', 'Signed URL signature', /[?&]sig=[A-Za-z0-9%]{20,}/g],
    ['API Keys', 'medium', 'Firebase database URL', /\b[a-z0-9-]+\.firebaseio\.com\b/gi],
    ['API Keys', 'medium', 'S3 bucket reference', /\b[a-z0-9.-]{1,63}\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b|\bs3:\/\/[a-z0-9._-]{1,63}/gi],
    ['API Keys', 'medium', 'Sentry DSN', /https?:\/\/[a-f0-9]{16,}@[\w.-]*sentry[\w.-]*\/\d+/gi],
    ['API Keys', 'critical', 'npm access token', /\bnpm_[A-Za-z0-9]{30,}\b/g],
    ['API Keys', 'low', 'UUID value', /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi],
    ['API Keys', 'low', 'Long token-like string', /\b(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{40,}={0,2}/g],
    ['API Keys', 'medium', 'Mapbox token', /\bpk\.eyJ[A-Za-z0-9._-]{20,}/g],
    ['API Keys', 'high', 'Secret in URL query', /[?&](?:key|apikey|api_key|token|access_token|auth|signature|secret)=[^&\s"']{6,}/gi],
    ['API Keys', 'critical', 'DigitalOcean token', /\bdop_v1_[a-f0-9]{64}\b/g],
    ['API Keys', 'critical', 'Shopify token', /\bshp(?:at|ss|ca|pa)_[a-f0-9]{32}\b/g],

    ['Infrastructure', 'high', 'Private IP (10.0.0.0/8)', /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g],
    ['Infrastructure', 'high', 'Private IP (172.16.0.0/12)', /\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g],
    ['Infrastructure', 'high', 'Private IP (192.168.0.0/16)', /\b192\.168\.\d{1,3}\.\d{1,3}\b/g],
    ['Infrastructure', 'medium', 'Localhost reference', /\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d{2,5})?\b/gi],
    ['Infrastructure', 'medium', 'Public IPv4 address', /\b(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g],
    ['Infrastructure', 'medium', 'IPv6 address', /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi],
    ['Infrastructure', 'high', 'Internal hostname', /\b[\w-]+\.(?:internal|local|lan|corp|intranet|private|home|localdomain)\b/gi],
    ['Infrastructure', 'medium', 'Staging or dev hostname', /\b(?:dev|staging|stage|stg|uat|qa|test|preprod|sandbox|beta)[\w-]*\.[\w.-]+\.[a-z]{2,}\b/gi],
    ['Infrastructure', 'medium', 'Non-standard port URL', /https?:\/\/[^\s\/:]+:(?!80\b|443\b)\d{2,5}\b/gi],
    ['Infrastructure', 'high', 'Admin panel path', /\/(?:admin|administrator|wp-admin|phpmyadmin|adminer|cpanel|manager\/html)\b/gi],
    ['Infrastructure', 'high', 'Internal or debug path', /\/(?:internal|private|debug|_internal|_debug)\/[\w\/.-]*/gi],
    ['Infrastructure', 'high', 'Backup or dump file', /\b[\w.-]{1,80}\.(?:bak|old|orig|save|swp|backup|tmp|sql|dump|tar\.gz|zip|7z|rar)\b/gi],
    ['Infrastructure', 'high', 'Sensitive config file', /(?:\.env(?:\.\w+)?|\.ht(?:access|passwd)|\.git(?:config|ignore)?|\.npmrc|\.aws\/credentials)\b|\b(?:web\.config|wp-config\.php|config\.(?:php|json|ya?ml|ini|xml)|settings\.py|application\.(?:properties|ya?ml)|docker-compose\.ya?ml|Dockerfile|id_rsa)\b/g],
    ['Infrastructure', 'high', 'Windows file path', /\b[A-Za-z]:\\(?:[\w.$ -]+\\)*[\w.$-]*/g],
    ['Infrastructure', 'high', 'UNC network path', /\\\\[\w.-]+\\[\w$.\\-]+/g],
    ['Infrastructure', 'high', 'Unix system path', /\/(?:etc|var|usr|opt|srv|mnt|proc|sbin|root)\/[\w.\/-]+/g, true],
    ['Infrastructure', 'high', 'User profile path', /(?:\bC:\\Users\\|\/Users\/|\/home\/)[\w.-]+/gi],
    ['Infrastructure', 'medium', 'Git or SSH remote', /\bgit@[\w.-]+:[\w.\/-]+\.git\b|\bssh:\/\/[^\s]+/gi],
    ['Infrastructure', 'medium', 'Source repository URL', /https?:\/\/(?:github|gitlab|bitbucket)\.(?:com|org)\/[\w.-]+\/[\w.-]+/gi],
    ['Infrastructure', 'low', 'Ticket reference', /\b(?:JIRA|TICKET|ISSUE|BUG|TASK|SEC|VULN)-\d+\b/gi],
    ['Infrastructure', 'low', 'DevOps tooling mention', /\b(?:kubernetes|k8s|kubectl|docker|helm|terraform|ansible|jenkins|kubeconfig)\b/gi],
    ['Infrastructure', 'critical', 'Database connection string', /\b(?:mysql|mysqli|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql|jdbc:[a-z]+|sqlserver):\/\/[^\s]+/gi],
    ['Infrastructure', 'high', 'SQL statement', /\b(?:SELECT\s[^\n]{1,120}?\sFROM\s|INSERT\s+INTO\s|UPDATE\s+\w+\s+SET\s|DELETE\s+FROM\s|DROP\s+TABLE\s|CREATE\s+TABLE\s|ALTER\s+TABLE\s)/gi],
    ['Infrastructure', 'high', 'Database setting', /\b(?:db|database|mysql|pg|postgres|mongo|redis)[_-]?(?:host|user|name|pass(?:word)?|port|url|uri)\s*[:=]\s*\S+/gi],
    ['Infrastructure', 'low', 'Database table reference', /\b(?:tbl_|tb_)\w+\b|\bschema\.\w+\b/gi],
    ['Infrastructure', 'medium', 'Mail server host', /\b(?:smtp|imap|pop3)[\w.-]*\.[a-z]{2,}(?::\d+)?\b/gi],
    ['Infrastructure', 'high', 'LDAP reference', /\bldaps?:\/\/[^\s]+|\b(?:cn|ou|dc)=[\w. -]+(?:,\s*(?:cn|ou|dc)=[\w. -]+)+/gi],
    ['Infrastructure', 'high', 'FTP URL', /\b(?:s?ftp|ftps):\/\/[^\s]+/gi],
    ['Infrastructure', 'medium', 'Remote access reference', /\b(?:VPN|RDP|SSH|Telnet|VNC|bastion|jump\s?host)\b/gi],
    ['Infrastructure', 'medium', 'Software version disclosure', /\b(?:Apache|nginx|IIS|Tomcat|PHP|Node(?:\.js)?|Python|Ruby|Django|Laravel|Rails|WordPress|Drupal|Joomla|jQuery|Spring|Express|OpenSSL)\/?\s*v?\d+(?:\.\d+){1,3}\b/gi],

    ['Development', 'medium', 'TODO or FIXME marker', /\b(?:TODO|FIXME|XXX|HACK|KLUDGE|WORKAROUND)\b/g],
    ['Development', 'medium', 'Debug artifact', /\b(?:debug(?:ging)?|stack\s?trace|console\.log|var_dump|print_r|phpinfo)\b/gi],
    ['Development', 'high', 'Remove before production', /\b(?:remove|delete|disable|hide)\b[^\n]{0,30}\b(?:before|in|for)\s+(?:prod(?:uction)?|release|launch|deploy(?:ment)?|go[- ]live)\b/gi],
    ['Development', 'high', 'Test or demo account', /\b(?:test|demo|dummy|temp(?:orary)?|guest)\s+(?:user|account|login|credentials?|password)\b/gi],
    ['Development', 'medium', 'Hardcoded value', /\bhard[- ]?cod(?:ed|e|ing)\b/gi],
    ['Development', 'high', 'Security bypass', /\b(?:bypass|backdoor|skip\s+(?:auth|validation|check|verification)|disable\s+(?:auth|security|csrf|ssl|tls|validation|verification)|insecure|no[- ]auth)\b/gi],
    ['Development', 'high', 'Vulnerability keyword', /\b(?:vulnerab\w*|exploit\w*|injection|xss|csrf|ssrf|rce|lfi|rfi|idor|cve-\d{4}-\d{4,7}|security\s+(?:hole|issue|flaw|bug|risk))\b/gi],
    ['Development', 'low', 'Deprecated or legacy code', /\b(?:deprecated|legacy|obsolete|old\s+(?:api|endpoint|version|login|admin))\b/gi],
    ['Development', 'high', 'Hidden feature reference', /\b(?:feature[_ -]?flag|hidden\s+(?:feature|page|field|endpoint|menu|link)|secret\s+(?:page|url|link|endpoint|menu)|easter\s?egg|undocumented|unlisted|not\s+for\s+(?:public|production|release))\b/gi],
    ['Development', 'high', 'Confidentiality marker', /\b(?:internal(?:\s+use)?\s+only|confidential|proprietary|classified|do\s+not\s+(?:share|distribute|publish|commit|delete|remove|touch)|restricted|top\s+secret)\b/gi],

    ['Personal Data', 'medium', 'Author attribution', /\b(?:written|created|modified|updated|maintained|authored|developed|coded)\s+by\s+[A-Z][\w.-]+(?:\s+[A-Z][\w.-]+)?/g],
    ['Personal Data', 'high', 'Email address', /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}\b/g],
    ['Personal Data', 'medium', 'Phone number', /\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\w)/g, true],
    ['Personal Data', 'critical', 'Payment card number', /\b(?:\d{4}[ -]?){3}\d{4}\b/g],
    ['Personal Data', 'high', 'SSN-like identifier', /\b\d{3}-\d{2}-\d{4}\b/g],
    ['Personal Data', 'high', 'IBAN', /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b/g],
    ['Personal Data', 'low', 'Geo coordinates', /-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}(?![\d.])/g, true],
    ['Commented-out Code', 'medium', 'Commented-out script or form', /<(?:script|form|iframe|object|embed)\b[^>]*>?/gi],
    ['Development', 'medium', 'Inactive or disabled feature note', /\b(?:(?:not|no longer|currently|temporarily)\s+(?:active|in use|used|enabled)|disabled|deactivated|inactive|turned off|switched off|unused)\b/gi],
    ['Commented-out Code', 'high', 'Hidden input field', /<input[^>]+type\s*=\s*["']?hidden["']?[^>]*>/gi]
  ].map(([category, severity, label, rx, standalone], i) => ({
    id: i + 1,
    category,
    severity,
    label,
    rx,
    standalone: !!standalone
  }));

  let _cmtModels = [];
  let _cmtFilter = 'all';

  function _openDefaultView() {
    const root = document.getElementById('panel-social-media') || document;
    root.querySelectorAll('.tls-sub-panel').forEach(p => p.classList.remove('active'));
    root.querySelectorAll('#social-subtab-bar .tls-subtab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('social-sub-presence')?.classList.add('active');
    document.querySelector('#social-subtab-bar .tls-subtab-btn[data-socialtab="social-sub-presence"]')?.classList.add('active');
    ['sec-social-target-params', 'sec-soc-summary', 'sec-soc-profiles'].forEach(id => {
      document.getElementById(id)?.classList.remove('collapsed');
    });
  }

  function init() {
    _bindEvents();
    _openDefaultView();
  }

  function _ensureUI() {
    _cacheUI();
  }

  function _cacheUI() {
    [
      'social-scan-btn', 'social-stop-btn', 'social-reset-btn', 'social-export-btn', 'social-scan-info',
      'social-input-domain', 'social-input-intercept', 'social-intercept-hint',
      'social-subtab-bar',
      'soc-summary-badge', 'soc-prof-count', 'soc-platform-count', 'soc-high-conf', 'soc-low-conf',
      'soc-profiles-badge', 'soc-profiles-body',
      'email-summary-badge', 'email-total', 'email-unique-domains', 'email-personal', 'email-sources',
      'email-results-badge', 'email-results-body',
      'htmlmeta-summary-badge', 'htmlmeta-meta-tags', 'htmlmeta-og-tags', 'htmlmeta-twitter-tags', 'htmlmeta-sensitive',
      'htmlmeta-standard-badge', 'htmlmeta-standard-body',
      'htmlmeta-og-badge', 'og-title', 'og-desc', 'og-image', 'og-url', 'og-type', 'og-sitename', 'og-locale', 'og-fbapp',
      'htmlmeta-twitter-badge', 'tw-card', 'tw-site', 'tw-creator', 'tw-title', 'tw-desc', 'tw-image', 'tw-domain',
      'htmlmeta-leak-badge', 'leak-generator', 'leak-author', 'leak-email', 'leak-paths', 'leak-comments', 'leak-versions',
      'htmlmeta-httpequiv-badge', 'htmlmeta-httpequiv-rows',
      'htmlmeta-comments-badge', 'htmlmeta-comments-rows',
      'doc-summary-badge', 'doc-total', 'doc-key-count', 'doc-cat-count', 'doc-ext-count', 'doc-requests', 'doc-bodies',
      'doc-key-badge', 'doc-key-grid', 'doc-cat-badge', 'doc-cat-grid', 'doc-ext-grid',
      'doc-files-badge', 'doc-pills', 'doc-search', 'doc-count', 'doc-table-body', 'doc-copy-btn', 'doc-export-btn'
    ].forEach(id => { UI[id] = document.getElementById(id); });
  }

  function _bindEvents() {
    document.addEventListener('click', function(e) {
      if (e.target.closest('#social-target-params-head')) {
        document.getElementById('sec-social-target-params')?.classList.toggle('collapsed');
        return;
      }

      if (e.target.closest('#social-browse-btn')) {
        document.getElementById('social-intercept-file')?.click();
        return;
      }

      if (e.target.closest('#social-scan-btn'))   { _ensureUI(); startScan();        return; }
      if (e.target.closest('#social-stop-btn'))   { _ensureUI(); stopScan();         return; }
      if (e.target.closest('#social-reset-btn'))  { _ensureUI(); resetAll();         return; }
      if (e.target.closest('#social-load-db-btn')) {
        const loadDbBtn = e.target.closest('#social-load-db-btn');
        loadDbBtn.disabled = true;
        _fetchAndRenderFromDB(document.getElementById('social-input-domain')?.value.trim() || '')
          .finally(() => { loadDbBtn.disabled = false; });
        return;
      }
      if (e.target.closest('#social-export-btn')) { _ensureUI(); exportData();       return; }
      if (e.target.closest('#doc-copy-btn'))      { _ensureUI(); _copyDocUrls();     return; }
      if (e.target.closest('#doc-export-btn'))    { _ensureUI(); exportDocuments();  return; }

      var subtabBtn = e.target.closest('#social-subtab-bar .tls-subtab-btn');
      if (subtabBtn) {
        var tabId = subtabBtn.getAttribute('data-socialtab');
        if (!tabId) return;
        var root = subtabBtn.closest('#panel-social-media') || document;
        root.querySelectorAll('.tls-sub-panel').forEach(function(p) { p.classList.remove('active'); });
        root.querySelectorAll('#social-subtab-bar .tls-subtab-btn').forEach(function(b) { b.classList.remove('active'); });
        document.getElementById(tabId)?.classList.add('active');
        subtabBtn.classList.add('active');
        return;
      }

      var pill = e.target.closest('.filter-pill');
      if (!pill) return;
      pill.parentElement.querySelectorAll('.filter-pill').forEach(function(p) { p.classList.remove('active'); });
      pill.classList.add('active');
      var socFilter   = pill.getAttribute('data-soc-filter');
      var emailFilter = pill.getAttribute('data-email-filter');
      var docFilter   = pill.getAttribute('data-doc-filter');
      if (socFilter)    _filterProfiles(socFilter);
      if (emailFilter)  _filterEmails(emailFilter);
      if (docFilter !== null) { _ensureUI(); _docFilter = docFilter; _renderDocTable(); }
    });

    document.addEventListener('input', function(e) {
      var id = e.target && e.target.id;
      if (id === 'doc-search') {
        _ensureUI();
        _docQuery = e.target.value.trim().toLowerCase();
        _renderDocTable();
      } else if (id === 'social-input-intercept') {
        _ensureUI();
        var v = e.target.value.trim();
        if (_pickedFile && v !== (_pickedFile.path || _pickedFile.name)) _pickedFile = null;
        _validateIntercept();
      }
    });

    document.addEventListener('change', function(e) {
      if (e.target && e.target.id === 'social-intercept-file') {
        _ensureUI();
        var f = e.target.files && e.target.files[0];
        if (f) _onInterceptPicked(f);
        e.target.value = '';
      }
    });
  }

  const CONN_BASE = window.SOCIAL_CONN_BASE || 'http://127.0.0.1:30300';
  const API_BASE  = window.SOCIAL_API_BASE  || 'http://127.0.0.1:30301';

  const POLL_INTERVAL = 2000;
  const POLL_TIMEOUT  = 1800000;

  let _pollTimer  = null;
  let _pollStart  = 0;
  let _currentJob = null;
  let _aborted    = false;
  let _lastStderr = '';
  let _pickedFile = null;

  const OUT_GREEN = '#3ddc84';
  const OUT_RED   = '#ff4d4d';
  const OUT_VALUE = '#d4d4d4';

  function _outputEl() { return document.getElementById('social-output-wrap'); }

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

  const INTERCEPT_EXT_RX = /\.(json|jsonl)$/i;
  const INTERCEPT_HINT   = 'Path to a captured traffic log used for offline file discovery';

  function _formatSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  function _setHint(text, cls) {
    const el = UI['social-intercept-hint'];
    if (!el) return;
    el.textContent = text;
    el.className = 'soc-field-hint' + (cls ? ' ' + cls : '');
  }

  function _validateIntercept() {
    const v = (UI['social-input-intercept']?.value || '').trim();
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
    if (UI['social-input-intercept']) UI['social-input-intercept'].value = file.path || file.name;
    _validateIntercept();
  }

  function _collectInputs() {
    const domain    = (UI['social-input-domain']?.value?.trim() || '');
    const intercept = (UI['social-input-intercept']?.value?.trim() || '');
    return { domain, intercept };
  }

  function _buildTargetPayload(vals) {
    if (!vals.domain) return null;
    const url = vals.domain.startsWith('http') ? vals.domain : `https://${vals.domain}`;
    return { url };
  }

  function _setBtnState(scanning) {
    const scanningHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="animation:spin 1s linear infinite">
               <circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6"
                       stroke-dasharray="10 6" stroke-linecap="round"/>
             </svg> Scanning…`;
    const idleHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none">
               <circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.4"/>
               <path d="M11 11l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
             </svg> Start`;
    if (UI['social-scan-btn']) {
      UI['social-scan-btn'].disabled      = scanning;
      UI['social-scan-btn'].style.opacity = scanning ? '0.55' : '';
      UI['social-scan-btn'].innerHTML     = scanning ? scanningHTML : idleHTML;
    }
    if (UI['social-stop-btn']) UI['social-stop-btn'].disabled = !scanning;
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
      const resp = await fetch(`${CONN_BASE}/api/social/job/${jobId}`);
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(data.error || `Status error: ${resp.status}`);

      const status = data.status;

      if (data.stderr) {
        _lastStderr = data.stderr;
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
          _appendScanResult(false, 'Database is not ready. database-manager.py may have failed or is missing.');
          _setInfo('Scan failed: database not ready');
          _onScanEnd();
          return;
        }

        _appendScanResult(true, data.output_file || 'Completed');
        await _fetchAndRenderFromDB(data.domain);
        window.markPanelComplete?.('panel-social-media', 'Social & Metadata');
        _onScanEnd();
        return;
      }

      if (status === 'error') {
        _appendScanResult(false, data.stderr || 'unknown error');
        _setInfo(`Scan error — check output console`);
        _onScanEnd();
        return;
      }

      _pollTimer = setTimeout(() => _poll(jobId), POLL_INTERVAL);

    } catch (err) {
      _appendScanResult(false, `Poll error: ${err.message}`);
      _setInfo(`Poll error: ${err.message}`);
      _onScanEnd();
    }
  }

  async function _fetchAndRenderFromDB(domain) {
    try {
      const normaliseTarget = value => {
        const raw = String(value || '').trim().toLowerCase();
        try { return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname; }
        catch (_) { return raw.replace(/^https?:\/\//, '').split('/')[0]; }
      };
      const scansResp = await fetch(`${API_BASE}/api/scans`);
      if (!scansResp.ok) throw new Error(`scans: ${scansResp.status}`);
      const scansData = await scansResp.json().catch(() => ({}));
      const socialScan = (scansData.scans || []).find(scan =>
        String(scan.source_file || '').toLowerCase().includes('social') &&
        (!domain || normaliseTarget(scan.target) === normaliseTarget(domain))
      );
      const query = socialScan ? `?scan_id=${encodeURIComponent(socialScan.id)}` : '';
      const resp = await fetch(`${API_BASE}/api/social/summary${query}`);
      if (!resp.ok) {
        const e = await resp.json().catch(() => ({}));
        throw new Error(e.error || `HTTP ${resp.status}`);
      }
      const json = await resp.json();
      if (!json.success) throw new Error(json.error || 'API returned success=false');
      loadFromAPI(json);
      _appendLabeled('DATABASE', 'Results loaded and rendered', OUT_GREEN);
      window.markPanelComplete?.('panel-social-media', 'Social & Metadata');
      return true;
    } catch (err) {
      window.reportDatabaseUnavailable?.(_appendLabeled, UI?.toast);
      _setInfo('Database results unavailable');
      return false;
    }
  }

  function _onScanEnd() {
    _stopPolling();
    _setStatus('IDLE');
    _aborted    = false;
    _currentJob = null;
    _setBtnState(false);
  }

  async function startScan() {
    _ensureUI();
    const vals          = _collectInputs();
    const targetPayload = _buildTargetPayload(vals);

    if (!targetPayload) {
      _setInfo('Please enter a domain or target URL.');
      return;
    }
    if (!_validateIntercept()) {
      _setInfo('Intercept log must be a .json or .jsonl file.');
      return;
    }

    _setStatus('RUNNING');
    _setBtnState(true);
    _aborted = false;
    _lastStderr = '';
    _clearOutput();
    _renderDocuments({ items: [], meta: { requests: null, bodies: null } });

    if (!document.getElementById('_social_sc_style')) {
      const s = document.createElement('style');
      s.id = '_social_sc_style';
      s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
      document.head.appendChild(s);
    }

    const domain = vals.domain;
    _appendLabeled('TARGET', domain, OUT_GREEN);
    const previewCmd = `python social_metadata.py${vals.intercept ? ' --intercept ' + vals.intercept : ''} --json --all -d ${domain}`;
    _setInfo('Registering target…');

    try {
      const tResp = await fetch(`${CONN_BASE}/api/target/set`, {
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
      const sResp = await fetch(`${CONN_BASE}/api/social/scan`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(scanPayload),
      });
      const sData = await sResp.json().catch(() => ({}));
      if (!sResp.ok || !sData.success) throw new Error(sData.error || `social/scan: ${sResp.status}`);

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
      _onScanEnd();
    }
  }

  function stopScan() {
    _ensureUI();
    if (_currentJob) {
      _aborted = true;
      _appendScanResult(false, 'Stopped by user.');
    }
    _setStatus('IDLE');
    _setBtnState(false);
    _setInfo('Stopped.');
  }

  function resetAll() {
    _ensureUI();
    if (_currentJob) _aborted = true;
    _currentJob = null;
    _stopPolling();
    _setStatus('IDLE');
    _setBtnState(false);
    _clearOutput();

    _state.raw = null;
    _pickedFile = null;

    _docFilter = 'all';
    _docQuery  = '';
    if (UI['doc-search']) UI['doc-search'].value = '';

    document.querySelectorAll('.filter-pill[data-soc-filter]').forEach(p => p.classList.remove('active'));
    document.querySelector('.filter-pill[data-soc-filter="all"]')?.classList.add('active');
    document.querySelectorAll('.filter-pill[data-email-filter]').forEach(p => p.classList.remove('active'));
    document.querySelector('.filter-pill[data-email-filter="all"]')?.classList.add('active');

    _renderSocial([]);
    _renderEmails([]);
    _renderHtmlMeta([]);
    _renderDocuments({ items: [], meta: { requests: null, bodies: null } });

    _setInfo('No scan data — enter a target, optionally an intercept log, and click Start');
    _openDefaultView();
  }

  function loadFromAPI(apiResp) {
    _state.raw = apiResp;

    const profileRows  = (apiResp.profiles?.rows  || []).map(r => ({
      url:      r.url,
      source:   r.source,
      platform: r.platform,
    }));

    const emailRows    = (apiResp.emails?.rows    || []).map(r => ({
      email:    r.address,
      source:   r.source,
      context:  r.context,
      verified: !!r.verified,
    }));

    const metaRows     = (apiResp.html_meta?.rows || []).map(r => ({
      source: r.source,
      name:   r.name,
      value:  r.value,
    }));

    _renderSocial(profileRows);
    _renderEmails(emailRows);
    _renderHtmlMeta(metaRows);

    const docRows   = apiResp.documents?.rows || [];
    const logParsed = _parseDocsFromLog(_lastStderr);
    _renderDocuments({
      items: _normalizeDocs(docRows.length ? docRows : logParsed.items),
      meta: {
        requests: apiResp.documents?.requests_scanned ?? logParsed.meta.requests,
        bodies:   apiResp.documents?.bodies_scanned   ?? logParsed.meta.bodies
      }
    });

    _setStatus('IDLE');
    const scan  = apiResp.scan || {};
    const target = scan.target || '';
    const ts     = (scan.timestamp || '').slice(0, 10);
    _setInfo(`Loaded — ${target}${ts ? ' | ' + ts : ''}`);
  }

  function loadFromJSON(json) {
    _state.raw = json;
    const results = json.results || {};

    _renderSocial(results.social || []);
    _renderEmails(results.emails || []);
    _renderHtmlMeta(results.html_meta || []);
    _renderDocuments({ items: _normalizeDocs(results.documents || []), meta: { requests: null, bodies: null } });

    _setStatus('IDLE');
    const target = json.meta?.target || '';
    _setInfo(`Loaded — ${target} | ${json.meta?.generated_at?.slice(0, 10) || ''}`);
  }

  function _setStatus(s) { _state.status = s; }
  function _setInfo(t) { if (UI['social-scan-info']) UI['social-scan-info'].textContent = t; }
  function _setText(id, v) {
    const el = UI[id];
    if (!el) return;
    el.textContent = v ?? '—';
    if (el.classList.contains('dcr-val')) {
      el.classList.toggle('dim', v == null || v === '—' || v === 'None' || v === 0);
    }
  }
  function _empty(id, msg) {
    if (!UI[id]) return;
    UI[id].innerHTML = `<div class="data-empty"><span>${msg}</span></div>`;
  }

  function _detectPlatform(url) {
    for (const [, sig] of Object.entries(PLATFORM_SIGNATURES)) {
      if (sig.patterns.some(p => p.test(url))) return sig;
    }
    return null;
  }

  function _confClass(src) {
    if (src === 'rel_me' || src === 'link_rel_me') return 'high';
    if (src === 'anchor') return 'medium';
    return 'low';
  }

  function _confPct(src) {
    if (src === 'rel_me' || src === 'link_rel_me') return '90%';
    if (src === 'anchor') return '70%';
    if (src === 'opengraph') return '60%';
    return '40%';
  }

  function _sevBadge(sev) {
    const cls = SEVERITY_CLASS[sev] || 'info';
    return `<span class="sev-badge sev-${cls}">${(sev || 'info').toUpperCase()}</span>`;
  }

  function _esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  let _allProfiles = [];
function _renderSocial(items) {
    _allProfiles = [];

    items.forEach(item => {
      const src = item.source || '';
      const url = item.url || '';
      const platform = item.platform || _detectPlatform(url)?.label || 'Other';

      if (src === 'hidden_input' || src === 'opengraph') return;

      if (platform && url.startsWith('http')) {
        _allProfiles.push({ platform, url, source: src, color: _detectPlatform(url)?.color || 'var(--text-dim)' });
      }
    });

    _renderProfilesTable(_allProfiles);

    const uniquePlatforms = new Set(_allProfiles.map(p => p.platform));
    const high = _allProfiles.filter(p => _confClass(p.source) === 'high').length;
    const low  = _allProfiles.filter(p => _confClass(p.source) === 'low').length;

    _setText('soc-prof-count', _allProfiles.length);
    _setText('soc-platform-count', uniquePlatforms.size);
    _setText('soc-high-conf', high);
    _setText('soc-low-conf', low);
    _setText('soc-summary-badge', _allProfiles.length);
    _setText('soc-profiles-badge', _allProfiles.length);
  }

  const CONF_LABEL = { high: 'High', medium: 'Medium', low: 'Low' };

  function _renderProfilesTable(profiles) {
    if (!UI['soc-profiles-body']) return;
    if (!profiles.length) { _empty('soc-profiles-body', 'No social profiles discovered'); return; }

    UI['soc-profiles-body'].innerHTML = profiles.map(p => {
      const cc = _confClass(p.source);
      return `<div class="data-row soc-row" data-soc-platform="${_esc(p.platform.toLowerCase().split(' ')[0])}">
        <span class="soc-c soc-c-plat"><span class="soc-platform-badge" style="color:${_esc(p.color)};">${_esc(p.platform)}</span></span>
        <a class="soc-c soc-c-grow soc-link" href="${_esc(p.url)}" target="_blank" rel="noopener">${_esc(p.url)}</a>
        <span class="soc-c soc-c-mid soc-dim">${_esc(p.source)}</span>
        <span class="soc-c soc-c-conf confidence-bar"><span class="confidence-dot ${cc}"></span><span>${CONF_LABEL[cc]} · ${_confPct(p.source)}</span></span>
      </div>`;
    }).join('');
  }

    function _filterProfiles(filter) {
    if (!UI['soc-profiles-body']) return;
    UI['soc-profiles-body'].querySelectorAll('.data-row').forEach(row => {
      const pl = row.getAttribute('data-soc-platform') || '';
      const show = filter === 'all' || pl.includes(filter);
      row.style.display = show ? '' : 'none';
    });
  }

  let _allEmails = [];

  const EMAIL_SRC_BADGE = {
    'plaintext':     'web',
    'obfuscated_at': 'web',
    'entity_encoded':'web',
    'js_concat':     'web',
    'js_variable':   'web',
    'data_attr':     'web',
    'data_attr_composite':'web',
    'hcard':         'web',
    'html_comment':  'web',
    'schema_org':    'web',
    'probe_path':    'web',
    'whois':         'whois',
    'github':        'github',
  };

  function _emailBadgeClass(src) {
    return EMAIL_SRC_BADGE[src] || 'web';
  }

function _renderEmails(items) {
    _allEmails = items.map(item => ({
      address:  item.email || item.value || item.address || '',
      source:   item.source || 'plaintext',
      context:  item.context || item.note || (item.role_based ? 'role-based' : '') || '',
      verified: item.verified || false,
      confidence: item.confidence || '',
      role_based: item.role_based || false,
    })).filter(e => e.address.includes('@'));

    _renderEmailTable(_allEmails);

    const uniqueDomains = new Set(_allEmails.map(e => e.address.split('@')[1]));
    const personal = _allEmails.filter(e => ['gmail.com','yahoo.com','outlook.com','hotmail.com','protonmail.com'].includes(e.address.split('@')[1])).length;
    const srcSet = new Set(_allEmails.map(e => e.source));

    _setText('email-total', _allEmails.length);
    _setText('email-unique-domains', uniqueDomains.size);
    _setText('email-personal', personal);
    _setText('email-sources', srcSet.size);
    _setText('email-summary-badge', _allEmails.length);
    _setText('email-results-badge', _allEmails.length);
  }

  function _renderEmailTable(emails) {
    if (!UI['email-results-body']) return;
    if (!emails.length) { _empty('email-results-body', 'No emails discovered'); return; }

    UI['email-results-body'].innerHTML = emails.map(e => {
      const src      = e.source || 'plaintext';
      const badgeCls = _emailBadgeClass(src);
      const confCls  = e.confidence === 'high' ? 'high' : e.confidence === 'medium' ? 'medium' : 'low';
      const confText = e.confidence ? e.confidence.charAt(0).toUpperCase() + e.confidence.slice(1) : '—';
      const role     = e.role_based ? '<span class="soc-role">role</span>' : '';
      return `<div class="data-row soc-row" data-email-src="${_esc(badgeCls)}">
        <span class="soc-c soc-c-grow soc-mono soc-val">${_esc(e.address)}${role}</span>
        <span class="soc-c soc-c-mid"><span class="email-badge ${_esc(badgeCls)}">${_esc(src)}</span></span>
        <span class="soc-c soc-c-ctx soc-dim">${_esc(e.context) || '—'}</span>
        <span class="soc-c soc-c-conf confidence-bar"><span class="confidence-dot ${confCls}"></span><span>${_esc(confText)}</span></span>
      </div>`;
    }).join('');
  }

    function _filterEmails(filter) {
    if (!UI['email-results-body']) return;
    UI['email-results-body'].querySelectorAll('.data-row').forEach(row => {
      const src = row.getAttribute('data-email-src') || '';
      row.style.display = (filter === 'all' || src === filter) ? '' : 'none';
    });
  }

  function _renderHtmlMeta(items) {
    const standard  = items.filter(i => i.source === 'standard_meta');
    const og        = items.filter(i => i.source === 'open_graph' || i.source === 'open_graph_missing');
    const tw        = items.filter(i => i.source === 'twitter_card');
    const httpEquiv = items.filter(i => i.source === 'http_equiv');
    const comments  = items.filter(i => i.source === 'html_comment' || i.category === 'Hidden Comments');

    _renderStandardMeta(standard);
    _renderOG(og);
    _renderTwitter(tw);
    _renderLeaks(items);
    _renderHttpEquiv(httpEquiv);
    _renderHiddenComments(comments);

    _setText('htmlmeta-meta-tags',     standard.length);
    _setText('htmlmeta-og-tags',       og.filter(i => i.source !== 'open_graph_missing').length);
    _setText('htmlmeta-twitter-tags',  tw.length);
    _setText('htmlmeta-summary-badge', items.length);
    _setText('htmlmeta-og-badge',      og.length);
    _setText('htmlmeta-twitter-badge', tw.length);
    _setText('htmlmeta-standard-badge',standard.length);
    _setText('htmlmeta-httpequiv-badge',httpEquiv.length);
    _setText('htmlmeta-comments-badge', comments.length);
  }

function _renderHttpEquiv(items) {
    const container = UI['htmlmeta-httpequiv-rows'];
    if (!container) return;
    if (!items.length) {
      container.innerHTML = '<div class="data-empty"><span>No http-equiv tags found</span></div>';
      return;
    }
    container.innerHTML = items.map(tag => `
      <div class="dns-check-row">
        <span class="dcr-label soc-mono">${_esc(tag.name)}</span>
        <span class="dcr-val monospace">${_esc(tag.value)}</span>
      </div>`).join('');
  }

  function _dedent(value) {
    const lines = String(value ?? '').replace(/\r\n?/g, '\n').replace(/\t/g, '  ').split('\n');
    while (lines.length && !lines[0].trim()) lines.shift();
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    if (!lines.length) return '';
    const indentOf = l => l.match(/^ */)[0].length;
    const rest = lines.slice(1).filter(l => l.trim());
    const cut = rest.length ? Math.min(...rest.map(indentOf)) : 0;
    const cleaned = [lines[0].trim(), ...lines.slice(1).map(l => l.slice(Math.min(cut, indentOf(l))).replace(/\s+$/, ''))];
    return cleaned.join('\n').replace(/\n{3,}/g, '\n\n');
  }

  function _scanComment(text) {
    const hits = [];
    CRITICAL_PATTERNS.forEach(p => {
      if (SEV_RANK[p.severity] < SEV_RANK.medium) return;
      const rx = new RegExp(p.rx.source, p.rx.flags);
      let m;
      let found = 0;
      while (found < 25 && (m = rx.exec(text))) {
        if (!m[0]) { rx.lastIndex++; continue; }
        if (p.standalone && m.index > 0 && /[\w.:\/-]/.test(text[m.index - 1])) continue;
        hits.push({ start: m.index, end: m.index + m[0].length, p });
        found++;
      }
    });
    return hits;
  }

  function _mergeRanges(hits) {
    const sorted = hits.slice().sort((a, b) => a.start - b.start || b.end - a.end);
    const ranges = [];
    sorted.forEach(h => {
      const last = ranges[ranges.length - 1];
      if (last && h.start < last.end) {
        last.end = Math.max(last.end, h.end);
        last.hits.push(h);
      } else {
        ranges.push({ start: h.start, end: h.end, hits: [h] });
      }
    });
    return ranges;
  }

  function _highlight(text, ranges) {
    let html = '';
    let pos = 0;
    ranges.forEach(r => {
      const labels = [...new Set(r.hits.map(h => h.p.label))].join(' · ');
      html += _esc(text.slice(pos, r.start));
      html += `<mark class="soc-hit" title="${_esc(labels)}">${_esc(text.slice(r.start, r.end))}</mark>`;
      pos = r.end;
    });
    return html + _esc(text.slice(pos));
  }

  function _buildCommentModel(item, index) {
    const text = _dedent(item.value);
    const hits = _scanComment(text);
    let level = 'info';
    hits.forEach(h => {
      if (SEV_RANK[h.p.severity] > SEV_RANK[level]) level = h.p.severity;
    });
    const reported = String(item.severity || 'info').toLowerCase();
    if (SEV_RANK[reported] >= SEV_RANK.medium && SEV_RANK[reported] > SEV_RANK[level]) level = reported;

    const byPattern = new Map();
    hits.forEach(h => {
      const entry = byPattern.get(h.p.id) || { p: h.p, count: 0 };
      entry.count++;
      byPattern.set(h.p.id, entry);
    });

    return {
      index,
      text,
      level,
      hits: hits.length,
      lines: text ? text.split('\n').length : 0,
      flagged: hits.length > 0 || SEV_RANK[level] >= SEV_RANK.medium,
      patterns: [...byPattern.values()].sort((a, b) => SEV_RANK[b.p.severity] - SEV_RANK[a.p.severity] || b.count - a.count),
      html: _highlight(text, _mergeRanges(hits))
    };
  }

  function _commentCardHtml(m) {
    const long = m.text.length > 420 || m.lines > 8;
    const badge = m.flagged ? _sevBadge(m.level) : '<span class="soc-comment-tag">clean</span>';
    const shown = m.patterns.slice(0, 8);
    const chips = shown.map(e => `<span class="soc-cmt-chip" title="${_esc(e.p.category)} · ${_esc(e.p.severity)}">${_esc(e.p.label)}${e.count > 1 ? ` ×${e.count}` : ''}</span>`).join('');
    const extra = m.patterns.length > shown.length ? `<span class="soc-cmt-chip muted">+${m.patterns.length - shown.length} more</span>` : '';
    const matchText = m.hits ? ` · <b>${m.hits} match${m.hits === 1 ? '' : 'es'}</b>` : '';
    return `<article class="soc-cmt${m.flagged ? ' flagged' : ''}">
      <header class="soc-cmt-head">
        <span class="soc-cmt-index">#${String(m.index).padStart(2, '0')}</span>
        <span class="soc-cmt-meta">${m.lines} line${m.lines === 1 ? '' : 's'} · ${m.text.length} chars${matchText}</span>
        <span class="soc-cmt-spacer"></span>
        ${badge}
        <button type="button" class="soc-cmt-btn" data-cmt-copy="${m.index}">Copy</button>
      </header>
      <pre class="soc-cmt-body${long ? ' collapsed' : ''}">${m.html}</pre>
      ${long ? '<button type="button" class="soc-cmt-more" data-cmt-toggle>Show more</button>' : ''}
      ${chips ? `<footer class="soc-cmt-foot">${chips}${extra}</footer>` : ''}
    </article>`;
  }

  function _paintComments(container) {
    const total = _cmtModels.length;
    const flagged = _cmtModels.filter(m => m.flagged).length;
    const matches = _cmtModels.reduce((n, m) => n + m.hits, 0);
    const counts = { all: total, flagged, clean: total - flagged };
    const visible = _cmtModels.filter(m => _cmtFilter === 'all' || (_cmtFilter === 'flagged') === m.flagged);
    const filters = ['all', 'flagged', 'clean'].map(f =>
      `<button type="button" class="soc-cmt-filter${_cmtFilter === f ? ' active' : ''}" data-cmt-filter="${f}">${f[0].toUpperCase() + f.slice(1)} <span>${counts[f]}</span></button>`
    ).join('');
    const list = visible.length
      ? visible.map(_commentCardHtml).join('')
      : '<div class="data-empty"><span>No comments match this filter</span></div>';

    container.innerHTML = `
      <div class="soc-cmt-toolbar">
        <div class="soc-cmt-stats">
          <span><b>${total}</b> comments</span>
          <span class="${flagged ? 'soc-cmt-red' : ''}"><b>${flagged}</b> flagged</span>
          <span class="${matches ? 'soc-cmt-red' : ''}"><b>${matches}</b> matches</span>
          <span>${CRITICAL_PATTERNS.length} patterns scanned</span>
        </div>
        <div class="soc-cmt-filters">${filters}</div>
      </div>
      <div class="soc-cmt-list">${list}</div>`;
  }

  function _onCommentsClick(e) {
    const t = e.target.closest('[data-cmt-filter],[data-cmt-copy],[data-cmt-toggle]');
    if (!t) return;

    if (t.hasAttribute('data-cmt-filter')) {
      _cmtFilter = t.getAttribute('data-cmt-filter');
      _paintComments(e.currentTarget);
      return;
    }

    if (t.hasAttribute('data-cmt-toggle')) {
      const body = t.previousElementSibling;
      const collapsed = body.classList.toggle('collapsed');
      t.textContent = collapsed ? 'Show more' : 'Show less';
      return;
    }

    const model = _cmtModels.find(m => String(m.index) === t.getAttribute('data-cmt-copy'));
    if (!model || !navigator.clipboard) return;
    navigator.clipboard.writeText(model.text).then(() => {
      t.textContent = 'Copied';
      setTimeout(() => { t.textContent = 'Copy'; }, 1200);
    }).catch(() => {});
  }

  function _renderHiddenComments(items) {
    const container = UI['htmlmeta-comments-rows'];
    if (!container) return;
    _cmtModels = items.map((c, i) => _buildCommentModel(c, i + 1)).filter(m => m.text);
    _cmtFilter = 'all';
    if (!_cmtModels.length) {
      container.onclick = null;
      container.innerHTML = '<div class="data-empty"><span>No HTML comments found</span></div>';
      return;
    }
    container.onclick = _onCommentsClick;
    _paintComments(container);
  }

  function _renderStandardMeta(items) {
    if (!UI['htmlmeta-standard-body']) return;
    if (!items.length) { _empty('htmlmeta-standard-body', 'No standard meta tags found'); return; }

    const SENSITIVE_NAMES = new Set(['generator', 'author', 'application-name', 'creator', 'publisher']);
    UI['htmlmeta-standard-body'].innerHTML = items.map(tag => {
      const cls = SENSITIVE_NAMES.has((tag.name || '').toLowerCase()) ? 'sensitive' : 'standard';
      return `<div class="data-row soc-row">
        <span class="soc-c soc-c-key soc-mono soc-dim">${_esc(tag.name)}</span>
        <span class="soc-c soc-c-grow soc-val">${_esc(tag.value)}</span>
        <span class="soc-c soc-c-tag"><span class="meta-class-badge ${cls}">${cls}</span></span>
      </div>`;
    }).join('');
  }

    function _renderOG(items) {
    const get = name => items.find(i => i.name === name)?.value || '—';
    _setText('og-title',    get('og:title'));
    _setText('og-desc',     get('og:description'));
    _setText('og-image',    get('og:image'));
    _setText('og-url',      get('og:url'));
    _setText('og-type',     get('og:type'));
    _setText('og-sitename', get('og:site_name'));
    _setText('og-locale',   get('og:locale'));
    _setText('og-fbapp',    get('fb:app_id'));
  }

  function _renderTwitter(items) {
    const get = name => items.find(i => i.name === name)?.value || '—';
    _setText('tw-card',    get('twitter:card'));
    _setText('tw-site',    get('twitter:site'));
    _setText('tw-creator', get('twitter:creator'));
    _setText('tw-title',   get('twitter:title'));
    _setText('tw-desc',    get('twitter:description'));
    _setText('tw-image',   get('twitter:image'));
    _setText('tw-domain',  get('twitter:domain'));
  }

  function _renderLeaks(items) {
    const LEAK_NAMES = new Set(['generator', 'author', 'application-name', 'creator', 'publisher']);
    const leaky = items.filter(i => LEAK_NAMES.has((i.name || '').toLowerCase()));

    const generator = items.find(i => i.name === 'generator')?.value;
    const author    = items.find(i => i.name === 'author')?.value;
    const emailRx   = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i;
    const emailLeak = items.find(i => emailRx.test(i.value || ''));
    const pathLeak  = items.find(i => /^\/[a-z]/i.test(i.value || '') && i.value.length > 10 && !i.value.startsWith('http'));
    const appName   = items.find(i => i.name === 'application-name')?.value;

    _setText('leak-generator', generator || 'None');
    _setText('leak-author',    author    || 'None');
    _setText('leak-email',     emailLeak ? emailLeak.value : 'None');
    _setText('leak-paths',     pathLeak  ? pathLeak.value  : 'None');
    _setText('leak-versions',  appName   || 'None');
    const commentCount = items.filter(i => i.source === 'html_comment' || i.category === 'Hidden Comments').length;
    _setText('leak-comments',  commentCount ? `${commentCount} comment(s) found` : 'None');

    const sensitive = leaky.filter(i => i.value).length;
    _setText('htmlmeta-sensitive', sensitive);
    _setText('htmlmeta-leak-badge', leaky.length);
  }

  let _docs = [];
  let _docFilter = 'all';
  let _docQuery = '';

  const DOC_KEY_CATEGORIES = new Set(['document', 'archive', 'spreadsheet', 'presentation', 'database', 'backup']);
  const DOC_LINE_RX = /^\s*([A-Za-z][A-Za-z0-9 _\-]*?)\s*\/\s*([A-Za-z0-9]+)\s*:\s*(https?:\/\/\S+)\s*$/;
  const DOC_SCAN_RX = /Scanning\s+(\d+)\s+captured\s+request\s+URL\(s\)\s+and\s+(\d+)\s+text\s+response\s+bod/i;
  const DOC_RANK = { document: 0, archive: 1, spreadsheet: 1, presentation: 1, database: 1, backup: 1, data: 2, image: 4, font: 5 };
  const EXT_GROUPS = {
    pdf: 'pdf',
    doc: 'word', docx: 'word', odt: 'word', rtf: 'word', txt: 'word',
    xls: 'sheet', xlsx: 'sheet', csv: 'sheet', ods: 'sheet',
    ppt: 'slide', pptx: 'slide', odp: 'slide',
    json: 'data', jsonl: 'data', xml: 'data', yaml: 'data', yml: 'data',
    zip: 'archive', rar: 'archive', '7z': 'archive', tar: 'archive', gz: 'archive'
  };

  function _parseDocsFromLog(text) {
    const items = [];
    const meta = { requests: null, bodies: null };
    String(text || '').split(/\r?\n/).forEach(line => {
      const sc = DOC_SCAN_RX.exec(line);
      if (sc) { meta.requests = parseInt(sc[1], 10); meta.bodies = parseInt(sc[2], 10); return; }
      const m = DOC_LINE_RX.exec(line);
      if (m) items.push({ category: m[1], type: m[2], url: m[3] });
    });
    return { items, meta };
  }

  function _extOf(url) {
    try {
      const seg = new URL(url).pathname.split('/').pop() || '';
      return seg.includes('.') ? seg.split('.').pop() : '';
    } catch (e) { return ''; }
  }

  function _fileName(url) {
    try {
      const u = new URL(url);
      const seg = u.pathname.split('/').filter(Boolean).pop() || u.hostname;
      try { return decodeURIComponent(seg); } catch (e) { return seg; }
    } catch (e) { return url; }
  }

  function _normalizeDocs(rows) {
    const seen = new Set();
    const out = [];
    (rows || []).forEach(r => {
      const url = String(r.url || '').trim();
      if (!/^https?:\/\//i.test(url) || seen.has(url)) return;
      seen.add(url);
      out.push({
        category: String(r.category || 'Other').trim() || 'Other',
        type: String(r.type || r.ext || r.extension || _extOf(url) || 'file').toLowerCase(),
        url
      });
    });
    out.sort((a, b) => {
      const ra = DOC_RANK[a.category.toLowerCase()] ?? 3;
      const rb = DOC_RANK[b.category.toLowerCase()] ?? 3;
      return ra - rb || a.category.localeCompare(b.category) || a.type.localeCompare(b.type) || a.url.localeCompare(b.url);
    });
    return out;
  }

  function _catClass(cat) {
    const c = cat.toLowerCase();
    return ['document', 'data', 'image', 'font'].includes(c) ? c : 'other';
  }

  function _extGroup(ext) { return EXT_GROUPS[ext] || 'default'; }

  function _countBy(items, keyFn) {
    const m = new Map();
    items.forEach(i => { const k = keyFn(i); m.set(k, (m.get(k) || 0) + 1); });
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }

  function _countGrid(id, entries, upper) {
    const el = UI[id];
    if (!el) return;
    if (!entries.length) { _empty(id, 'No data'); return; }
    el.innerHTML = entries.map(([label, n]) =>
      `<div class="soc-source-item"><span class="ssi-label">${_esc(upper ? label.toUpperCase() : label)}</span><span class="ssi-count">${n}</span></div>`
    ).join('');
  }

  function _filteredDocs() {
    return _docs.filter(d => {
      if (_docFilter !== 'all' && d.category.toLowerCase() !== _docFilter) return false;
      if (!_docQuery) return true;
      return (d.url + ' ' + _fileName(d.url) + ' ' + d.type + ' ' + d.category).toLowerCase().includes(_docQuery);
    });
  }

  function _renderDocuments(payload) {
    _docs = payload.items || [];
    const meta = payload.meta || {};
    const cats = _countBy(_docs, d => d.category);
    const exts = _countBy(_docs, d => d.type);
    const key  = _docs.filter(d => DOC_KEY_CATEGORIES.has(d.category.toLowerCase()));

    if (_docFilter !== 'all' && !cats.some(([c]) => c.toLowerCase() === _docFilter)) _docFilter = 'all';

    _setText('doc-total', _docs.length);
    _setText('doc-key-count', key.length);
    _setText('doc-cat-count', cats.length);
    _setText('doc-ext-count', exts.length);
    _setText('doc-requests', meta.requests);
    _setText('doc-bodies', meta.bodies);
    _setText('doc-summary-badge', _docs.length);
    _setText('doc-key-badge', key.length);
    _setText('doc-cat-badge', cats.length);
    _setText('doc-files-badge', _docs.length);

    _renderKeyDocs(key);
    _countGrid('doc-cat-grid', cats, false);
    _countGrid('doc-ext-grid', exts, true);

    if (UI['doc-pills']) {
      UI['doc-pills'].innerHTML =
        `<button class="filter-pill${_docFilter === 'all' ? ' active' : ''}" data-doc-filter="all">All<span class="doc-pill-n">${_docs.length}</span></button>` +
        cats.map(([c, n]) => `<button class="filter-pill${_docFilter === c.toLowerCase() ? ' active' : ''}" data-doc-filter="${_esc(c.toLowerCase())}">${_esc(c)}<span class="doc-pill-n">${n}</span></button>`).join('');
    }

    _renderDocTable();
  }

  function _renderKeyDocs(key) {
    const el = UI['doc-key-grid'];
    if (!el) return;
    if (!key.length) { _empty('doc-key-grid', _docs.length ? 'No documents found among discovered files' : 'Provide an intercept log and run a scan to discover documents'); return; }
    el.innerHTML = key.map(d => {
      const name = _fileName(d.url);
      return `<a class="doc-card" href="${_esc(d.url)}" target="_blank" rel="noopener" title="${_esc(d.url)}">
        <span class="doc-ext-tile ext-${_extGroup(d.type)}">${_esc(d.type.slice(0, 5))}</span>
        <span class="doc-card-body">
          <div class="doc-card-name">${_esc(name)}</div>
          <div class="doc-card-url">${_esc(d.url.replace(/^https?:\/\//i, ''))}</div>
        </span>
        <svg class="doc-card-open" width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M6 3H3.5A1.5 1.5 0 0 0 2 4.5v8A1.5 1.5 0 0 0 3.5 14h8a1.5 1.5 0 0 0 1.5-1.5V10M9 2h5v5M14 2L7.5 8.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </a>`;
    }).join('');
  }

  function _renderDocTable() {
    const body = UI['doc-table-body'];
    if (!body) return;
    const rows = _filteredDocs();
    _setText('doc-count', `${rows.length} of ${_docs.length} files`);
    if (!rows.length) { _empty('doc-table-body', _docs.length ? 'No files match the current filter' : 'No files discovered yet'); return; }
    body.innerHTML = rows.map(d => `<div class="data-row soc-row">
        <span class="soc-c soc-c-cat"><span class="doc-cat-badge ${_catClass(d.category)}">${_esc(d.category)}</span></span>
        <span class="soc-c soc-c-type soc-mono">${_esc(d.type)}</span>
        <span class="soc-c soc-c-name soc-val">${_esc(_fileName(d.url))}</span>
        <a class="soc-c soc-c-grow soc-link" href="${_esc(d.url)}" target="_blank" rel="noopener">${_esc(d.url)}</a>
      </div>`).join('');
  }

  function _flashBtn(btn, text) {
    const lbl = btn?.querySelector('.doc-btn-label');
    if (!lbl) return;
    const orig = lbl.dataset.orig || lbl.textContent;
    lbl.dataset.orig = orig;
    lbl.textContent = text;
    setTimeout(() => { lbl.textContent = orig; }, 1300);
  }

  function _copyDocUrls() {
    const urls = _filteredDocs().map(d => d.url).join('\n');
    if (!urls) return;
    const done = () => _flashBtn(UI['doc-copy-btn'], 'Copied');
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(urls).then(done).catch(() => { _legacyCopy(urls); done(); });
    } else {
      _legacyCopy(urls);
      done();
    }
  }

  function _legacyCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0;';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    ta.remove();
  }

  function exportDocuments() {
    const rows = _filteredDocs();
    if (!rows.length) return;
    const q = v => {
      let t = String(v);
      if (/^[=+\-@]/.test(t)) t = "'" + t;
      return '"' + t.replace(/"/g, '""') + '"';
    };
    const csv = ['category,type,file_name,url']
      .concat(rows.map(d => [d.category, d.type, _fileName(d.url), d.url].map(q).join(',')))
      .join('\r\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `discovered-files-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportData() {
    if (!_state.raw) return;
    const blob = new Blob([JSON.stringify(_state.raw, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `social-osint-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return { init, loadFromJSON, loadFromAPI, startScan, stopScan, resetAll, exportData, exportDocuments, getState: () => ({ ..._state }) };

})();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => Social.init());
} else {
  Social.init();
}