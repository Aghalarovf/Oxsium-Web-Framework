/**
 * Oxsium Web — state.js
 * Mərkəzi tətbiq vəziyyəti. Bütün JS faylları bu obyekti oxuyur/yeniləyir.
 */

const State = {
    // Aktiv tab (topbar)
    activeTab: 'recon',

    // Aktiv sidebar modulu
    activeModule: 'target-setup',

    // Target məlumatları
    target: {
        url:      '',
        ip:       '',
        port:     '',
        basePath: '',
        username: '',
        password: '',
        headers:  '',
        proxy:    '',
        threads:  3,
        intercept:'',
        options: {
            takeover: false,
            checkLive: false,
            resolve: false,
            wildcardFilter: false,
            dnsSecurity: true,
            serviceScanner: true,
            exchange: true,
            ntlm: false,
        },
        protocol: 'http-https',  // 'http-https' | 'ws-wss'
        mode:     'single',      // 'single' | 'bulk' | 'file'
    },

    // Skan vəziyyəti
    scan: {
        running:  false,
        module:   null,
        startedAt: null,
    },

    // API backend
    api: {
        base:    'http://localhost:30300',
        online:  false,
        latency: null,
    },

    // Sağ panel runtime məlumatları
    info: {
        status:      'IDLE',
        targetUrl:   '--',
        ipAddress:   '--',
        webServer:   '--',
        tlsVersion:  '--',
        wafDetected: '--',
        responseTime:'--',
        http2:       '--',
        cors:        '--',
        hsts:        '--',
        csp:         '--',
        clickjacking:'--',
        apiBackend:  '--',
        latency:     '--',
    },

    // Statusbar
    statusbar: {
        status:  'IDLE',
        module:  '--',
        session: '--',
    },
};