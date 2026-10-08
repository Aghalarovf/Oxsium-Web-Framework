const Nav = (() => {

    function switchPanel(panelId) {
        document.querySelectorAll('.module-panel').forEach(p => p.classList.remove('active'));
        if (panelId) document.getElementById(panelId)?.classList.add('active');
    }

    function initNavItems() {
        const items = document.querySelectorAll('.nav-item:not(.locked)');
        items.forEach(item => {
            item.addEventListener('click', () => {
                if (item.dataset.status === 'deactivated') return;

                items.forEach(i => i.classList.remove('active'));
                item.classList.add('active');

                const label = [...item.childNodes]
                    .filter(n => n.nodeType === Node.TEXT_NODE)
                    .map(n => n.textContent.trim())
                    .filter(Boolean)
                    .join('');
                State.activeModule = item.dataset.module || label;
                UI.setModule(label);
                switchPanel(item.dataset.panel);
            });
        });
    }

    function activateItem(nameOrEl) {
        const item = typeof nameOrEl === 'string'
            ? [...document.querySelectorAll('.nav-item')].find(
                el => el.textContent.trim().startsWith(nameOrEl)
              )
            : nameOrEl;

        if (!item) return;
        delete item.dataset.status;
        item.style.pointerEvents = '';
    }

    function initModeToggle() {
        const btns = document.querySelectorAll('.mode-btn');
        btns.forEach(btn => {
            btn.addEventListener('click', () => {
                btns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const label = btn.textContent.trim().toLowerCase();
                if (label.includes('single'))    State.target.mode = 'single';
                else if (label.includes('bulk')) State.target.mode = 'bulk';
                else if (label.includes('file')) State.target.mode = 'file';
            });
        });
    }

    function initProtocol() {
        const btns = document.querySelectorAll('.proto-btn:not([style*="not-allowed"])');
        btns.forEach(btn => {
            btn.addEventListener('click', () => {
                btns.forEach(b => b.classList.remove('selected'));
                btn.classList.add('selected');

                const name = btn.querySelector('.proto-name')?.textContent.trim().toLowerCase() || '';
                State.target.protocol = name.includes('ws') ? 'ws-wss' : 'http-https';
            });
        });
    }

    function init() {
        initNavItems();
        initModeToggle();
        initProtocol();
    }

    return { init, initNavItems, initModeToggle, initProtocol, activateItem };
})();