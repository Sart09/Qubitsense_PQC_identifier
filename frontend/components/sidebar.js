/**
 * Shared app sidebar.
 *
 * One component, injected at runtime, rather than markup copy-pasted into
 * each page. Every app page previously carried its own hand-rolled header
 * bar and they had already drifted apart — different link sets, different
 * labels for the same destination, and "Back to Home" pointing at /scanner
 * on one page and / on another. A single source for navigation means adding
 * a destination is a one-line change here instead of an edit in every file.
 *
 * Mounted on app pages only (dashboard, schedules, analytics). index.html
 * keeps its full-screen landing hero and is reached via the Home item.
 *
 * Colours are explicit hex, never Tailwind palette classes. components/
 * pnb-theme.css rewrites slate/indigo/amber with !important, which has twice
 * produced invisible white-on-white text in this project; nothing here
 * depends on a utility class resolving to the colour it names.
 *
 * Usage — add before </body>:
 *   <script src="/components/sidebar.js"></script>
 */

(function () {
    'use strict';

    // requiresAuth items are dropped entirely when no token is present;
    // adminOnly items are additionally dropped unless the stored role is
    // 'admin'. The role is only ever used to decide whether to SHOW this
    // link — every /admin/* API call is independently re-checked
    // server-side (admin_routes.py's require_admin), so a stale or
    // tampered localStorage value can hide/show a link but never grant
    // real access.
    var NAV_ITEMS = [
        {
            // Home is the domain-inventory card grid, NOT index.html.
            // index.html is the anonymous entry page and is entirely a
            // "start a new scan" form, so pointing Home there dropped a
            // returning user into a new scan rather than showing them the
            // domains they had already scanned.
            href: '/home', icon: '🏠', label: 'Home',
            match: function (p) {
                return exactRoot(p) || prefix('/home')(p) || prefix('/user-dashboard')(p);
            }
        },
        { href: '/schedules', icon: '🕒', label: 'Schedule Scan', match: prefix('/schedules') },
        {
            href: '/analytics', icon: '📊', label: 'Scan History & Analytics',
            // A per-scan dashboard is a drill-down reached from this
            // section, so it keeps this item lit.
            match: function (p) {
                return prefix('/analytics')(p) || prefix('/dashboard')(p);
            }
        },
        {
            href: '/security', icon: '🔒', label: 'Security', requiresAuth: true,
            match: prefix('/security')
        },
        {
            href: '/admin', icon: '🛡️', label: 'Admin Console', requiresAuth: true, adminOnly: true,
            match: prefix('/admin')
        }
    ];

    var COLLAPSE_KEY = 'sidebar_collapsed';
    var WIDTH_EXPANDED = 236;
    var WIDTH_COLLAPSED = 64;

    function exactRoot(pathname) {
        return pathname === '/' || pathname === '/index.html';
    }

    function prefix(base) {
        return function (pathname) {
            return pathname === base || pathname.indexOf(base + '/') === 0;
        };
    }

    function injectStyles() {
        var css = [
            '#appSidebar{position:fixed;top:0;left:0;bottom:0;z-index:60;display:flex;flex-direction:column;',
            'background:#4E0B11;border-right:1px solid rgba(212,160,23,.35);',
            'box-shadow:2px 0 12px rgba(0,0,0,.28);transition:width .18s ease;overflow:hidden;}',
            '#appSidebar .sb-brand{display:flex;align-items:center;gap:10px;height:64px;padding:0 14px;',
            'border-bottom:1px solid rgba(212,160,23,.28);flex-shrink:0;}',
            '#appSidebar .sb-brand-text{color:#F0C040;font-weight:800;font-size:13px;line-height:1.15;white-space:nowrap;}',
            '#appSidebar .sb-brand-sub{color:#E7C9C9;font-weight:600;font-size:10px;white-space:nowrap;}',
            '#appSidebar nav{padding:12px 8px;display:flex;flex-direction:column;gap:4px;flex:1;overflow-y:auto;}',
            '#appSidebar a.sb-item{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:9px;',
            'text-decoration:none;color:#F5EDED;font-size:13px;font-weight:600;white-space:nowrap;',
            'border:1px solid transparent;transition:background .13s ease,color .13s ease;}',
            '#appSidebar a.sb-item:hover{background:rgba(240,192,64,.14);color:#fff;}',
            /* Active item: gold fill + dark text. High contrast so the current
               location is unmistakable even on the maroon ground. */
            '#appSidebar a.sb-item.sb-active{background:#F0C040;color:#4E0B11;font-weight:800;',
            'border-color:#D4A017;box-shadow:0 2px 8px rgba(0,0,0,.25);}',
            '#appSidebar .sb-icon{font-size:16px;width:20px;text-align:center;flex-shrink:0;}',
            '#appSidebar .sb-label{overflow:hidden;text-overflow:ellipsis;}',
            '#appSidebar .sb-foot{padding:10px 8px;border-top:1px solid rgba(212,160,23,.28);flex-shrink:0;}',
            '#appSidebar .sb-user{color:#E7C9C9;font-size:10.5px;padding:0 6px 8px;white-space:nowrap;',
            'overflow:hidden;text-overflow:ellipsis;}',
            '#appSidebar .sb-btn{width:100%;display:flex;align-items:center;gap:10px;padding:9px 12px;',
            'border-radius:8px;background:#88001b;color:#FFE9E9;border:1px solid rgba(212,160,23,.3);',
            'font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;}',
            '#appSidebar .sb-btn:hover{background:#9E1F2D;color:#fff;}',
            '#sbToggle{position:absolute;top:20px;right:10px;width:24px;height:24px;border-radius:6px;',
            'background:rgba(0,0,0,.28);color:#F0C040;border:1px solid rgba(212,160,23,.3);cursor:pointer;',
            'font-size:12px;line-height:1;display:flex;align-items:center;justify-content:center;padding:0;}',
            '#sbToggle:hover{background:rgba(0,0,0,.45);color:#fff;}',
            /* Collapsed rail: labels and the brand text are hidden, icons stay
               centred, and each item keeps a native tooltip so the rail is
               still navigable without guessing what an icon means. */
            'body.sb-collapsed #appSidebar .sb-label,',
            'body.sb-collapsed #appSidebar .sb-brand-block,',
            'body.sb-collapsed #appSidebar .sb-user{display:none;}',
            'body.sb-collapsed #appSidebar a.sb-item{justify-content:center;padding:11px 0;}',
            'body.sb-collapsed #appSidebar .sb-btn{justify-content:center;padding:9px 0;}',
            'body.sb-collapsed #sbToggle{right:auto;left:50%;transform:translateX(-50%);top:auto;bottom:74px;}',
            '#sbScrim{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:55;display:none;}',
            '#sbBurger{display:none;position:fixed;top:12px;left:12px;z-index:70;width:40px;height:40px;',
            'border-radius:9px;background:#4E0B11;color:#F0C040;border:1px solid rgba(212,160,23,.4);',
            'font-size:17px;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,.35);}',
            /* Under 900px the sidebar becomes off-canvas: content reclaims the
               full width and the rail slides over it instead of squeezing
               dashboard tables into an unreadable column. */
            '@media (max-width:900px){',
            '  body{padding-left:0 !important;}',
            '  #sbBurger{display:block;}',
            '  #appSidebar{width:236px !important;transform:translateX(-100%);transition:transform .2s ease;}',
            '  body.sb-open #appSidebar{transform:translateX(0);}',
            '  body.sb-open #sbScrim{display:block;}',
            '  body.sb-collapsed #appSidebar .sb-label,',
            '  body.sb-collapsed #appSidebar .sb-brand-block,',
            '  body.sb-collapsed #appSidebar .sb-user{display:revert;}',
            '  body.sb-collapsed #appSidebar a.sb-item{justify-content:flex-start;padding:11px 12px;}',
            '  #sbToggle{display:none;}',
            '}',
            '@media print{#appSidebar,#sbBurger,#sbScrim{display:none !important;}body{padding-left:0 !important;}}'
        ].join('');

        var style = document.createElement('style');
        style.id = 'appSidebarStyles';
        style.textContent = css;
        document.head.appendChild(style);
    }

    function build() {
        var pathname = window.location.pathname;
        var collapsed = localStorage.getItem(COLLAPSE_KEY) === '1';
        var email = localStorage.getItem('email') || '';
        var token = localStorage.getItem('token');
        var role = localStorage.getItem('role') || '';

        var aside = document.createElement('aside');
        aside.id = 'appSidebar';
        aside.setAttribute('aria-label', 'Main navigation');

        var visibleItems = NAV_ITEMS.filter(function (item) {
            if (item.requiresAuth && !token) return false;
            if (item.adminOnly && role !== 'admin') return false;
            return true;
        });

        var links = visibleItems.map(function (item) {
            var active = item.match(pathname) ? ' sb-active' : '';
            return '<a class="sb-item' + active + '" href="' + item.href + '" title="' + item.label + '"'
                + (active ? ' aria-current="page"' : '') + '>'
                + '<span class="sb-icon">' + item.icon + '</span>'
                + '<span class="sb-label">' + item.label + '</span></a>';
        }).join('');

        // Logged out: offer Login instead of a Logout button that would do
        // nothing. The rest of the app is usable anonymously, so the sidebar
        // must not imply a session that does not exist.
        var footAction = token
            ? '<button class="sb-btn" id="sbLogout" type="button" title="Log out">'
              + '<span class="sb-icon">⏻</span><span class="sb-label">Logout</span></button>'
            : '<a class="sb-btn" href="/login" title="Log in" style="text-decoration:none;">'
              + '<span class="sb-icon">→</span><span class="sb-label">Login</span></a>';

        aside.innerHTML =
            '<div class="sb-brand">'
            + '<span style="font-size:20px;flex-shrink:0;">🏦</span>'
            + '<span class="sb-brand-block">'
            + '<span class="sb-brand-text">Punjab National Bank</span><br>'
            + '<span class="sb-brand-sub">Enterprise PQC</span>'
            + '</span>'
            + '<button id="sbToggle" type="button" aria-label="Collapse sidebar" title="Collapse / expand">‹</button>'
            + '</div>'
            + '<nav>' + links + '</nav>'
            + '<div class="sb-foot">'
            + (email
                ? '<div class="sb-user" title="' + email + '">' + email
                    + (role === 'admin' ? ' <span style="color:#F0C040;font-weight:800;">· ADMIN</span>' : '')
                    + '</div>'
                : '')
            + footAction
            + '</div>';

        var scrim = document.createElement('div');
        scrim.id = 'sbScrim';

        var burger = document.createElement('button');
        burger.id = 'sbBurger';
        burger.type = 'button';
        burger.setAttribute('aria-label', 'Open navigation');
        burger.textContent = '☰';

        document.body.appendChild(aside);
        document.body.appendChild(scrim);
        document.body.appendChild(burger);

        function applyWidth() {
            var isCollapsed = document.body.classList.contains('sb-collapsed');
            var w = isCollapsed ? WIDTH_COLLAPSED : WIDTH_EXPANDED;
            aside.style.width = w + 'px';
            // Offset page content by the rail width. Padding on body rather
            // than a wrapper element so it works on all these pages without
            // restructuring their existing max-w containers.
            document.body.style.paddingLeft = w + 'px';
            document.getElementById('sbToggle').textContent = isCollapsed ? '›' : '‹';
        }

        if (collapsed) document.body.classList.add('sb-collapsed');
        applyWidth();

        document.getElementById('sbToggle').addEventListener('click', function () {
            var isCollapsed = document.body.classList.toggle('sb-collapsed');
            localStorage.setItem(COLLAPSE_KEY, isCollapsed ? '1' : '0');
            applyWidth();
        });

        burger.addEventListener('click', function () {
            document.body.classList.toggle('sb-open');
        });
        scrim.addEventListener('click', function () {
            document.body.classList.remove('sb-open');
        });

        var logout = document.getElementById('sbLogout');
        if (logout) {
            logout.addEventListener('click', function () {
                localStorage.removeItem('token');
                localStorage.removeItem('email');
                localStorage.removeItem('user_id');
                localStorage.removeItem('role');
                localStorage.removeItem('mfa_enabled');
                // Drop any guest pass too, so logout lands on the login page
                // instead of slipping through the scanner's auth guard.
                sessionStorage.removeItem('guest');
                window.location.href = '/login';
            });
        }
    }

    function init() {
        if (document.getElementById('appSidebar')) return;
        injectStyles();
        build();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
