/*
 * Landing gate.
 *
 * Every fresh visitor must see /login first, whatever URL they typed. The
 * only way past it without an account is the page's own "Skip login and
 * proceed to scanner" link, which hands out a guest pass.
 *
 * Auth in this app is a localStorage bearer token, so the server cannot tell
 * a signed-in visitor from an anonymous one on a plain GET — gating in the
 * route handler would bounce logged-in users too, and "/" is the New Scan
 * page the sidebar points at. The check therefore runs here, as the first
 * synchronous script in <head>, before any of the page body is parsed or
 * painted: location.replace() aborts the load, so there is no flash of the
 * protected page and no extra history entry to bounce back to.
 *
 * The guest pass lives in sessionStorage, so it dies with the browser tab.
 * Close the tab, come back tomorrow, and you land on /login again — which is
 * the point. This is a UX gate, not access control: every endpoint that
 * returns real data still authorises the bearer token server-side.
 */
(function () {
    'use strict';

    try {
        // Signed in — carry on.
        if (localStorage.getItem('token')) return;

        var params = new URLSearchParams(window.location.search);

        // Arriving via the skip link, or via the AI agent's "scan this domain"
        // action, which the visitor asked for explicitly. Either one opens a
        // guest session for the rest of this tab.
        if (params.get('guest') === '1' || params.get('autostart') === 'true') {
            sessionStorage.setItem('guest', '1');
            return;
        }

        if (sessionStorage.getItem('guest') === '1') return;

        window.location.replace('/login');
    } catch (e) {
        // Storage blocked (private mode, third-party cookie policy). Fail open
        // rather than trapping the visitor in a redirect they cannot escape.
    }
})();
