/*
 * Extra Mile 3 — runs from /assets (same origin), which script-src 'self' allows.
 * Records CSP violations and reports whether the page's inline code ran.
 */
(function () {
    'use strict';

    var pending = [];

    function show(text) {
        var list = document.getElementById('violations');
        if (!list) {
            pending.push(text);
            return;
        }
        var item = document.createElement('li');
        item.textContent = text;
        list.appendChild(item);
    }

    document.addEventListener('securitypolicyviolation', function (event) {
        var what = event.blockedURI === 'inline' || event.blockedURI === ''
            ? 'inline code'
            : event.blockedURI;
        var where = event.lineNumber ? ' (line ' + event.lineNumber + ')' : '';
        show('Blocked by ' + event.effectiveDirective + ': ' + what + where);
    });

    function setResult(id, ok, text) {
        var element = document.getElementById(id);
        element.textContent = text;
        element.className = 'alert ' + (ok ? 'alert-ok' : 'alert-error');
    }

    document.addEventListener('DOMContentLoaded', function () {
        pending.forEach(show);
        pending = [];
        setResult('external-result', true, "✅ External script from 'self' executed.");
        setResult('inline-result', window.__inlineScriptRan !== true, window.__inlineScriptRan === true
            ? '❌ Inline <script> EXECUTED — the CSP is not active!'
            : '✅ Inline <script> was blocked by the Content-Security-Policy.');
    });

    // The broken image's onerror fires after DOMContentLoaded; check once everything has loaded.
    window.addEventListener('load', function () {
        setResult('handler-result', window.__inlineHandlerRan !== true, window.__inlineHandlerRan === true
            ? '❌ Inline onerror="…" handler EXECUTED — the CSP is not active!'
            : '✅ Inline onerror="…" event handler was blocked as well.');
    });
}());
