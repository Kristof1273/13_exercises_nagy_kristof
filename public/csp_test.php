<?php

declare(strict_types=1);

/*
 * Extra Mile 3 — Content-Security-Policy check.
 *
 * This page deliberately contains inline JavaScript (a <script> block and an
 * onerror="…" handler). With the CSP header (script-src 'self') the browser
 * must refuse both, while /assets/csp-test.js (same origin) still runs and
 * reports the result. Open the browser console to see the CSP violations.
 */

require __DIR__ . '/../private/bootstrap.php';

render_header('CSP test');
?>
<h1>Content-Security-Policy test</h1>

<?php // External script from 'self' — allowed. Loaded first so it can listen for violations. ?>
<script src="/assets/csp-test.js"></script>

<section class="card">
    <h2>Results</h2>
    <div id="external-result" class="alert alert-error">❌ The external script did not run (JavaScript disabled?).</div>
    <div id="inline-result" class="alert alert-warn">⏳ Waiting for the result…</div>
    <div id="handler-result" class="alert alert-warn">⏳ Waiting for the result…</div>
    <h2>Violations reported by the browser</h2>
    <ul id="violations" class="list-links"></ul>
</section>

<section class="card">
    <h2>Policy sent with this page</h2>
    <pre id="policy"><?= e(implode("\n", array_map(
        static fn (string $h): string => preg_replace('/;\s*/', ";\n", $h) ?? $h,
        array_filter(headers_list(), static fn (string $h): bool => stripos($h, 'Content-Security-Policy:') === 0)
    ))) ?></pre>
</section>

<?php // ❌ Inline script — must be BLOCKED by script-src 'self'. ?>
<script>
    window.__inlineScriptRan = true;
    document.getElementById('inline-result').textContent = '❌ Inline script EXECUTED — the CSP is not active!';
</script>

<?php // ❌ Inline event handler — must be BLOCKED as well (the image does not exist, so onerror fires). ?>
<img src="/assets/this-image-does-not-exist.png" alt="" class="hidden-probe" onerror="window.__inlineHandlerRan = true">
<?php render_footer(); ?>
