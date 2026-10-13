<?php

declare(strict_types=1);

// Extra Mile 3 — Content-Security-Policy

test("every page sends a CSP with script-src 'self'", function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    foreach (['/', '/form.php', '/login.php', '/register.php', '/csp_test.php'] as $path) {
        $csp = (string) $browser->get($path)->header('Content-Security-Policy');
        assert_contains("script-src 'self'", $csp, $path);
        assert_contains("object-src 'none'", $csp, $path);
        assert_contains("frame-ancestors 'none'", $csp, $path);
        assert_not_contains('unsafe-inline', $csp, $path);
    }
});

test('the generic 500 page carries the CSP too', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/error_test.php?level=exception');
    assert_same(500, $r->status, 'status');
    assert_contains("script-src 'self'", (string) $r->header('Content-Security-Policy'), 'CSP');
});

test('the application itself contains no inline scripts, handlers or styles', function (): void {
    $files = array_merge(
        glob(TEST_ROOT . '/public/*.php') ?: [],
        glob(TEST_ROOT . '/private/templates/*.php') ?: [],
        [TEST_ROOT . '/private/src/ErrorHandler.php'],
    );
    $offenders = [];
    foreach ($files as $file) {
        if (basename($file) === 'csp_test.php') {
            continue; // contains inline code on purpose
        }
        $html = (string) file_get_contents($file);
        if (
            preg_match('/<script(?![^>]*\ssrc=)[^>]*>/i', $html) === 1
            || preg_match('/<[a-z][^>]*\s(?:on[a-z]+|style)\s*=/i', $html) === 1
        ) {
            $offenders[] = basename($file);
        }
    }
    assert_same([], $offenders, 'files with inline code');
});

test('the CSP test page really contains inline code to be blocked', function (): void {
    $body = (new Browser(SERVER_URLS['main']))->get('/csp_test.php')->body;
    assert_contains('window.__inlineScriptRan = true', $body, 'inline <script>');
    assert_contains('onerror="window.__inlineHandlerRan = true"', $body, 'inline handler');
    assert_contains('<script src="/assets/csp-test.js"></script>', $body, 'external script');
});
