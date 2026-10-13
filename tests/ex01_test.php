<?php

declare(strict_types=1);

// Exercise 01 — secure configuration & error handling

$errorLog = TEST_ROOT . '/private/logs/php_errors.log';
$leakMarkers = ['Notice:', 'Warning:', 'Fatal error', 'Stack trace', '.php on line', 'undefined_function_for_demo', TEST_ROOT];

test('every directory contains an index.php (no directory listing)', function (): void {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(TEST_ROOT, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    $missing = [];
    foreach ($iterator as $item) {
        $path = $item->getPathname();
        if ($item->isDir() && !str_contains($path, DIRECTORY_SEPARATOR . '.git') && !is_file($path . '/index.php')) {
            $missing[] = substr($path, strlen(TEST_ROOT) + 1);
        }
    }
    assert_same([], $missing, 'Directories without index.php');
});

test('a sub-directory request returns 403, not a listing', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/assets/');
    assert_same(403, $r->status, 'GET /assets/');
});

test('files in private/ cannot be requested', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    foreach (['/private/config.php', '/private/logs/php_errors.log', '/../private/config.php'] as $path) {
        $r = $browser->get($path);
        assert_same(404, $r->status, "GET {$path}");
    }
});

test('X-Powered-By header is not sent (expose_php = Off)', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/');
    assert_same(200, $r->status, 'GET /');
    assert_same(null, $r->header('X-Powered-By'), 'X-Powered-By');
});

test('E_NOTICE is logged but not displayed', function () use ($errorLog, $leakMarkers): void {
    $log = new LogWatcher($errorLog);
    $r = (new Browser(SERVER_URLS['main']))->get('/error_test.php?level=notice');
    assert_same(200, $r->status, 'status');
    foreach ($leakMarkers as $marker) {
        assert_not_contains($marker, $r->body, 'Response body');
    }
    $new = $log->newContent();
    assert_contains('PHP Notice:', $new, 'php_errors.log');
    assert_contains('Only variables should be passed by reference', $new, 'php_errors.log');
});

test('E_WARNING is logged but not displayed', function () use ($errorLog, $leakMarkers): void {
    $log = new LogWatcher($errorLog);
    $r = (new Browser(SERVER_URLS['main']))->get('/error_test.php?level=warning');
    assert_same(200, $r->status, 'status');
    foreach ($leakMarkers as $marker) {
        assert_not_contains($marker, $r->body, 'Response body');
    }
    $new = $log->newContent();
    assert_contains('PHP Warning:', $new, 'php_errors.log');
    assert_contains('Undefined array key "missing_key"', $new, 'php_errors.log');
});

test('E_ERROR (fatal) is logged, visitor gets a generic 500 page', function () use ($errorLog, $leakMarkers): void {
    $log = new LogWatcher($errorLog);
    $r = (new Browser(SERVER_URLS['main']))->get('/error_test.php?level=error');
    assert_same(500, $r->status, 'status');
    assert_contains('Something went wrong', $r->body, 'generic error page');
    foreach ([...$leakMarkers, 'memory'] as $marker) {
        assert_not_contains($marker, $r->body, 'Response body');
    }
    $new = $log->newContent();
    assert_contains('PHP Fatal error:', $new, 'php_errors.log');
    assert_contains('Allowed memory size', $new, 'php_errors.log');
});

test('uncaught exception is logged, visitor gets a generic 500 page', function () use ($errorLog, $leakMarkers): void {
    $log = new LogWatcher($errorLog);
    $r = (new Browser(SERVER_URLS['main']))->get('/error_test.php?level=exception');
    assert_same(500, $r->status, 'status');
    foreach ($leakMarkers as $marker) {
        assert_not_contains($marker, $r->body, 'Response body');
    }
    assert_contains('Call to undefined function undefined_function_for_demo()', $log->newContent(), 'php_errors.log');
});

test('exec() is blocked by disable_functions', function () use ($errorLog): void {
    $log = new LogWatcher($errorLog);
    $r = (new Browser(SERVER_URLS['main']))->get('/error_test.php?level=disabled');
    assert_same(500, $r->status, 'status');
    assert_contains('Call to undefined function exec()', $log->newContent(), 'php_errors.log');
});
