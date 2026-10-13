<?php

declare(strict_types=1);

// Exercise 07 — security logging & brute-force protection

const SECURITY_LOG = TEST_ROOT . '/private/logs/security.log';

/** @return list<string> log lines of the given event */
function events(string $logContent, string $event): array
{
    return array_values(array_filter(
        explode("\n", $logContent),
        static fn (string $line): bool => preg_match('/^\[[^\]]+\] [A-Z]+ +' . $event . ' /', $line) === 1
    ));
}

test('log lines carry a timestamp, level, event, IP and request', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $lines = events($log->newContent(), 'LOGIN_SUCCESS');
    assert_same(1, count($lines), 'one LOGIN_SUCCESS line');
    assert_true(preg_match('/^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}\] INFO +LOGIN_SUCCESS ip="127\.0\.0\.1" user="tester" req="POST \/login\.php"/', $lines[0]) === 1, 'format: ' . $lines[0]);
});

test('PHP errors and exceptions are logged', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    $browser = new Browser(SERVER_URLS['main']);
    $browser->get('/error_test.php?level=warning');
    $browser->get('/error_test.php?level=exception');
    $browser->get('/error_test.php?level=error');
    $content = $log->newContent();
    assert_contains('Undefined array key', implode("\n", events($content, 'PHP_ERROR')), 'warning');
    assert_true(events($content, 'UNCAUGHT_EXCEPTION') !== [], 'exception');
    assert_contains('Allowed memory size', implode("\n", events($content, 'FATAL_ERROR')), 'fatal error');
});

test('failed logins are logged, the password never is', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    login(new Browser(SERVER_URLS['main']), TESTER['username'], 'Secret-Guess-123');
    $content = $log->newContent();
    $failed = events($content, 'LOGIN_FAILED');
    assert_same(1, count($failed), 'LOGIN_FAILED');
    assert_contains('"reason":"wrong_password"', $failed[0], 'reason');
    assert_not_contains('Secret-Guess-123', $content, 'password must not be logged');
});

test('password changes are logged and need the current password', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    register_user($browser, 'frank', 'frank@example.com', 'Original-Pass-11');
    login($browser, 'frank', 'Original-Pass-11');

    $log = new LogWatcher(SECURITY_LOG);
    $wrong = submit_form($browser, '/change_password.php', '/change_password.php', [
        'current_password' => 'not-it', 'new_password' => 'Brand-New-Pass-22', 'new_password_confirm' => 'Brand-New-Pass-22',
    ]);
    assert_contains('current password is incorrect', $wrong->body, 'wrong current password');

    $ok = submit_form($browser, '/change_password.php', '/change_password.php', [
        'current_password' => 'Original-Pass-11', 'new_password' => 'Brand-New-Pass-22', 'new_password_confirm' => 'Brand-New-Pass-22',
    ]);
    assert_same('/dashboard.php', $ok->location(), 'redirect');
    assert_contains('password has been changed', $browser->follow($ok)->body, 'flash message');

    $content = $log->newContent();
    assert_same(1, count(events($content, 'PASSWORD_CHANGE_FAILED')), 'PASSWORD_CHANGE_FAILED');
    assert_same(1, count(events($content, 'PASSWORD_CHANGED')), 'PASSWORD_CHANGED');
    assert_not_contains('Brand-New-Pass-22', $content, 'new password must not be logged');

    $fresh = new Browser(SERVER_URLS['main']);
    assert_same('/dashboard.php', login($fresh, 'frank', 'Brand-New-Pass-22')->location(), 'new password works');
});

test('CSRF token mismatches are logged', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    $browser = new Browser(SERVER_URLS['main']);
    $browser->get('/form.php');
    $browser->post('/process.php', valid_contact() + ['csrf_token' => str_repeat('0', 64)]);
    $lines = events($log->newContent(), 'CSRF_TOKEN_MISMATCH');
    assert_same(1, count($lines), 'CSRF_TOKEN_MISMATCH');
    assert_contains('ALERT', $lines[0], 'level');
    assert_contains('"form":"contact"', $lines[0], 'form id');
});

test('SQL injection attempts are logged (GET and POST)', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $browser->get('/search.php?username=' . rawurlencode("' OR '1'='1"));
    submit_form($browser, '/form.php', '/process.php', ['message' => "x' UNION SELECT password FROM users --"] + valid_contact());
    $lines = events($log->newContent(), 'SQLI_ATTEMPT');
    assert_same(2, count($lines), 'two SQLI_ATTEMPT lines');
    assert_contains('"field":"username"', $lines[0], 'GET field');
    assert_contains('quote_then_boolean', $lines[0], 'rule');
    assert_contains('"field":"message"', $lines[1], 'POST field');
    assert_contains('union_select', $lines[1], 'rule');
});

test("ordinary input such as O'Brien is not flagged", function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    submit_form(new Browser(SERVER_URLS['main']), '/form.php', '/process.php', ['name' => "Seán O'Brien", 'message' => "I'd like to order 2 items, or maybe 3."] + valid_contact());
    $content = $log->newContent();
    assert_same([], events($content, 'SQLI_ATTEMPT'), 'no SQLI_ATTEMPT');
    assert_same([], events($content, 'XSS_ATTEMPT'), 'no XSS_ATTEMPT');
});

test('passwords are never inspected or logged, even if they look like SQL', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    login(new Browser(SERVER_URLS['main']), TESTER['username'], "' OR '1'='1");
    $content = $log->newContent();
    assert_same([], events($content, 'SQLI_ATTEMPT'), 'no SQLI_ATTEMPT for the password field');
    assert_not_contains("OR '1'='1", $content, 'password value');
});

test('XSS attempts are logged', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    submit_form(new Browser(SERVER_URLS['main']), '/form.php', '/process.php', ['name' => '<script>alert(1)</script>'] + valid_contact());
    assert_same(1, count(events($log->newContent(), 'XSS_ATTEMPT')), 'XSS_ATTEMPT');
});

test('session hijacking indicators are logged', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $browser->userAgent = 'EvilBot/6.6';
    $browser->get('/dashboard.php');
    $lines = events($log->newContent(), 'SESSION_FINGERPRINT_MISMATCH');
    assert_same(1, count($lines), 'SESSION_FINGERPRINT_MISMATCH');
    assert_contains('"changed":["user_agent"]', $lines[0], 'what changed');
});

test('log injection: newlines in input cannot forge log lines', function (): void {
    $log = new LogWatcher(SECURITY_LOG);
    $forged = "nobody\n[2026-01-01T00:00:00.000+00:00] INFO    LOGIN_SUCCESS ip=\"1.2.3.4\" user=\"admin\"";
    login(new Browser(SERVER_URLS['main']), $forged, 'whatever-password');
    $content = $log->newContent();
    foreach (array_filter(explode("\n", $content)) as $line) {
        assert_true(str_starts_with($line, '[' . date('Y')) || str_starts_with($line, '[' . gmdate('Y')), 'every line is a real entry: ' . $line);
    }
    assert_same([], events($content, 'LOGIN_SUCCESS'), 'no forged LOGIN_SUCCESS');
    assert_contains('\\n[2026-01-01', $content, 'newline is escaped');
});

test('brute force: 5 failures in 10 minutes block the IP, even with the right password', function (): void {
    (new PDO('sqlite:' . TEST_DB))->exec('DELETE FROM login_attempts');
    $log = new LogWatcher(SECURITY_LOG);
    $browser = new Browser(SERVER_URLS['main']);

    for ($i = 1; $i <= 4; $i++) {
        $r = login($browser, TESTER['username'], "wrong-password-{$i}");
        assert_contains('Invalid username or password.', $r->body, "attempt {$i}");
    }
    $fifth = login($browser, TESTER['username'], 'wrong-password-5');
    assert_same(429, $fifth->status, '5th attempt status');
    assert_contains('Too many failed login attempts', $fifth->body, '5th attempt message');

    $sixth = login($browser, TESTER['username'], TESTER['password']);
    assert_same(429, $sixth->status, 'correct password is still refused');
    assert_true((int) $sixth->header('Retry-After') > 0, 'Retry-After header');

    $content = $log->newContent();
    assert_same(5, count(events($content, 'LOGIN_FAILED')), 'LOGIN_FAILED x5');
    assert_true(count(events($content, 'REPEATED_FAILED_LOGINS')) >= 1, 'REPEATED_FAILED_LOGINS');
    assert_same(1, count(events($content, 'BRUTE_FORCE_DETECTED')), 'BRUTE_FORCE_DETECTED');
    assert_same(1, count(events($content, 'LOGIN_BLOCKED')), 'LOGIN_BLOCKED');

    // once the oldest failure is older than 10 minutes the IP may try again
    (new PDO('sqlite:' . TEST_DB))->exec('UPDATE login_attempts SET attempted_at = attempted_at - 601');
    assert_same('/dashboard.php', login(new Browser(SERVER_URLS['main']), TESTER['username'], TESTER['password'])->location(), 'unblocked after the window');
});
