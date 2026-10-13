<?php

declare(strict_types=1);

// Exercise 05 — secure password handling

test('the password is stored as a bcrypt hash, never in plain text', function (): void {
    $r = register_user(new Browser(SERVER_URLS['main']), 'dave', 'dave@example.com', 'Purple-Monkey-77');
    assert_same(303, $r->status, 'register');
    $pdo = new PDO('sqlite:' . TEST_DB);
    $hash = (string) $pdo->query("SELECT password FROM users WHERE username = 'dave'")->fetchColumn();
    assert_true(str_starts_with($hash, '$2y$12$'), 'bcrypt, cost 12');
    assert_same(60, strlen($hash), 'hash length');
    assert_true(password_verify('Purple-Monkey-77', $hash), 'hash verifies');
});

test('password column is VARCHAR(255)', function (): void {
    $pdo = new PDO('sqlite:' . TEST_DB);
    $columns = $pdo->query('PRAGMA table_info(users)')->fetchAll(PDO::FETCH_ASSOC);
    $password = array_values(array_filter($columns, static fn (array $c): bool => $c['name'] === 'password'))[0];
    assert_same('VARCHAR(255)', strtoupper($password['type']), 'column type');
});

test('weak or mismatching passwords are rejected', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $short = register_user($browser, 'erin', 'erin@example.com', 'short');
    assert_contains('at least 10 characters', $short->body, 'too short');

    $mismatch = submit_form($browser, '/register.php', '/register.php', [
        'username' => 'erin', 'email' => 'erin@example.com', 'password' => 'Long-Enough-123', 'password_confirm' => 'Different-123',
    ]);
    assert_contains('do not match', $mismatch->body, 'mismatch');
});

test('wrong password and unknown user give the same generic error', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $wrong = login($browser, TESTER['username'], 'not-the-password');
    $unknown = login($browser, 'nobody-here', 'not-the-password');
    assert_same(200, $wrong->status, 'wrong password status');
    assert_contains('Invalid username or password.', $wrong->body, 'wrong password');
    assert_contains('Invalid username or password.', $unknown->body, 'unknown user');
});

test('successful login regenerates the session ID (no session fixation)', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $browser->get('/login.php');
    $name = session_cookie_name($browser);
    $before = $browser->cookies[$name] ?? '';
    $r = login($browser, TESTER['username'], TESTER['password']);
    assert_same('/dashboard.php', $r->location(), 'redirect after login');
    assert_true($before !== '' && $browser->cookies[$name] !== $before, 'session ID changed');

    // the pre-login ID is worthless now
    $attacker = new Browser(SERVER_URLS['main']);
    $attacker->cookies[$name] = $before;
    assert_same(303, $attacker->get('/dashboard.php')->status, 'old ID is not logged in');
});

test('protected page redirects anonymous visitors to the login page', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/dashboard.php');
    assert_same(303, $r->status, 'status');
    assert_same('/login.php?status=login_required', $r->location(), 'redirect');
});

test('protected page is shown after login and not cached', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $r = $browser->get('/dashboard.php');
    assert_same(200, $r->status, 'status');
    assert_contains('Welcome, tester!', $r->body, 'greeting');
    assert_contains('no-store', (string) $r->header('Cache-Control'), 'Cache-Control');
});

test('search requires login', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/search.php?username=a');
    assert_same('/login.php?status=login_required', $r->location(), 'redirect');
});

test('logout via GET only asks for confirmation', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $browser->get('/logout.php');
    assert_same(200, $browser->get('/dashboard.php')->status, 'still logged in');
});

test('logout destroys the session and its cookie', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $name = session_cookie_name($browser);
    $sessionId = $browser->cookies[$name];

    $dashboard = $browser->get('/dashboard.php');
    $r = $browser->post('/logout.php', ['csrf_token' => $dashboard->csrfToken()]);
    assert_same('/login.php?status=logged_out', $r->location(), 'redirect');
    $deleted = array_filter($r->headerAll('Set-Cookie'), static fn (string $c): bool => str_starts_with($c, $name . '=deleted') || str_starts_with($c, $name . '=;'));
    assert_true($deleted !== [], 'cookie deletion header sent');
    assert_true(!isset($browser->cookies[$name]), 'cookie removed from browser');

    // replaying the old session ID does not log anybody in
    $replay = new Browser(SERVER_URLS['main']);
    $replay->cookies[$name] = $sessionId;
    assert_same(303, $replay->get('/dashboard.php')->status, 'old session is gone');
});
