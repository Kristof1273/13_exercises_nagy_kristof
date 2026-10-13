<?php

declare(strict_types=1);

// Exercise 04 — SQL injection prevention

test('registration inserts a user', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    foreach (['alice', 'bob', 'carol'] as $name) {
        $r = register_user($browser, $name, "{$name}@example.com", 'Correct-Horse-9');
        assert_same(303, $r->status, "register {$name}");
    }
    $page = $browser->get('/register.php');
    assert_contains('was registered', $page->body, 'success message');
});

test('duplicate username is rejected', function (): void {
    $r = register_user(new Browser(SERVER_URLS['main']), 'ALICE', 'other@example.com', 'Correct-Horse-9');
    assert_same(200, $r->status, 'status');
    assert_contains('already registered', $r->body, 'error');
});

test('username with SQL meta-characters is rejected by validation', function (): void {
    $r = register_user(new Browser(SERVER_URLS['main']), "x'); DROP TABLE users; --", 'evil@example.com', 'Correct-Horse-9');
    assert_contains('Username must be 3–30 characters', $r->body, 'error');
});

test('safe search finds users by partial username', function (): void {
    $r = search_browser()->get('/search.php?username=' . rawurlencode('li'));
    assert_contains('alice@example.com', $r->body, 'alice found');
    assert_not_contains('bob@example.com', $r->body, 'bob not found');
});

test("safe search treats ' OR '1'='1 as plain text", function (): void {
    $r = search_browser()->get('/search.php?username=' . rawurlencode("' OR '1'='1"));
    assert_same(200, $r->status, 'status');
    assert_contains('0 result(s)', $r->body, 'no rows');
});

test('safe search escapes LIKE wildcards (% does not match everything)', function (): void {
    $r = search_browser()->get('/search.php?username=' . rawurlencode('%'));
    assert_contains('0 result(s)', $r->body, 'no rows');
});

test("vulnerable search: ' OR '1'='1 dumps every user", function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $normal = $browser->get('/vulnerable_search.php?username=alice');
    assert_contains('1 row(s) returned', $normal->body, 'normal lookup');

    $attack = $browser->get('/vulnerable_search.php?username=' . rawurlencode("' OR '1'='1"));
    assert_contains('4 row(s) returned', $attack->body, 'injected query (alice, bob, carol + tester)');
    foreach (['alice', 'bob', 'carol'] as $name) {
        assert_contains("{$name}@example.com", $attack->body, "{$name} leaked");
    }
});

test('vulnerable search: UNION attack reads another column', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/vulnerable_search.php?username=' . rawurlencode("' UNION SELECT id, username, password FROM users --"));
    assert_contains('4 row(s) returned', $r->body, 'UNION rows');
    assert_contains('$2y$12$', $r->body, 'password hashes leaked');
});

test('the users table survived all of the above', function (): void {
    $pdo = new PDO('sqlite:' . TEST_DB);
    assert_true((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() >= 3, 'users still there');
});
