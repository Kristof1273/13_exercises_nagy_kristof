<?php

declare(strict_types=1);

// Exercise 06 — session security & cookie hardening

function session_set_cookie(Response $r, string $prefix): string
{
    foreach ($r->headerAll('Set-Cookie') as $cookie) {
        if (str_starts_with($cookie, $prefix)) {
            return $cookie;
        }
    }
    throw new AssertionFailed("No Set-Cookie for {$prefix}");
}

test('session cookie is HttpOnly, SameSite=Strict, Path=/, host-only', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/login.php');
    $cookie = strtolower(session_set_cookie($r, 'SECSESSID='));
    assert_contains('httponly', $cookie, 'HttpOnly');
    assert_contains('samesite=strict', $cookie, 'SameSite');
    assert_contains('path=/', $cookie, 'Path');
    assert_not_contains('domain=', $cookie, 'no Domain attribute');
    assert_not_contains('expires=', $cookie, 'session cookie (no Expires)');
});

test('with SESSION_COOKIE_SECURE=1 the cookie is Secure and uses the __Host- prefix', function (): void {
    $r = (new Browser(SERVER_URLS['secure']))->get('/login.php');
    $cookie = strtolower(session_set_cookie($r, '__Host-SECSESSID='));
    assert_contains('; secure', $cookie, 'Secure');
    assert_contains('httponly', $cookie, 'HttpOnly');
});

test('normal login and navigation keep the session', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    foreach (['/dashboard.php', '/search.php?username=a', '/form.php', '/dashboard.php'] as $page) {
        assert_same(200, $browser->get($page)->status, $page);
    }
});

test('a manually changed session cookie is rejected and replaced', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $id = $browser->cookies['SECSESSID'];
    $tampered = substr($id, 0, -1) . ($id[-1] === 'a' ? 'b' : 'a');
    $browser->cookies['SECSESSID'] = $tampered;

    $r = $browser->get('/dashboard.php');
    assert_same('/login.php?status=login_required', $r->location(), 'not logged in');
    assert_true(($browser->cookies['SECSESSID'] ?? '') !== $tampered, 'server issued a new ID (strict mode)');
});

test('a forged session ID chosen by an attacker is never adopted', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $browser->cookies['SECSESSID'] = 'attackerchosenid1234567890abc';
    $browser->get('/login.php');
    assert_true($browser->cookies['SECSESSID'] !== 'attackerchosenid1234567890abc', 'ID replaced');
});

test('changing the User-Agent ends the session (fingerprint)', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $browser->userAgent = 'Mozilla/5.0 (Hijacker)';
    $r = $browser->get('/dashboard.php');
    assert_same('/login.php?status=session_invalid', $r->location(), 'redirect');

    // the original browser is logged out as well: the session was destroyed
    $browser->userAgent = 'SecurityLabTest/1.0 (+tests/run.php)';
    assert_same(303, $browser->get('/dashboard.php')->status, 'session is gone');
});

test('activity within the idle window keeps the session alive (timeout = 3 s)', function (): void {
    $browser = new Browser(SERVER_URLS['short']);
    login_as_tester($browser);
    sleep(2);
    assert_same(200, $browser->get('/dashboard.php')->status, 'after 2 s');
    sleep(2);
    assert_same(200, $browser->get('/dashboard.php')->status, 'after 4 s total, 2 s idle');
});

test('the session expires after the idle timeout', function (): void {
    $browser = new Browser(SERVER_URLS['short']);
    login_as_tester($browser);
    usleep(4_500_000);
    $r = $browser->get('/dashboard.php');
    assert_same('/login.php?status=expired', $r->location(), 'redirect');
    assert_contains('session expired', $browser->follow($r)->body, 'message');
});
