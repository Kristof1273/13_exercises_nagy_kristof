<?php

declare(strict_types=1);

// Exercise 03 — XSS & CSRF protection

test('the form contains a 64-hex-character CSRF token', function (): void {
    $page = (new Browser(SERVER_URLS['main']))->get('/form.php');
    assert_same(64, strlen($page->csrfToken()), 'token length');
});

test('a new token is generated on every form load', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $a = $browser->get('/form.php')->csrfToken();
    $b = $browser->get('/form.php')->csrfToken();
    assert_true($a !== $b, 'tokens must differ');
});

test('normal submission with the token succeeds', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $token = $browser->get('/form.php')->csrfToken();
    $r = $browser->post('/process.php', valid_contact() + ['csrf_token' => $token]);
    assert_same('/confirmation.php', $r->location(), 'redirect target');
});

test('submission without a token is rejected (403)', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $browser->get('/form.php'); // victim has a session, attacker has no token
    $r = $browser->post('/process.php', valid_contact());
    assert_same(403, $r->status, 'status');
    assert_contains('security token', $r->body, 'error page');
});

test('submission with a tampered token is rejected (403)', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $token = $browser->get('/form.php')->csrfToken();
    $tampered = substr($token, 0, -1) . ($token[-1] === 'a' ? 'b' : 'a');
    $r = $browser->post('/process.php', valid_contact() + ['csrf_token' => $tampered]);
    assert_same(403, $r->status, 'status');
});

test("a token from another user's session is rejected (403)", function (): void {
    $attacker = new Browser(SERVER_URLS['main']);
    $victim = new Browser(SERVER_URLS['main']);
    $attackerToken = $attacker->get('/form.php')->csrfToken();
    $victim->get('/form.php');
    $r = $victim->post('/process.php', valid_contact() + ['csrf_token' => $attackerToken]);
    assert_same(403, $r->status, 'status');
});

test('a token cannot be replayed (single use)', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $token = $browser->get('/form.php')->csrfToken();
    $first = $browser->post('/process.php', valid_contact() + ['csrf_token' => $token]);
    assert_same(303, $first->status, 'first submit');
    $second = $browser->post('/process.php', valid_contact() + ['csrf_token' => $token]);
    assert_same(403, $second->status, 'replayed submit');
});

test('XSS payloads in every field are rendered harmlessly', function (): void {
    $payloads = [
        'name' => '"><script>alert(1)</script>',
        'website' => 'https://example.com/"onmouseover="alert(1)',
        'message' => '<img src=x onerror=alert(1)> and " onmouseover="alert(2)',
    ];
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', $payloads + valid_contact());
    $body = $browser->follow($r)->body;
    foreach (['<script>alert', '<img', '"onmouseover="', '" onmouseover="'] as $raw) {
        assert_not_contains($raw, $body, 'confirmation page');
    }
});

test('values echoed back into the form cannot break out of the attribute', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    // invalid email -> redirect back, the raw values are re-inserted into value="..."
    $r = submit_form($browser, '/form.php', '/process.php', ['email' => '"><svg onload=alert(1)>', 'name' => "' onmouseover='alert(1)"] + valid_contact());
    $form = $browser->follow($r)->body;
    assert_not_contains('"><svg', $form, 'email attribute');
    assert_contains('value="&quot;&gt;&lt;svg onload=alert(1)&gt;"', $form, 'encoded email');
    assert_contains('value="&#039; onmouseover=&#039;alert(1)"', $form, 'encoded name');
});

test("apostrophes are not double-encoded (O'Brien)", function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', ['name' => "Seán O'Brien & Co"] + valid_contact());
    $body = $browser->follow($r)->body;
    assert_contains('Seán O&#039;Brien &amp; Co', $body, 'confirmation');
    assert_not_contains('&amp;#039;', $body, 'double encoding');
});

test('baseline security headers are sent', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/form.php');
    assert_same('nosniff', $r->header('X-Content-Type-Options'), 'X-Content-Type-Options');
    assert_same('DENY', $r->header('X-Frame-Options'), 'X-Frame-Options');
});
