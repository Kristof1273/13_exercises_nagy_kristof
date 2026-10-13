<?php

declare(strict_types=1);

// Exercise 02 — input validation & sanitization

test('valid submission redirects to the confirmation page', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', valid_contact());
    assert_same(303, $r->status, 'status');
    assert_same('/confirmation.php', $r->location(), 'redirect target');
    $page = $browser->follow($r);
    assert_contains('Ada Lovelace', $page->body, 'confirmation');
    assert_contains('ada@example.com', $page->body, 'confirmation');
});

test('GET on the handler is rejected with 405', function (): void {
    $r = (new Browser(SERVER_URLS['main']))->get('/process.php');
    assert_same(405, $r->status, 'status');
});

test('missing required fields redirect back with errors', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', ['name' => '', 'email' => '', 'age' => '', 'message' => '']);
    assert_same('/form.php', $r->location(), 'redirect target');
    $form = $browser->follow($r);
    foreach (['Name is required.', 'Email is required.', 'Age is required.', 'Message is required.'] as $msg) {
        assert_contains($msg, $form->body, 'error list');
    }
});

test('each validation rule is enforced', function (): void {
    $cases = [
        'name' => [str_repeat('a', 51), 'Name must not exceed 50 characters.'],
        'email' => ['not-an-email', 'Please enter a valid email address.'],
        'age' => ['abc', 'Age must be a number.'],
        'website' => ['javascript://%0Aalert(1)', 'Website must be a valid http:// or https:// URL.'],
        'message' => [str_repeat('m', 501), 'Message must not exceed 500 characters.'],
    ];
    foreach ($cases as $field => [$value, $message]) {
        $browser = new Browser(SERVER_URLS['main']);
        $r = submit_form($browser, '/form.php', '/process.php', [$field => $value] + valid_contact());
        assert_same('/form.php', $r->location(), "{$field}: redirect");
        assert_contains($message, $browser->follow($r)->body, "{$field}: error message");
    }
});

test('50 multibyte characters are accepted (length is counted in characters)', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', ['name' => str_repeat('ő', 50)] + valid_contact());
    assert_same('/confirmation.php', $r->location(), 'redirect target');
});

test('<script> in the name is neutralised', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', ['name' => "<script>alert('XSS')</script>"] + valid_contact());
    $page = $browser->follow($r);
    assert_not_contains('<script>', $page->body, 'confirmation page');
    assert_contains('alert(&#039;XSS&#039;)', $page->body, 'tags stripped, quotes encoded');
});

test('a value consisting only of tags is rejected', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    $r = submit_form($browser, '/form.php', '/process.php', ['message' => '<b></b><i></i>'] + valid_contact());
    assert_contains('Message must contain text', $browser->follow($r)->body, 'error');
});
