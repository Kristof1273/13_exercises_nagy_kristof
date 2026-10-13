<?php

declare(strict_types=1);

// Extra Mile 2 — encryption & decryption

require_once TEST_ROOT . '/private/src/Crypto.php';
require_once TEST_ROOT . '/private/src/CryptoException.php';

test('encrypt/decrypt round trip (unit)', function (): void {
    $crypto = new Crypto(random_bytes(32));
    $secret = "Árvíztűrő tükörfúrógép 🔐\nsecond line";
    $ciphertext = $crypto->encrypt($secret);
    assert_true(str_starts_with($ciphertext, 'v1:'), 'version prefix');
    assert_not_contains('tükörfúrógép', $ciphertext, 'no plaintext inside');
    assert_same($secret, $crypto->decrypt($ciphertext), 'round trip');
});

test('the same plaintext encrypts differently every time (random IV)', function (): void {
    $crypto = new Crypto(random_bytes(32));
    assert_true($crypto->encrypt('same') !== $crypto->encrypt('same'), 'ciphertexts differ');
});

test('tampered ciphertext or a wrong key is detected (HMAC)', function (): void {
    $crypto = new Crypto(random_bytes(32));
    $raw = base64_decode(substr($crypto->encrypt('pay 100 EUR to Alice'), 3));
    $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1); // flip one bit
    foreach (['tampered' => [$crypto, 'v1:' . base64_encode($raw)], 'wrong key' => [new Crypto(random_bytes(32)), $crypto->encrypt('x')]] as $case => [$c, $payload]) {
        try {
            $c->decrypt($payload);
            throw new AssertionFailed("{$case}: decrypt() must fail");
        } catch (CryptoException) {
            // expected
        }
    }
});

test('notes are stored encrypted and shown decrypted', function (): void {
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    $r = submit_form($browser, '/notes.php', '/notes.php', ['note' => 'My bank PIN hint: blue elephant']);
    assert_same('/notes.php', $r->location(), 'redirect');
    assert_contains('My bank PIN hint: blue elephant', $browser->get('/notes.php')->body, 'decrypted on the page');

    $body = (string) (new PDO('sqlite:' . TEST_DB))->query('SELECT body FROM notes ORDER BY id DESC LIMIT 1')->fetchColumn();
    assert_true(str_starts_with($body, 'v1:'), 'ciphertext format');
    assert_not_contains('blue elephant', $body, 'no plaintext in the database');
    assert_not_contains('blue elephant', base64_decode(substr($body, 3)), 'not just base64');
});

test("another user can neither see nor delete someone else's note", function (): void {
    $pdo = new PDO('sqlite:' . TEST_DB);
    $noteId = (int) $pdo->query('SELECT MAX(id) FROM notes')->fetchColumn();

    $other = new Browser(SERVER_URLS['main']);
    register_user($other, 'mallory', 'mallory@example.com', 'Sneaky-Person-11');
    login($other, 'mallory', 'Sneaky-Person-11');
    $page = $other->get('/notes.php');
    assert_not_contains('blue elephant', $page->body, 'not visible');

    $other->post('/notes.php', ['action' => 'delete', 'note_id' => (string) $noteId, 'csrf_token' => $page->csrfToken('/notes.php')]);
    assert_same(1, (int) $pdo->query("SELECT COUNT(*) FROM notes WHERE id = {$noteId}")->fetchColumn(), 'note still exists');
});

test('a note modified directly in the database fails the integrity check', function (): void {
    $pdo = new PDO('sqlite:' . TEST_DB);
    $row = $pdo->query('SELECT id, body FROM notes ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    $raw = base64_decode(substr($row['body'], 3));
    $raw[20] = chr(ord($raw[20]) ^ 1);
    $stmt = $pdo->prepare('UPDATE notes SET body = :b WHERE id = :id');
    $stmt->execute([':b' => 'v1:' . base64_encode($raw), ':id' => $row['id']]);

    $log = new LogWatcher(TEST_ROOT . '/private/logs/security.log');
    $browser = new Browser(SERVER_URLS['main']);
    login_as_tester($browser);
    assert_contains('Integrity check failed', $browser->get('/notes.php')->body, 'error shown');
    assert_contains('DECRYPTION_FAILED', $log->newContent(), 'logged');
});
