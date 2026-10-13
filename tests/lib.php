<?php

declare(strict_types=1);

/*
 * Tiny dependency-free test toolkit: a cookie-aware HTTP "browser" built on
 * ext-curl, a few assertions and a log-file watcher.
 */

final class AssertionFailed extends RuntimeException
{
}

/** @var list<array{string, callable}> $GLOBALS['TESTS'] */
$GLOBALS['TESTS'] = [];

function test(string $name, callable $body): void
{
    $GLOBALS['TESTS'][] = [$name, $body];
}

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        throw new AssertionFailed($message);
    }
}

function assert_same(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new AssertionFailed($message . ' — expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function assert_contains(string $needle, string $haystack, string $message): void
{
    if (!str_contains($haystack, $needle)) {
        throw new AssertionFailed($message . " — '{$needle}' not found");
    }
}

function assert_not_contains(string $needle, string $haystack, string $message): void
{
    if (str_contains($haystack, $needle)) {
        throw new AssertionFailed($message . " — '{$needle}' must not appear");
    }
}

final class Response
{
    /** @param array<string, list<string>> $headers lower-cased names */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)][0] ?? null;
    }

    /** @return list<string> */
    public function headerAll(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    public function location(): ?string
    {
        return $this->header('location');
    }

    public function csrfToken(): string
    {
        if (preg_match('/name="csrf_token" value="([a-f0-9]{64})"/', $this->body, $m) !== 1) {
            throw new AssertionFailed('No CSRF token found in the page');
        }

        return $m[1];
    }
}

/**
 * Minimal browser: keeps cookies (single host), never follows redirects
 * automatically so tests can assert on them.
 */
final class Browser
{
    /** @var array<string, string> */
    public array $cookies = [];
    public string $userAgent = 'SecurityLabTest/1.0 (+tests/run.php)';

    public function __construct(public string $base)
    {
    }

    public function get(string $path, array $headers = []): Response
    {
        return $this->request('GET', $path, null, $headers);
    }

    /** @param array<string, string> $data */
    public function post(string $path, array $data, array $headers = []): Response
    {
        return $this->request('POST', $path, $data, $headers);
    }

    public function follow(Response $response): Response
    {
        $location = $response->location();
        if ($location === null) {
            throw new AssertionFailed('Expected a redirect, got HTTP ' . $response->status);
        }

        return $this->get($location);
    }

    /** @param array<string, string>|null $data */
    private function request(string $method, string $path, ?array $data, array $headers): Response
    {
        $url = str_starts_with($path, 'http') ? $path : $this->base . $path;
        $ch = curl_init($url);

        if ($this->cookies !== []) {
            $pairs = [];
            foreach ($this->cookies as $name => $value) {
                $pairs[] = $name . '=' . $value;
            }
            $headers[] = 'Cookie: ' . implode('; ', $pairs);
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_HTTPHEADER => $headers,
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data ?? []));
        }

        $raw = curl_exec($ch);
        if ($raw === false) {
            throw new AssertionFailed('HTTP request failed: ' . curl_error($ch));
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $parsed = [];
        foreach (preg_split('/\r?\n/', substr($raw, 0, $headerSize)) ?: [] as $line) {
            if (str_contains($line, ':')) {
                [$name, $value] = explode(':', $line, 2);
                $parsed[strtolower(trim($name))][] = trim($value);
            }
        }

        foreach ($parsed['set-cookie'] ?? [] as $cookie) {
            $first = explode(';', $cookie, 2)[0];
            [$name, $value] = array_pad(explode('=', $first, 2), 2, '');
            $deleted = $value === '' || $value === 'deleted' || preg_match('/expires=([^;]+)/i', $cookie, $m) === 1 && strtotime($m[1]) < time();
            if ($deleted) {
                unset($this->cookies[$name]);
            } else {
                $this->cookies[$name] = $value;
            }
        }

        return new Response($status, $parsed, substr($raw, $headerSize));
    }
}

/**
 * Remembers the size of a log file so a test can read only the lines that
 * were written after a given point.
 */
final class LogWatcher
{
    private int $offset;

    public function __construct(private string $file)
    {
        clearstatcache();
        $this->offset = is_file($file) ? (int) filesize($file) : 0;
    }

    public function newContent(): string
    {
        clearstatcache();
        // Give the server a moment to flush (fatal errors are logged during shutdown).
        usleep(150_000);
        if (!is_file($this->file)) {
            return '';
        }

        return (string) file_get_contents($this->file, false, null, $this->offset);
    }
}

/**
 * Loads a page with a form, adds its CSRF token (if the form has one) and posts it.
 *
 * @param array<string, string> $fields
 */
function submit_form(Browser $browser, string $formPage, string $action, array $fields): Response
{
    $page = $browser->get($formPage);
    if (str_contains($page->body, 'name="csrf_token"')) {
        $fields += ['csrf_token' => $page->csrfToken()];
    }

    return $browser->post($action, $fields);
}

/** @return array<string, string> */
function valid_contact(): array
{
    return [
        'name' => 'Ada Lovelace',
        'email' => 'ada@example.com',
        'age' => '36',
        'website' => 'https://example.com/ada',
        'message' => 'Hello there!',
    ];
}

function login(Browser $browser, string $username, string $password): Response
{
    return submit_form($browser, '/login.php', '/login.php', ['username' => $username, 'password' => $password]);
}

/** alice is registered by the Exercise 04 tests. */
function login_as_searcher(Browser $browser): void
{
    $r = login($browser, 'alice', 'Correct-Horse-9');
    assert_same('/dashboard.php', $r->location(), 'login as alice');
}

function session_cookie_name(Browser $browser): ?string
{
    foreach (array_keys($browser->cookies) as $name) {
        if (str_contains($name, 'SESS')) {
            return $name;
        }
    }

    return null;
}
