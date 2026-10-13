<?php

declare(strict_types=1);

/**
 * Reads a configuration value with "dot" notation, e.g. config('app.name').
 */
function config(string $key, mixed $default = null): mixed
{
    $value = $GLOBALS['APP_CONFIG'] ?? [];
    foreach (explode('.', $key) as $segment) {
        if (!is_array($value) || !array_key_exists($segment, $value)) {
            return $default;
        }
        $value = $value[$segment];
    }

    return $value;
}

/**
 * HTML-escapes a value for output in HTML text or a quoted attribute.
 */
function e(string|int|float|null $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Returns a GET parameter as a string. Arrays (?x[]=1) are rejected, which
 * avoids type-juggling surprises and "Array to string conversion" warnings.
 */
function query_string(string $key): string
{
    $value = $_GET[$key] ?? '';

    return is_string($value) ? $value : '';
}

function client_ip(): string
{
    // Only REMOTE_ADDR is trustworthy. X-Forwarded-For is client-controlled
    // unless a trusted reverse proxy sets it.
    return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
}

function is_local_request(): bool
{
    return in_array(client_ip(), ['127.0.0.1', '::1'], true);
}

function current_path(): string
{
    return (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
}

/**
 * Redirects to an internal path. Only "/something" is accepted, so this helper
 * can never be abused as an open redirect ("//evil.example", "https://...").
 */
function redirect(string $path, int $status = 303): never
{
    if (!str_starts_with($path, '/') || str_starts_with($path, '//') || str_contains($path, "\\")) {
        $path = '/';
    }
    header('Location: ' . $path, true, $status);
    exit;
}

/**
 * Demo pages (deliberately unsafe or noisy) are only served to localhost and
 * only while APP_DEMO_PAGES is enabled. Everybody else gets a plain 404.
 */
function require_demo_mode(): void
{
    if (!config('app.demo_pages') || !is_local_request()) {
        http_response_code(404);
        exit('Not Found');
    }
}

/**
 * @return array<string, string> href => label
 */
function nav_items(): array
{
    return [
        '/' => 'Home',
        '/error_test.php' => 'Error demo',
    ];
}

function render_header(string $title): void
{
    require PRIVATE_DIR . '/templates/header.php';
}

function render_footer(): void
{
    require PRIVATE_DIR . '/templates/footer.php';
}
