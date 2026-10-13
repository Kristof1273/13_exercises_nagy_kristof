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
 * Output encoding for HTML text and quoted attributes (Exercise 03).
 *
 * EVERY piece of user-supplied data is printed through this function:
 *   - ENT_QUOTES encodes both " and ' (attribute break-out),
 *   - ENT_SUBSTITUTE replaces invalid UTF-8 instead of returning '',
 *   - 'UTF-8' is stated explicitly.
 *
 * $doubleEncode = false is only used for values that were already encoded on
 * input (the Exercise 02 requirement for name/message): existing entities are
 * kept, everything else is still encoded. That is safe because an entity such
 * as &lt; can never turn back into markup.
 */
function e(string|int|float|null $value, bool $doubleEncode = true): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', $doubleEncode);
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

/**
 * Same as query_string() for POST fields.
 */
function post_string(string $key): string
{
    $value = $_POST[$key] ?? '';

    return is_string($value) ? $value : '';
}

/**
 * Reads a value from the session and removes it ("flash" data that survives
 * exactly one redirect).
 */
function session_pull(string $key, mixed $default = null): mixed
{
    $value = $_SESSION[$key] ?? $default;
    unset($_SESSION[$key]);

    return $value;
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
 * Renders a minimal error page and stops.
 */
function abort(int $status, string $title, string $message): never
{
    http_response_code($status);
    render_header($title);
    echo '<h1>' . e($title) . '</h1>' . PHP_EOL;
    echo '<div class="alert alert-error" role="alert">' . e($message) . '</div>' . PHP_EOL;
    echo '<p><a href="/">Back to the home page</a></p>' . PHP_EOL;
    render_footer();
    exit;
}

/**
 * Baseline security headers sent with every response.
 */
function send_security_headers(): void
{
    header('X-Content-Type-Options: nosniff');           // no MIME sniffing (e.g. text served as script)
    header('X-Frame-Options: DENY');                     // no framing -> no clickjacking
    header('Referrer-Policy: same-origin');              // don't leak URLs to other sites
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
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
    $items = [
        '/' => 'Home',
        '/error_test.php' => 'Error demo',
        '/form.php' => 'Contact form',
        '/search.php' => 'Search users',
    ];

    return Auth::check()
        ? $items + ['/dashboard.php' => 'Dashboard']
        : $items + ['/register.php' => 'Register', '/login.php' => 'Log in'];
}

function render_header(string $title): void
{
    require PRIVATE_DIR . '/templates/header.php';
}

function render_footer(): void
{
    require PRIVATE_DIR . '/templates/footer.php';
}
