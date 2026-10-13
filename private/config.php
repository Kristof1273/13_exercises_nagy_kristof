<?php

declare(strict_types=1);

/*
 * Central configuration.
 * Lives in private/, so the web server can never send it to a browser.
 * Every value can be overridden with an environment variable (used by the
 * automated tests and for production deployments).
 */

$env = static function (string $key, ?string $default = null): ?string {
    $value = getenv($key);

    return ($value === false || $value === '') ? $default : $value;
};

$appEnv = $env('APP_ENV', 'development');

return [
    'app' => [
        'name' => 'PHP Security Lab',
        'env' => $appEnv,
        'timezone' => $env('APP_TIMEZONE', 'UTC'),
        // Demo pages (error trigger, deliberately vulnerable search) are only
        // served to localhost and only while this flag is on. Off in production.
        'demo_pages' => filter_var(
            $env('APP_DEMO_PAGES', $appEnv === 'production' ? '0' : '1'),
            FILTER_VALIDATE_BOOL
        ),
    ],

    // Exercise 04 — SQLite by default (zero setup). For MySQL set e.g.
    //   DB_DSN="mysql:host=127.0.0.1;dbname=security_lab;charset=utf8mb4"
    //   DB_USERNAME=... DB_PASSWORD=...
    'db' => [
        'dsn' => $env('DB_DSN', 'sqlite:' . __DIR__ . '/db/app.sqlite'),
        'username' => $env('DB_USERNAME'),
        'password' => $env('DB_PASSWORD'),
    ],

    // Exercise 06 — session hardening
    'session' => [
        'name' => 'SECSESSID',
        // Idle timeout in seconds (30 minutes). The tests shorten it via the env var.
        'idle_timeout' => (int) $env('SESSION_IDLE_TIMEOUT', '1800'),
        // 'auto' = Secure flag only when the request arrived over HTTPS.
        // Use SESSION_COOKIE_SECURE=1 in production / behind a TLS-terminating proxy.
        'cookie_secure' => $env('SESSION_COOKIE_SECURE', 'auto'),
        'samesite' => 'Strict',
        // Fingerprint checked on every request (see Session::enforceFingerprint()).
        // IP binding can log out mobile users whose IP changes; it is a trade-off.
        'bind_ip' => filter_var($env('SESSION_BIND_IP', '1'), FILTER_VALIDATE_BOOL),
        'bind_user_agent' => true,
    ],

    // Exercise 07 — brute-force protection
    'security' => [
        'login_max_attempts' => 5,          // failed logins per IP ...
        'login_window' => 600,              // ... within 10 minutes -> blocked
        'repeated_failures_warning' => 3,   // log a warning from the 3rd failure on
    ],

    // Extra Mile — encryption key: APP_KEY (base64, 32 bytes) in production,
    // otherwise a key file that is generated on first use (git-ignored).
    'crypto' => [
        'key' => $env('APP_KEY'),
        'key_file' => __DIR__ . '/keys/app.key',
    ],

    'paths' => [
        'root' => dirname(__DIR__),
        'private' => __DIR__,
        'logs' => __DIR__ . '/logs',
        'security_log' => __DIR__ . '/logs/security.log',
        'sessions' => __DIR__ . '/sessions',
    ],
];
