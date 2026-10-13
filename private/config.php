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

    'paths' => [
        'root' => dirname(__DIR__),
        'private' => __DIR__,
        'logs' => __DIR__ . '/logs',
    ],
];
