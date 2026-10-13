<?php

declare(strict_types=1);

/*
 * Application bootstrap.
 *
 * Every public entry point starts with:
 *     require __DIR__ . '/../private/bootstrap.php';
 *
 * This file is inside private/, which is outside the document root, so it can
 * be included by PHP but never requested by a browser.
 */

define('APP_ROOT', dirname(__DIR__));
define('PRIVATE_DIR', __DIR__);

$GLOBALS['APP_CONFIG'] = require PRIVATE_DIR . '/config.php';

require PRIVATE_DIR . '/src/helpers.php';

// Simple autoloader for the classes in private/src (class name = file name).
spl_autoload_register(static function (string $class): void {
    if (preg_match('/^[A-Za-z][A-Za-z0-9_]*$/', $class) !== 1) {
        return;
    }
    $file = PRIVATE_DIR . '/src/' . $class . '.php';
    if (is_file($file)) {
        require $file;
    }
});

// ---------------------------------------------------------------------------
// Exercise 01 — runtime error configuration (ini_set)
// These are PHP_INI_ALL directives, so they can be (and are) enforced here even
// if the server was started without our php.ini.
// ---------------------------------------------------------------------------
$logDir = config('paths.logs');
if (!is_dir($logDir)) {
    mkdir($logDir, 0750, true);
}

ini_set('display_errors', '0');           // never show error details to visitors
ini_set('display_startup_errors', '0');
ini_set('html_errors', '0');              // plain-text messages in the log
ini_set('log_errors', '1');               // ...but always record them
ini_set('error_log', $logDir . '/php_errors.log');
error_reporting(E_ALL);

date_default_timezone_set(config('app.timezone'));

// expose_php is PHP_INI_SYSTEM (set in php.ini). Runtime fallback for servers
// that were not started with our php.ini:
header_remove('X-Powered-By');

ErrorHandler::register();

// Command-line tools (bin/*.php) reuse the bootstrap but need no headers or session.
if (PHP_SAPI !== 'cli') {
    send_security_headers();

    // Sessions carry validation errors / results across redirects (Exercise 02).
    // They are hardened in Exercise 06.
    session_start();
}
