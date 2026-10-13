<?php

declare(strict_types=1);

/**
 * Centralised error handling (Exercise 01).
 *
 * - Warnings/notices: PHP's own handler writes them to error_log (display_errors
 *   is off, so nothing reaches the browser).
 * - Uncaught exceptions and fatal errors: logged, and the visitor gets a generic
 *   HTTP 500 page that reveals nothing about the code, paths or PHP version.
 */
final class ErrorHandler
{
    /** Memory reserved so the fatal-error page can still be rendered after an out-of-memory error. */
    private static ?string $reservedMemory = null;

    private const FATAL_TYPES = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];

    public static function register(): void
    {
        // Buffer output so a half-rendered page can be discarded on a fatal error.
        ob_start();

        self::$reservedMemory = str_repeat(' ', 64 * 1024);

        set_error_handler([self::class, 'handleError']);
        set_exception_handler([self::class, 'handleException']);
        register_shutdown_function([self::class, 'handleShutdown']);
    }

    public static function handleError(int $severity, string $message, string $file = '', int $line = 0): bool
    {
        if ((error_reporting() & $severity) === 0) {
            return false; // silenced with @ or excluded by error_reporting
        }

        // false = continue with PHP's standard handler, which writes the entry
        // to error_log because log_errors=On (and displays nothing).
        return false;
    }

    public static function handleException(Throwable $e): void
    {
        // A custom exception handler replaces PHP's default logging, so log it ourselves.
        error_log(sprintf(
            'PHP Uncaught %s: %s in %s:%d%sStack trace:%s%s',
            $e::class,
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            PHP_EOL,
            PHP_EOL,
            $e->getTraceAsString()
        ));

        self::renderErrorPage();
    }

    public static function handleShutdown(): void
    {
        self::$reservedMemory = null; // give the memory back for rendering

        $error = error_get_last();
        if ($error !== null && in_array($error['type'], self::FATAL_TYPES, true)) {
            // PHP has already written the fatal error to error_log (log_errors=On).
            self::renderErrorPage();
        }
    }

    private static function renderErrorPage(): void
    {
        // Throw away anything that was already rendered.
        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/html; charset=UTF-8');
            header('Cache-Control: no-store');
        }

        echo <<<HTML
            <!doctype html>
            <html lang="en">
            <head><meta charset="utf-8"><title>Server error</title><link rel="stylesheet" href="/assets/app.css"></head>
            <body><main class="container narrow">
              <h1>Something went wrong</h1>
              <p>An unexpected error occurred. It has been logged and will be looked at.</p>
              <p><a href="/">Back to the home page</a></p>
            </main></body>
            </html>
            HTML;
    }
}
