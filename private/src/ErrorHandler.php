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

        // Exercise 07: also record it in the security log with request context.
        SecurityLogger::error('PHP_ERROR', $message, [
            'severity' => self::severityName($severity),
            'file' => self::relativePath($file),
            'line' => $line,
        ]);

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
        SecurityLogger::error('UNCAUGHT_EXCEPTION', $e->getMessage(), [
            'class' => $e::class,
            'file' => self::relativePath($e->getFile()),
            'line' => $e->getLine(),
        ]);

        self::renderErrorPage();
    }

    public static function handleShutdown(): void
    {
        self::$reservedMemory = null; // give the memory back for rendering

        $error = error_get_last();
        if ($error !== null && in_array($error['type'], self::FATAL_TYPES, true)) {
            // PHP has already written the fatal error to error_log (log_errors=On).
            SecurityLogger::error('FATAL_ERROR', $error['message'], [
                'severity' => self::severityName($error['type']),
                'file' => self::relativePath($error['file']),
                'line' => $error['line'],
            ]);
            self::renderErrorPage();
        }
    }

    private static function severityName(int $severity): string
    {
        return match ($severity) {
            E_ERROR => 'E_ERROR',
            E_WARNING => 'E_WARNING',
            E_PARSE => 'E_PARSE',
            E_NOTICE => 'E_NOTICE',
            E_CORE_ERROR => 'E_CORE_ERROR',
            E_COMPILE_ERROR => 'E_COMPILE_ERROR',
            E_USER_ERROR => 'E_USER_ERROR',
            E_USER_WARNING => 'E_USER_WARNING',
            E_USER_NOTICE => 'E_USER_NOTICE',
            E_DEPRECATED, E_USER_DEPRECATED => 'E_DEPRECATED',
            default => 'E_' . $severity,
        };
    }

    private static function relativePath(string $file): string
    {
        return str_starts_with($file, APP_ROOT) ? ltrim(substr($file, strlen(APP_ROOT)), '/\\') : $file;
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
