<?php

declare(strict_types=1);

/**
 * Security event log (Exercise 07) — private/logs/security.log
 *
 * One event per line:
 *   [2026-10-13T11:04:05.123+00:00] ALERT   CSRF_TOKEN_MISMATCH ip=127.0.0.1 user=- req="POST /process.php" msg="..." ctx={"form":"contact"}
 *
 * Log injection (CWE-117) is impossible: every value that could contain user
 * input is JSON-encoded, which escapes newlines and other control characters,
 * so an attacker cannot forge extra lines. Secrets (passwords, tokens) are
 * redacted, long values are truncated.
 */
final class SecurityLogger
{
    public const INFO = 'INFO';        // normal but security-relevant (login, logout, password change)
    public const WARNING = 'WARNING';  // suspicious (failed login, XSS-looking input)
    public const ALERT = 'ALERT';      // likely attack (CSRF mismatch, SQLi pattern, brute force)
    public const ERROR = 'ERROR';      // PHP errors and exceptions

    private const MAX_VALUE_LENGTH = 200;
    private const SECRET_KEYS = '/pass|token|secret|key|cookie|session_id/i';

    /** Guards against recursion if writing the log itself raises a PHP error. */
    private static bool $writing = false;

    public static function info(string $event, string $message, array $context = []): void
    {
        self::log(self::INFO, $event, $message, $context);
    }

    public static function warning(string $event, string $message, array $context = []): void
    {
        self::log(self::WARNING, $event, $message, $context);
    }

    public static function alert(string $event, string $message, array $context = []): void
    {
        self::log(self::ALERT, $event, $message, $context);
    }

    public static function error(string $event, string $message, array $context = []): void
    {
        self::log(self::ERROR, $event, $message, $context);
    }

    public static function log(string $level, string $event, string $message, array $context = []): void
    {
        if (self::$writing) {
            return;
        }
        self::$writing = true;

        try {
            $user = '-';
            if (session_status() === PHP_SESSION_ACTIVE && is_string($_SESSION['user']['username'] ?? null)) {
                $user = $_SESSION['user']['username'];
            }
            $request = PHP_SAPI === 'cli'
                ? 'CLI ' . implode(' ', $GLOBALS['argv'] ?? [])
                : ($_SERVER['REQUEST_METHOD'] ?? '?') . ' ' . ($_SERVER['REQUEST_URI'] ?? '?');

            $line = sprintf(
                '[%s] %-7s %s ip=%s user=%s req=%s msg=%s ctx=%s',
                (new DateTimeImmutable())->format('Y-m-d\TH:i:s.vP'),
                $level,
                preg_replace('/[^A-Z0-9_]/', '', strtoupper($event)),
                self::json(PHP_SAPI === 'cli' ? 'cli' : client_ip()),
                self::json($user),
                self::json(self::truncate($request)),
                self::json(self::truncate($message)),
                self::json(self::sanitizeContext($context))
            );

            $file = (string) config('paths.security_log');
            $isNew = !is_file($file);
            if (file_put_contents($file, $line . PHP_EOL, FILE_APPEND | LOCK_EX) === false) {
                error_log('SecurityLogger: cannot write ' . $file . ' — ' . $line);
            } elseif ($isNew) {
                chmod($file, 0640);
            }
        } catch (Throwable $e) {
            // Logging must never take the application down.
            error_log('SecurityLogger failure: ' . $e->getMessage());
        } finally {
            self::$writing = false;
        }
    }

    private static function json(mixed $value): string
    {
        // Escapes \n, \r, \t, \0, quotes, U+2028/2029 … -> one event = one line.
        return (string) json_encode(
            $value,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR
        );
    }

    private static function truncate(string $value): string
    {
        return mb_strlen($value, 'UTF-8') > self::MAX_VALUE_LENGTH
            ? mb_substr($value, 0, self::MAX_VALUE_LENGTH, 'UTF-8') . '…'
            : $value;
    }

    /**
     * @param array<array-key, mixed> $context
     * @return array<array-key, mixed>
     */
    private static function sanitizeContext(array $context, int $depth = 0): array
    {
        $clean = [];
        foreach ($context as $key => $value) {
            if (is_string($key) && preg_match(self::SECRET_KEYS, $key) === 1) {
                $clean[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $clean[$key] = $depth < 3 ? self::sanitizeContext($value, $depth + 1) : '[…]';
            } elseif (is_string($value)) {
                $clean[$key] = self::truncate($value);
            } elseif (is_scalar($value) || $value === null) {
                $clean[$key] = $value;
            } else {
                $clean[$key] = get_debug_type($value);
            }
        }

        return $clean;
    }
}
