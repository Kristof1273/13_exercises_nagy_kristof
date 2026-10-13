<?php

declare(strict_types=1);

/**
 * Synchronizer-token CSRF protection (Exercise 03).
 *
 * - A fresh 256-bit token (bin2hex(random_bytes(32))) is generated every time a
 *   form is rendered and stored in $_SESSION under the form's id.
 * - The token travels back in a hidden field; the handler compares it with the
 *   stored one using hash_equals() (constant-time, no timing leak).
 * - Tokens are single-use: they are removed on the first check, so a captured
 *   request cannot be replayed.
 *
 * An attacker's page can make the victim's browser send a request WITH the
 * victim's cookies, but it cannot read our page, so it cannot know the token.
 */
final class Csrf
{
    public const FIELD = 'csrf_token';
    private const SESSION_KEY = '_csrf_tokens';

    /** @var array<string, string> tokens already issued during this request */
    private static array $issued = [];

    public static function generate(string $formId): string
    {
        // One token per form per page load: if the same form appears twice on a
        // page (e.g. the logout button in the header and on /logout.php) both
        // copies must carry the same, currently valid token.
        if (isset(self::$issued[$formId])) {
            return self::$issued[$formId];
        }

        $token = bin2hex(random_bytes(32));
        $_SESSION[self::SESSION_KEY][$formId] = $token;

        return self::$issued[$formId] = $token;
    }

    /** Hidden <input> to drop into a form. */
    public static function field(string $formId): string
    {
        return '<input type="hidden" name="' . self::FIELD . '" value="' . e(self::generate($formId)) . '">';
    }

    public static function validate(string $formId, string $submitted): bool
    {
        return self::failureReason($formId, $submitted) === null;
    }

    /**
     * Validates the token of the current POST request; rejects it with 403 otherwise.
     */
    public static function check(string $formId): void
    {
        if (!self::passes($formId)) {
            abort(403, 'Request rejected', 'The security token is missing, expired or invalid. Please reload the form and try again.');
        }
    }

    /**
     * Like check(), but lets the caller decide what to do on failure.
     * Every failure is written to the security log (Exercise 07).
     */
    public static function passes(string $formId): bool
    {
        $reason = self::failureReason($formId, post_string(self::FIELD));
        if ($reason === null) {
            return true;
        }

        SecurityLogger::alert('CSRF_TOKEN_MISMATCH', 'Request rejected: CSRF token ' . $reason, [
            'form' => $formId,
            'reason' => $reason,
            'origin' => $_SERVER['HTTP_ORIGIN'] ?? null,
            'referer' => $_SERVER['HTTP_REFERER'] ?? null,
        ]);

        return false;
    }

    /** null = valid; otherwise why it failed. */
    private static function failureReason(string $formId, string $submitted): ?string
    {
        $expected = $_SESSION[self::SESSION_KEY][$formId] ?? null;
        unset($_SESSION[self::SESSION_KEY][$formId]); // single use

        return match (true) {
            $submitted === '' => 'missing',
            !is_string($expected) => 'not issued for this session (expired, replayed or foreign)',
            !hash_equals($expected, $submitted) => 'mismatch',
            default => null,
        };
    }
}
