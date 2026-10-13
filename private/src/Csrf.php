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

    public static function generate(string $formId): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION[self::SESSION_KEY][$formId] = $token;

        return $token;
    }

    /** Hidden <input> to drop into a form. */
    public static function field(string $formId): string
    {
        return '<input type="hidden" name="' . self::FIELD . '" value="' . e(self::generate($formId)) . '">';
    }

    public static function validate(string $formId, string $submitted): bool
    {
        $expected = $_SESSION[self::SESSION_KEY][$formId] ?? null;
        unset($_SESSION[self::SESSION_KEY][$formId]); // single use

        if (!is_string($expected) || $submitted === '') {
            return false;
        }

        return hash_equals($expected, $submitted);
    }

    /**
     * Validates the token of the current POST request; rejects it with 403 otherwise.
     */
    public static function check(string $formId): void
    {
        if (self::validate($formId, post_string(self::FIELD))) {
            return;
        }

        abort(403, 'Request rejected', 'The security token is missing, expired or invalid. Please reload the form and try again.');
    }
}
