<?php

declare(strict_types=1);

/**
 * Authentication (Exercise 05).
 */
final class Auth
{
    /** bcrypt via PASSWORD_DEFAULT; cost 12 ≈ a few hundred ms per hash. */
    public const HASH_OPTIONS = ['cost' => 12];

    /**
     * A real bcrypt hash of a random throw-away string. When the username does
     * not exist we still run password_verify() against it, so "unknown user"
     * takes as long as "wrong password" — no user enumeration through timing.
     */
    private const DUMMY_HASH = '$2y$12$Clhn02u6uENRfvfLAtHSvuHh8kfmropbGPVGHFNw4/GuVjrgc22z6';

    public static function hashPassword(string $password): string
    {
        // Salt is generated automatically and stored inside the hash string
        // together with the algorithm and cost: "$2y$12$<salt><hash>" (60 chars).
        return password_hash($password, PASSWORD_DEFAULT, self::HASH_OPTIONS);
    }

    /**
     * Password policy for new passwords.
     *
     * @return list<string> error messages (empty = OK)
     */
    public static function validateNewPassword(string $password, string $confirmation, string $username): array
    {
        $errors = [];
        if (mb_strlen($password, 'UTF-8') < 10) {
            $errors[] = 'Password must be at least 10 characters long.';
        }
        // bcrypt only looks at the first 72 BYTES; anything longer would be silently ignored.
        if (strlen($password) > 72) {
            $errors[] = 'Password must not be longer than 72 bytes.';
        }
        if ($username !== '' && stripos($password, $username) !== false) {
            $errors[] = 'Password must not contain the username.';
        }
        if (!hash_equals($password, $confirmation)) {
            $errors[] = 'The two passwords do not match.';
        }

        return $errors;
    }

    public static function attempt(string $username, string $password): bool
    {
        $users = UserRepository::default();
        $user = $users->findByUsername($username);

        $hash = is_string($user['password'] ?? null) ? $user['password'] : self::DUMMY_HASH;
        if (!password_verify($password, $hash) || $user === null) {
            return false;
        }

        // Keep hashes up to date when PHP's default algorithm or our cost changes.
        if (password_needs_rehash($hash, PASSWORD_DEFAULT, self::HASH_OPTIONS)) {
            $users->updatePassword((int) $user['id'], self::hashPassword($password));
        }

        self::startAuthenticatedSession((int) $user['id'], (string) $user['username']);

        return true;
    }

    /**
     * Session fixation defense: whenever the privilege level changes, the old
     * session ID is thrown away (true = delete the old session data too). An
     * ID planted by an attacker before login is worthless afterwards.
     */
    public static function startAuthenticatedSession(int $userId, string $username): void
    {
        session_regenerate_id(true);
        $_SESSION['user'] = ['id' => $userId, 'username' => $username];
        $_SESSION['auth_time'] = time();
    }

    /** @return array{id: int, username: string}|null */
    public static function user(): ?array
    {
        $user = $_SESSION['user'] ?? null;

        return is_array($user) ? $user : null;
    }

    public static function check(): bool
    {
        return self::user() !== null;
    }

    /**
     * Guard for protected pages: anonymous visitors are sent to the login page.
     *
     * @return array{id: int, username: string}
     */
    public static function requireLogin(): array
    {
        $user = self::user();
        if ($user === null) {
            redirect('/login.php?status=login_required');
        }

        // Personal pages must not be stored by the browser or proxies
        // (otherwise "Back" after logout could show them again).
        header('Cache-Control: no-store, private');

        return $user;
    }

    /**
     * Logout: empty the session, delete its cookie, destroy the server-side data.
     */
    public static function logout(): void
    {
        $_SESSION = [];

        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'],
        ]);

        session_destroy();
    }
}
