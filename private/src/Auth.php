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

    public static function attempt(string $username, string $password): LoginResult
    {
        $ip = client_ip();
        $throttle = LoginThrottle::default();

        // Exercise 07 — brute-force protection: a blocked IP is refused before the
        // password is even checked, so it learns nothing from further guesses.
        $wait = $throttle->retryAfter($ip);
        if ($wait > 0) {
            SecurityLogger::alert('LOGIN_BLOCKED', 'Login attempt refused: too many recent failures from this IP', [
                'username' => $username,
                'retry_after_seconds' => $wait,
            ]);

            return LoginResult::blocked($wait);
        }

        $users = UserRepository::default();
        $user = $users->findByUsername($username);

        $hash = is_string($user['password'] ?? null) ? $user['password'] : self::DUMMY_HASH;
        if (!password_verify($password, $hash) || $user === null) {
            $failures = $throttle->recordFailure($ip, $username);
            SecurityLogger::warning('LOGIN_FAILED', 'Failed login attempt', [
                'username' => $username,
                'reason' => $user === null ? 'unknown_user' : 'wrong_password',
                'failures_in_window' => $failures,
            ]);

            if ($failures >= $throttle->maxAttempts()) {
                SecurityLogger::alert('BRUTE_FORCE_DETECTED', sprintf(
                    '%d failed logins from this IP within %d minutes — further attempts are blocked',
                    $failures,
                    $throttle->windowMinutes()
                ), ['username' => $username, 'failures_in_window' => $failures]);

                return LoginResult::blocked($throttle->retryAfter($ip));
            }
            if ($failures >= (int) config('security.repeated_failures_warning')) {
                SecurityLogger::warning('REPEATED_FAILED_LOGINS', 'Several failed logins from the same IP', [
                    'failures_in_window' => $failures,
                ]);
            }

            return LoginResult::failed();
        }

        // Keep hashes up to date when PHP's default algorithm or our cost changes.
        if (password_needs_rehash($hash, PASSWORD_DEFAULT, self::HASH_OPTIONS)) {
            $users->updatePassword((int) $user['id'], self::hashPassword($password));
        }

        self::startAuthenticatedSession((int) $user['id'], (string) $user['username']);
        SecurityLogger::info('LOGIN_SUCCESS', 'User logged in', [
            'user_id' => (int) $user['id'],
            'username' => (string) $user['username'],
        ]);

        return LoginResult::success();
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
        Session::bindToClient(); // Exercise 06: remember IP + User-Agent
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
            // Tell the user WHY they have to log in again (fixed keys, see login.php).
            $status = match (Session::endReason()) {
                'expired' => 'expired',
                'fingerprint' => 'session_invalid',
                default => 'login_required',
            };
            redirect('/login.php?status=' . $status);
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
        SecurityLogger::info('LOGOUT', 'User logged out', ['user_id' => self::user()['id'] ?? null]);

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
