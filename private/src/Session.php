<?php

declare(strict_types=1);

/**
 * Hardened session handling (Exercise 06).
 *
 *  - cookie: HttpOnly, Secure (on HTTPS), SameSite=Strict, host-only, session cookie
 *  - strict mode: IDs the server never issued are rejected and replaced
 *  - idle timeout: session is wiped after 30 minutes without a request
 *  - fingerprint: IP address + User-Agent stored at login, checked on every request
 */
final class Session
{
    /** Why the authenticated session was ended in this request: 'expired' | 'fingerprint' | null */
    private static ?string $endReason = null;

    public static function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $secure = self::useSecureCookie();
        $name = (string) config('session.name');
        if ($secure) {
            // "__Host-" prefix: the browser only accepts this cookie when it is Secure,
            // has Path=/ and no Domain -> it cannot be planted by a subdomain or over HTTP.
            $name = '__Host-' . $name;
        }

        $savePath = (string) config('paths.sessions');
        if (!is_dir($savePath)) {
            mkdir($savePath, 0700, true);
        }

        ini_set('session.use_strict_mode', '1');   // reject session IDs the server did not create
        ini_set('session.use_only_cookies', '1');  // never accept an ID from the URL (?PHPSESSID=...)
        ini_set('session.use_trans_sid', '0');     // never append the ID to URLs
        ini_set('session.save_path', $savePath);   // session files in private/sessions, not a shared /tmp
        ini_set('session.gc_maxlifetime', (string) max(1440, self::idleTimeout()));
        ini_set('session.gc_probability', '1');
        ini_set('session.gc_divisor', '100');

        session_name($name);
        session_set_cookie_params([
            'lifetime' => 0,        // deleted when the browser closes
            'path' => '/',
            'domain' => '',         // host-only: not sent to subdomains
            'secure' => $secure,    // only sent over HTTPS
            'httponly' => true,     // invisible to JavaScript (document.cookie) -> XSS can't steal it
            'samesite' => (string) config('session.samesite'), // not sent with cross-site requests
        ]);

        $presentedId = $_COOKIE[$name] ?? null;
        session_start();

        if (is_string($presentedId) && $presentedId !== session_id()) {
            // Strict mode threw away an ID it did not know: forged, tampered with,
            // or belonging to a session that no longer exists.
            SecurityLogger::warning('SESSION_ID_REJECTED', 'Unknown session ID presented (tampered, forged or expired) — new ID issued', [
                'presented_id_prefix' => substr($presentedId, 0, 6) . '…',
            ]);
        }

        self::enforceIdleTimeout();
        self::enforceFingerprint();
    }

    /**
     * Called right after a successful login: remember who the session belongs to.
     */
    public static function bindToClient(): void
    {
        $_SESSION['_fingerprint'] = self::currentFingerprint();
        $_SESSION['_last_activity'] = time();
    }

    public static function endReason(): ?string
    {
        return self::$endReason;
    }

    public static function idleTimeout(): int
    {
        return max(1, (int) config('session.idle_timeout'));
    }

    /** "30 minutes" / "3 seconds" */
    public static function idleTimeoutLabel(): string
    {
        $seconds = self::idleTimeout();

        return $seconds >= 120 && $seconds % 60 === 0 ? intdiv($seconds, 60) . ' minutes' : $seconds . ' seconds';
    }

    /** Seconds until the session expires if the user stays idle. */
    public static function secondsLeft(): int
    {
        $last = (int) ($_SESSION['_last_activity'] ?? time());

        return max(0, $last + self::idleTimeout() - time());
    }

    private static function enforceIdleTimeout(): void
    {
        $now = time();
        $last = $_SESSION['_last_activity'] ?? null;

        if (is_int($last) && $now - $last > self::idleTimeout()) {
            $user = $_SESSION['user'] ?? null;
            self::wipe();
            if (is_array($user)) {
                self::$endReason = 'expired';
                SecurityLogger::info('SESSION_EXPIRED', 'Session ended after the idle timeout', [
                    'user_id' => $user['id'] ?? null,
                    'username' => $user['username'] ?? null,
                    'idle_seconds' => $now - $last,
                ]);
            }
        }

        $_SESSION['_last_activity'] = $now;
    }

    private static function enforceFingerprint(): void
    {
        $stored = $_SESSION['_fingerprint'] ?? null;
        if (!is_array($stored)) {
            return; // anonymous session, nothing bound yet
        }

        $current = self::currentFingerprint();
        $mismatch = [];
        foreach ($current as $key => $value) {
            if (!is_string($stored[$key] ?? null) || !hash_equals($stored[$key], $value)) {
                $mismatch[] = $key;
            }
        }

        if ($mismatch !== []) {
            $user = $_SESSION['user'] ?? null;
            self::wipe();
            self::$endReason = 'fingerprint';
            // Possible session hijacking: the cookie is being used from another client.
            SecurityLogger::alert('SESSION_FINGERPRINT_MISMATCH', 'Session used from a different IP/User-Agent — session destroyed', [
                'user_id' => is_array($user) ? ($user['id'] ?? null) : null,
                'username' => is_array($user) ? ($user['username'] ?? null) : null,
                'changed' => $mismatch,
                'expected' => $stored,
                'actual' => $current,
            ]);
        }
    }

    /**
     * @return array<string, string>
     */
    private static function currentFingerprint(): array
    {
        $fingerprint = [];
        if (config('session.bind_ip')) {
            $fingerprint['ip'] = client_ip();
        }
        if (config('session.bind_user_agent')) {
            $fingerprint['user_agent'] = mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512, 'UTF-8');
        }

        return $fingerprint;
    }

    /**
     * Empties the session and moves it to a brand-new ID (old data file deleted).
     */
    private static function wipe(): void
    {
        $_SESSION = [];
        session_regenerate_id(true);
    }

    private static function useSecureCookie(): bool
    {
        return match (strtolower((string) config('session.cookie_secure'))) {
            '1', 'true', 'on', 'yes' => true,
            '0', 'false', 'off', 'no' => false,
            default => is_https(), // 'auto'
        };
    }
}
