<?php

declare(strict_types=1);

/**
 * Brute-force protection (Exercise 07).
 *
 * After `max_attempts` (5) failed logins from the same IP within `window`
 * seconds (10 minutes), further attempts from that IP are refused without even
 * checking the password. Sliding window: the IP may try again as soon as the
 * oldest of those failures is older than 10 minutes.
 *
 * Design notes:
 *  - Counted per IP (as the exercise asks). Per-account counting would let an
 *    attacker lock real users out of their accounts on purpose.
 *  - A successful login does NOT reset the counter, otherwise an attacker with
 *    one valid account could interleave its own logins to keep guessing.
 *  - Stored in the database, not in the session: an attacker simply would not
 *    send the session cookie.
 */
final class LoginThrottle
{
    public function __construct(
        private readonly PDO $db,
        private readonly int $maxAttempts,
        private readonly int $window,
    ) {
    }

    public static function default(): self
    {
        return new self(
            Database::connection(),
            (int) config('security.login_max_attempts'),
            (int) config('security.login_window'),
        );
    }

    public function maxAttempts(): int
    {
        return $this->maxAttempts;
    }

    public function windowMinutes(): int
    {
        return (int) ceil($this->window / 60);
    }

    /** Seconds this IP still has to wait; 0 means it may try. */
    public function retryAfter(string $ip): int
    {
        $stmt = $this->db->prepare(
            'SELECT attempted_at FROM login_attempts
             WHERE ip = :ip AND attempted_at > :since
             ORDER BY attempted_at DESC
             LIMIT :max'
        );
        $stmt->bindValue(':ip', $ip, PDO::PARAM_STR);
        $stmt->bindValue(':since', time() - $this->window, PDO::PARAM_INT);
        $stmt->bindValue(':max', $this->maxAttempts, PDO::PARAM_INT);
        $stmt->execute();
        $times = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));

        if (count($times) < $this->maxAttempts) {
            return 0;
        }

        return max(1, min($times) + $this->window - time());
    }

    /** Records a failed attempt; returns the number of failures from this IP inside the window. */
    public function recordFailure(string $ip, string $username): int
    {
        $insert = $this->db->prepare(
            'INSERT INTO login_attempts (ip, username, attempted_at) VALUES (:ip, :username, :at)'
        );
        $insert->bindValue(':ip', $ip, PDO::PARAM_STR);
        $insert->bindValue(':username', mb_substr($username, 0, 255, 'UTF-8'), PDO::PARAM_STR);
        $insert->bindValue(':at', time(), PDO::PARAM_INT);
        $insert->execute();

        // Housekeeping: rows older than a day are no longer needed.
        $cleanup = $this->db->prepare('DELETE FROM login_attempts WHERE attempted_at < :before');
        $cleanup->bindValue(':before', time() - 86400, PDO::PARAM_INT);
        $cleanup->execute();

        $count = $this->db->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip = :ip AND attempted_at > :since');
        $count->bindValue(':ip', $ip, PDO::PARAM_STR);
        $count->bindValue(':since', time() - $this->window, PDO::PARAM_INT);
        $count->execute();

        return (int) $count->fetchColumn();
    }
}
