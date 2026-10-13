<?php

declare(strict_types=1);

/**
 * All SQL touching the users table (Exercise 04).
 *
 * Rule: user input NEVER becomes part of the SQL string. Every value is sent
 * as a bound parameter of a prepared statement.
 */
final class UserRepository
{
    public function __construct(private readonly PDO $db)
    {
    }

    public static function default(): self
    {
        return new self(Database::connection());
    }

    public function create(string $username, string $email, ?string $passwordHash = null): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO users (username, email, password) VALUES (:username, :email, :password)'
        );
        $stmt->bindValue(':username', $username, PDO::PARAM_STR);
        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
        $stmt->bindValue(':password', $passwordHash, $passwordHash === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->execute();

        return (int) $this->db->lastInsertId();
    }

    public function usernameOrEmailTaken(string $username, string $email): bool
    {
        $stmt = $this->db->prepare(
            'SELECT 1 FROM users WHERE LOWER(username) = LOWER(:username) OR LOWER(email) = LOWER(:email) LIMIT 1'
        );
        $stmt->execute([':username' => $username, ':email' => $email]);

        return $stmt->fetchColumn() !== false;
    }

    /**
     * Partial, case-insensitive username search.
     *
     * The search term is a bound parameter, so it cannot change the query.
     * LIKE wildcards inside the term (% and _) are escaped as well, otherwise
     * searching for "%" would quietly match every user.
     *
     * @return list<array{id: int, username: string, email: string}>
     */
    public function searchByUsername(string $term, int $limit = 50): array
    {
        $pattern = '%' . strtr($term, ['!' => '!!', '%' => '!%', '_' => '!_']) . '%';

        $stmt = $this->db->prepare(
            "SELECT id, username, email FROM users
             WHERE LOWER(username) LIKE LOWER(:pattern) ESCAPE '!'
             ORDER BY username
             LIMIT :limit"
        );
        $stmt->bindValue(':pattern', $pattern, PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll();
    }
}
