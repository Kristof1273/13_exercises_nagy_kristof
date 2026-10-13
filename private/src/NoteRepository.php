<?php

declare(strict_types=1);

/**
 * Encrypted user notes (Extra Mile 2).
 *
 * The note text is encrypted before INSERT and decrypted after SELECT, so the
 * database only ever sees ciphertext. Every query is scoped to the owner
 * (user_id = :user_id) — a user can never read or delete someone else's note,
 * even by guessing IDs (Broken Access Control / IDOR).
 */
final class NoteRepository
{
    public function __construct(
        private readonly PDO $db,
        private readonly Crypto $crypto,
    ) {
    }

    public static function default(): self
    {
        return new self(Database::connection(), Crypto::fromConfig());
    }

    public function add(int $userId, string $text): int
    {
        $stmt = $this->db->prepare('INSERT INTO notes (user_id, body) VALUES (:user_id, :body)');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':body', $this->crypto->encrypt($text), PDO::PARAM_STR);
        $stmt->execute();

        return (int) $this->db->lastInsertId();
    }

    /**
     * @return list<array{id: int, created_at: string, ciphertext: string, text: ?string, error: ?string}>
     */
    public function forUser(int $userId): array
    {
        $stmt = $this->db->prepare('SELECT id, body, created_at FROM notes WHERE user_id = :user_id ORDER BY id DESC');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_INT);
        $stmt->execute();

        $notes = [];
        foreach ($stmt->fetchAll() as $row) {
            $text = null;
            $error = null;
            try {
                $text = $this->crypto->decrypt((string) $row['body']);
            } catch (CryptoException $e) {
                $error = $e->getMessage();
                SecurityLogger::alert('DECRYPTION_FAILED', 'Encrypted note failed its integrity check', [
                    'note_id' => (int) $row['id'],
                    'reason' => $e->getMessage(),
                ]);
            }
            $notes[] = [
                'id' => (int) $row['id'],
                'created_at' => (string) $row['created_at'],
                'ciphertext' => (string) $row['body'],
                'text' => $text,
                'error' => $error,
            ];
        }

        return $notes;
    }

    /** Deletes the note only if it belongs to $userId. Returns whether a row was deleted. */
    public function delete(int $userId, int $noteId): bool
    {
        $stmt = $this->db->prepare('DELETE FROM notes WHERE id = :id AND user_id = :user_id');
        $stmt->bindValue(':id', $noteId, PDO::PARAM_INT);
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->rowCount() === 1;
    }
}
