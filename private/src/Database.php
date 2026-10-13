<?php

declare(strict_types=1);

/**
 * PDO connection factory (Exercise 04).
 *
 * Works with SQLite (default, no setup) and MySQL/MariaDB (set DB_DSN).
 * The schema in private/db/schema.<driver>.sql is applied idempotently on
 * the first connection of every request.
 */
final class Database
{
    private static ?PDO $pdo = null;

    public static function connection(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        $dsn = (string) config('db.dsn');
        if (str_starts_with($dsn, 'sqlite:')) {
            $directory = dirname(substr($dsn, strlen('sqlite:')));
            if (!is_dir($directory)) {
                mkdir($directory, 0750, true);
            }
        }

        $pdo = new PDO($dsn, config('db.username'), config('db.password'), [
            // Every SQL error becomes an exception: nothing fails silently, and
            // the details go to the log, never to the browser.
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Use the database's native prepared statements: the SQL text and the
            // values are sent separately, so a value can never be parsed as SQL.
            // (SQLite always prepares natively; this matters for MySQL.)
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $pdo->exec('PRAGMA foreign_keys = ON');
            $pdo->exec('PRAGMA busy_timeout = 5000');
        }

        self::migrate($pdo);

        return self::$pdo = $pdo;
    }

    private static function migrate(PDO $pdo): void
    {
        $driver = (string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $file = PRIVATE_DIR . "/db/schema.{$driver}.sql";
        if (!is_file($file)) {
            throw new RuntimeException("No schema file for PDO driver '{$driver}'");
        }

        // Drop "--" comment lines, then run the statements one by one.
        $sql = preg_replace('/^\s*--.*$/m', '', (string) file_get_contents($file));
        foreach (explode(';', (string) $sql) as $statement) {
            if (trim($statement) !== '') {
                $pdo->exec($statement);
            }
        }
    }
}
