<?php

declare(strict_types=1);

/**
 * Creates the database schema and (optionally) demo users.
 *
 *   php bin/init-db.php            create tables if missing
 *   php bin/init-db.php --seed     ... and add the demo users
 *   php bin/init-db.php --reset    delete the SQLite file first (all data is lost!)
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/../private/bootstrap.php';

$options = getopt('', ['seed', 'reset']);
$dsn = (string) config('db.dsn');

if (isset($options['reset'])) {
    if (!str_starts_with($dsn, 'sqlite:')) {
        fwrite(STDERR, "--reset only works with SQLite. Drop the MySQL tables manually.\n");
        exit(1);
    }
    $file = substr($dsn, strlen('sqlite:'));
    if (is_file($file)) {
        unlink($file);
        echo "Deleted {$file}\n";
    }
}

$pdo = Database::connection();
echo "Schema is up to date ({$pdo->getAttribute(PDO::ATTR_DRIVER_NAME)}).\n";

if (isset($options['seed'])) {
    $users = new UserRepository($pdo);
    $demo = [
        ['alice', 'alice@example.com'],
        ['bob', 'bob@example.com'],
        ['carol', 'carol@example.com'],
    ];
    foreach ($demo as [$username, $email]) {
        if ($users->usernameOrEmailTaken($username, $email)) {
            echo "  - {$username} already exists\n";
            continue;
        }
        $users->create($username, $email);
        echo "  + {$username}\n";
    }
}
