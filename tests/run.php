<?php

declare(strict_types=1);

/*
 * Automated security test-suite.
 *
 *   php tests/run.php            run everything
 *   php tests/run.php ex03       run only files whose name contains "ex03"
 *
 * Starts throw-away instances of the built-in server (with the hardened
 * php.ini directives), runs tests/ex*_test.php against them, stops them.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/../bin/dev-server-lib.php';
require __DIR__ . '/lib.php';

$root = dirname(__DIR__);
$filter = $argv[1] ?? '';

// Environment shared by every test server: a throw-away test database.
$testDb = $root . '/private/db/test.sqlite';
foreach (glob($testDb . '*') ?: [] as $file) {
    unlink($file);
}
$commonEnv = ['DB_DSN' => 'sqlite:' . $testDb];
define('TEST_DB', $testDb);

// Several servers with different settings; all share the same files/sessions.
$servers = [
    'main' => ['port' => 8089, 'env' => []],
    'short' => ['port' => 8090, 'env' => ['SESSION_IDLE_TIMEOUT' => '3']],
    'secure' => ['port' => 8091, 'env' => ['SESSION_COOKIE_SECURE' => '1']],
];

define('TEST_ROOT', $root);
define('SERVER_URLS', array_map(static fn (array $s): string => 'http://127.0.0.1:' . $s['port'], $servers));

$processes = [];
$baseEnv = getenv();
foreach ($servers as $name => $server) {
    $env = array_merge($baseEnv, $commonEnv, $server['env']);
    $log = sys_get_temp_dir() . "/php-security-test-server-{$name}.log";
    $process = proc_open(
        dev_server_command($root, '127.0.0.1', $server['port']),
        [0 => ['pipe', 'r'], 1 => ['file', $log, 'w'], 2 => ['file', $log, 'a']],
        $pipes,
        $root,
        $env
    );
    if (!is_resource($process)) {
        fwrite(STDERR, "Could not start test server '{$name}'\n");
        exit(1);
    }
    $processes[$name] = $process;
}

register_shutdown_function(static function () use (&$processes): void {
    foreach ($processes as $process) {
        proc_terminate($process);
    }
});

// Wait until every server accepts connections.
foreach ($servers as $name => $server) {
    $deadline = microtime(true) + 10;
    while (true) {
        $socket = @fsockopen('127.0.0.1', $server['port'], $errno, $errstr, 0.2);
        if ($socket !== false) {
            fclose($socket);
            break;
        }
        if (microtime(true) > $deadline) {
            fwrite(STDERR, "Test server '{$name}' did not start (port {$server['port']} busy?)\n");
            exit(1);
        }
        usleep(100_000);
    }
}

$files = glob(__DIR__ . '/ex*_test.php') ?: [];
sort($files);

$passed = 0;
$failed = 0;
foreach ($files as $file) {
    if ($filter !== '' && !str_contains(basename($file), $filter)) {
        continue;
    }
    $GLOBALS['TESTS'] = [];
    require $file;

    echo PHP_EOL . basename($file) . PHP_EOL;
    foreach ($GLOBALS['TESTS'] as [$name, $body]) {
        try {
            $body();
            $passed++;
            echo "  \033[32m✔\033[0m {$name}" . PHP_EOL;
        } catch (Throwable $e) {
            $failed++;
            echo "  \033[31m✘ {$name}\033[0m" . PHP_EOL . '      ' . $e->getMessage() . PHP_EOL;
        }
    }
}

echo PHP_EOL . "{$passed} passed, {$failed} failed" . PHP_EOL;
exit($failed === 0 ? 0 : 1);
