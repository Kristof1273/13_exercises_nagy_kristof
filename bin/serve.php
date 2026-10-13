<?php

declare(strict_types=1);

/**
 * Starts the local development server with the hardened php.ini settings.
 *
 *   php bin/serve.php                 -> http://localhost:8000
 *   php bin/serve.php --port=8080
 *   php bin/serve.php --host=0.0.0.0  (only if you know why you need it)
 *
 * Environment variables (APP_ENV, SESSION_IDLE_TIMEOUT, ...) are inherited
 * by the server, see README.md.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/dev-server-lib.php';

$options = getopt('', ['host:', 'port:']);
$host = is_string($options['host'] ?? null) ? $options['host'] : 'localhost';
$port = (int) ($options['port'] ?? 8000);

$root = dirname(__DIR__);
$command = dev_server_command($root, $host, $port);

fwrite(STDOUT, "Starting http://{$host}:{$port}  (document root: public/)\n");
fwrite(STDOUT, "Hardened directives from php.ini are applied with -d. Press Ctrl+C to stop.\n\n");

// Array form = no shell involved, so no quoting/injection issues on any OS.
$process = proc_open($command, [STDIN, STDOUT, STDERR], $pipes, $root);
if (!is_resource($process)) {
    fwrite(STDERR, "Could not start the PHP built-in server.\n");
    exit(1);
}
exit(proc_close($process));
