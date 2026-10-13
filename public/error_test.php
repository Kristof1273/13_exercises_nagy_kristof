<?php

declare(strict_types=1);

/*
 * Exercise 01 — error level demo  (demo page: localhost only)
 *
 * Each link triggers a real error of a different level. Expected result:
 *   - the browser shows NO error details (only a normal page or a generic 500 page),
 *   - the full message lands in private/logs/php_errors.log.
 *
 *   tail -f private/logs/php_errors.log
 */

require __DIR__ . '/../private/bootstrap.php';
require_demo_mode();

$level = query_string('level');
$status = null;

switch ($level) {
    case 'notice':
        // Genuine E_NOTICE in PHP 8: passing a function's return value by reference.
        $last = end(explode(',', 'a,b,c'));
        $status = 'An E_NOTICE was raised. Nothing is shown here — check the log file.';
        break;

    case 'warning':
        // Genuine E_WARNING in PHP 8: reading an array key that does not exist.
        $settings = [];
        $value = $settings['missing_key'];
        $status = 'An E_WARNING was raised. Nothing is shown here — check the log file.';
        break;

    case 'error':
        // Genuine E_ERROR: exhaust the memory limit. Execution stops here and the
        // shutdown handler shows the generic 500 page.
        ini_set('memory_limit', '16M');
        $blob = str_repeat('x', 64 * 1024 * 1024);
        break;

    case 'exception':
        // Uncaught Error (exception) -> ErrorHandler::handleException().
        undefined_function_for_demo();
        break;

    case 'disabled':
        // exec() is listed in disable_functions, so PHP 8 throws
        // "Call to undefined function exec()" — the command never runs.
        exec('whoami');
        break;
}

$checks = [
    'display_errors' => ini_get('display_errors'),
    'log_errors' => ini_get('log_errors'),
    'error_log' => str_replace(APP_ROOT . DIRECTORY_SEPARATOR, '', (string) ini_get('error_log')),
    'expose_php' => ini_get('expose_php'),
    'disable_functions' => ini_get('disable_functions'),
];

render_header('Error handling demo');
?>
<h1>Error handling demo <span class="badge">demo</span></h1>

<?php if ($status !== null): ?>
    <div class="alert alert-ok"><?= e($status) ?></div>
<?php endif; ?>

<section class="card">
    <h2>Trigger an error</h2>
    <ul class="list-links">
        <li><a href="?level=notice">E_NOTICE</a> — page keeps working, entry goes to the log</li>
        <li><a href="?level=warning">E_WARNING</a> — page keeps working, entry goes to the log</li>
        <li><a href="?level=error">E_ERROR</a> (fatal, out of memory) — generic 500 page</li>
        <li><a href="?level=exception">Uncaught exception</a> — generic 500 page</li>
        <li><a href="?level=disabled">Call exec()</a> — blocked by <code>disable_functions</code></li>
    </ul>
    <p class="muted">Then run <code>tail private/logs/php_errors.log</code> in the project root.</p>
</section>

<section class="card">
    <h2>Effective configuration</h2>
    <table>
        <?php foreach ($checks as $directive => $value): ?>
            <tr>
                <th><code><?= e($directive) ?></code></th>
                <td><code><?= e($value === '' || $value === false ? '(empty)' : (string) $value) ?></code></td>
            </tr>
        <?php endforeach; ?>
    </table>
    <p class="muted">If <code>expose_php</code> is 1 or <code>disable_functions</code> is empty, the server was not started with <code>php bin/serve.php</code>.</p>
</section>
<?php render_footer(); ?>
