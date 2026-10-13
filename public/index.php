<?php

declare(strict_types=1);

require __DIR__ . '/../private/bootstrap.php';

$exercises = [
    ['01', 'Secure PHP configuration & error handling', [
        '/error_test.php' => 'Trigger E_NOTICE / E_WARNING / E_ERROR and check the log  [demo]',
    ]],
    ['02', 'Input validation & sanitization', [
        '/form.php' => 'Contact form (server-side validation)',
        '/form.php?novalidate=1' => 'Same form with browser validation switched off (to test the server side)',
    ]],
    ['03', 'XSS & CSRF protection', [
        '/form.php' => 'The contact form now carries a single-use CSRF token',
    ]],
    ['04', 'SQL injection prevention', [
        '/register.php' => 'Register a user (PDO prepared statement)',
        '/search.php' => 'Search users by username (prepared statement)',
        '/vulnerable_search.php' => 'Deliberately vulnerable search — try \' OR \'1\'=\'1  [demo]',
    ]],
    ['05', 'Secure password handling', [
        '/register.php' => 'Register with a password (bcrypt via password_hash)',
        '/login.php' => 'Log in (password_verify + session_regenerate_id)',
        '/dashboard.php' => 'Protected page (redirects to login when anonymous)',
    ]],
    ['06', 'Session security & cookie hardening', [
        '/dashboard.php' => 'Dashboard shows the session binding and timeout',
    ]],
    ['07', 'Security logging', [
        '/change_password.php' => 'Change password (logged as a sensitive action)',
        '/login.php' => 'Fail the login 5 times in a row to trigger the brute-force block',
    ]],
    ['Extra', 'Encryption & decryption', [
        '/notes.php' => 'Encrypted notes (AES-256-CBC + HMAC-SHA256)',
    ]],
    ['Extra', 'Content Security Policy', [
        '/csp_test.php' => "Check that inline scripts are blocked while 'self' scripts run",
    ]],
];

// Demo pages are not linked when they are switched off (production).
$demoPages = ['/error_test.php', '/vulnerable_search.php'];
if (!config('app.demo_pages')) {
    foreach ($exercises as &$exercise) {
        $exercise[2] = array_diff_key($exercise[2], array_flip($demoPages));
    }
    unset($exercise);
}

render_header('Home');
?>
<h1>PHP Security Exercises</h1>
<p class="muted">Each exercise builds on the previous one. Pages marked <span class="badge">demo</span> are localhost-only teaching aids.</p>

<?php foreach ($exercises as [$number, $title, $links]): ?>
    <section class="card">
        <h2><?= is_numeric($number) ? 'Exercise ' . e($number) : e($number) ?> — <?= e($title) ?></h2>
        <ul class="list-links">
            <?php foreach ($links as $href => $label): ?>
                <li><a href="<?= e($href) ?>"><?= e($label) ?></a></li>
            <?php endforeach; ?>
        </ul>
    </section>
<?php endforeach; ?>
<?php render_footer(); ?>
