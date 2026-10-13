<?php

declare(strict_types=1);

/*
 * Exercise 05 — protected page. Anonymous visitors are redirected to /login.php.
 */

require __DIR__ . '/../private/bootstrap.php';

$user = Auth::requireLogin();
$authTime = (int) ($_SESSION['auth_time'] ?? time());
$fingerprint = $_SESSION['_fingerprint'] ?? [];
$flash = session_pull('flash_ok');

render_header('Dashboard');
?>
<h1>Welcome, <?= e($user['username']) ?>!</h1>

<?php if (is_string($flash)): ?>
    <div class="alert alert-ok"><?= e($flash) ?></div>
<?php endif; ?>

<section class="card">
    <h2>Your session</h2>
    <table>
        <tr><th>Logged in at</th><td><?= e(date('Y-m-d H:i:s T', $authTime)) ?></td></tr>
        <tr><th>Idle timeout</th><td><?= e(Session::idleTimeoutLabel()) ?> (expires at <?= e(date('H:i:s T', time() + Session::secondsLeft())) ?> without activity)</td></tr>
        <tr><th>Bound to IP</th><td><code><?= e($fingerprint['ip'] ?? '—') ?></code></td></tr>
        <tr><th>Bound to User-Agent</th><td><code><?= e($fingerprint['user_agent'] ?? '—') ?></code></td></tr>
    </table>
    <p class="muted">The session cookie is HttpOnly and SameSite=Strict (Secure on HTTPS). Changing it, switching browser or network, or idling for too long ends the session.</p>
</section>

<section class="card">
    <h2>Things you can do</h2>
    <ul class="list-links">
        <li><a href="/search.php">Search users</a></li>
        <li><a href="/change_password.php">Change password</a></li>
    </ul>
</section>
<?php render_footer(); ?>
