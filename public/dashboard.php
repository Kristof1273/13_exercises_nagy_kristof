<?php

declare(strict_types=1);

/*
 * Exercise 05 — protected page. Anonymous visitors are redirected to /login.php.
 */

require __DIR__ . '/../private/bootstrap.php';

$user = Auth::requireLogin();
$authTime = (int) ($_SESSION['auth_time'] ?? time());

render_header('Dashboard');
?>
<h1>Welcome, <?= e($user['username']) ?>!</h1>

<section class="card">
    <h2>Your session</h2>
    <table>
        <tr><th>Logged in at</th><td><?= e(date('Y-m-d H:i:s T', $authTime)) ?></td></tr>
    </table>
</section>

<section class="card">
    <h2>Things you can do</h2>
    <ul class="list-links">
        <li><a href="/search.php">Search users</a></li>
    </ul>
</section>
<?php render_footer(); ?>
