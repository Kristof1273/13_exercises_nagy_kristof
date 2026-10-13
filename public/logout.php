<?php

declare(strict_types=1);

/*
 * Exercise 05 — logout.
 *
 * Logout changes state, so it is a POST protected by a CSRF token. Otherwise
 * any page could log the user out with <img src="/logout.php">.
 * GET (or a stale token, e.g. from another tab) shows a confirmation form.
 */

require __DIR__ . '/../private/bootstrap.php';

if (!Auth::check()) {
    redirect('/login.php');
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && Csrf::passes('logout')) {
    Auth::logout(); // empties the session, deletes the cookie, destroys server-side data
    redirect('/login.php?status=logged_out');
}

render_header('Log out');
?>
<h1>Log out</h1>
<form class="card narrow" method="post" action="/logout.php">
    <?= Csrf::field('logout') ?>
    <p>Do you really want to log out?</p>
    <button type="submit">Log out</button>
</form>
<?php render_footer(); ?>
