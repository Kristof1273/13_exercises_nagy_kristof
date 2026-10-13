<?php

declare(strict_types=1);

require __DIR__ . '/../private/bootstrap.php';

if (Auth::check()) {
    redirect('/dashboard.php');
}

// Fixed messages selected by a key: the URL can choose WHICH message is shown
// but can never inject its own text into the page.
$statusMessages = [
    'login_required' => ['warn', 'Please log in to view that page.'],
    'logged_out' => ['ok', 'You have been logged out.'],
    'expired' => ['warn', 'Your session expired after ' . Session::idleTimeoutLabel() . ' of inactivity. Please log in again.'],
    'session_invalid' => ['error', 'Your session was ended for security reasons (your network or browser changed). Please log in again.'],
];
$status = $statusMessages[query_string('status')] ?? null;

$error = null;
$username = '';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Csrf::check('login'); // login CSRF: stops a third-party page from logging you into an attacker's account

    $username = trim(post_string('username'));
    $password = post_string('password');

    if ($username !== '' && $password !== '' && Auth::attempt($username, $password)) {
        redirect('/dashboard.php');
    }

    // Same message for "no such user" and "wrong password" (no user enumeration).
    $error = 'Invalid username or password.';
}

render_header('Log in');
?>
<h1>Log in</h1>

<?php if ($status !== null): ?>
    <div class="alert alert-<?= e($status[0]) ?>"><?= e($status[1]) ?></div>
<?php endif; ?>

<?php if ($error !== null): ?>
    <div class="alert alert-error" role="alert"><?= e($error) ?></div>
<?php endif; ?>

<form class="card narrow" method="post" action="/login.php">
    <?= Csrf::field('login') ?>
    <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required maxlength="30" autocomplete="username" value="<?= e($username) ?>">
    </div>
    <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">
    </div>
    <button type="submit">Log in</button>
    <p class="muted">No account yet? <a href="/register.php">Register</a></p>
</form>
<?php render_footer(); ?>
