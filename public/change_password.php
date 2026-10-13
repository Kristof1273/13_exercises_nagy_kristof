<?php

declare(strict_types=1);

/*
 * Password change — a sensitive action that is logged (Exercise 07).
 *
 *  - requires an active login AND the current password (a hijacked session
 *    alone is not enough to take over the account)
 *  - wrong current passwords count towards the brute-force limit
 *  - the session ID is regenerated after the change
 */

require __DIR__ . '/../private/bootstrap.php';

$user = Auth::requireLogin();
$errors = [];

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Csrf::check('change_password');

    $current = post_string('current_password');
    $new = post_string('new_password');
    $confirm = post_string('new_password_confirm');

    $throttle = LoginThrottle::default();
    $users = UserRepository::default();
    $record = $users->findById($user['id']);
    $wait = $throttle->retryAfter(client_ip());

    if ($wait > 0) {
        SecurityLogger::alert('PASSWORD_CHANGE_BLOCKED', 'Password change refused: too many recent failures from this IP', [
            'retry_after_seconds' => $wait,
        ]);
        $errors[] = sprintf('Too many failed attempts. Please try again in %d minute(s).', (int) ceil($wait / 60));
    } elseif ($record === null || !password_verify($current, $record['password'])) {
        $failures = $throttle->recordFailure(client_ip(), $user['username']);
        SecurityLogger::warning('PASSWORD_CHANGE_FAILED', 'Wrong current password on password change', [
            'user_id' => $user['id'],
            'failures_in_window' => $failures,
        ]);
        $errors[] = 'The current password is incorrect.';
    } else {
        $errors = Auth::validateNewPassword($new, $confirm, $user['username']);
        if ($errors === [] && password_verify($new, $record['password'])) {
            $errors[] = 'The new password must be different from the current one.';
        }

        if ($errors === []) {
            $users->updatePassword($user['id'], Auth::hashPassword($new));
            session_regenerate_id(true);
            SecurityLogger::info('PASSWORD_CHANGED', 'Password changed', ['user_id' => $user['id']]);

            $_SESSION['flash_ok'] = 'Your password has been changed.';
            redirect('/dashboard.php');
        }
    }
}

render_header('Change password');
?>
<h1>Change password</h1>

<?php if ($errors !== []): ?>
    <div class="alert alert-error" role="alert">
        <ul>
            <?php foreach ($errors as $message): ?>
                <li><?= e($message) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form class="card narrow" method="post" action="/change_password.php">
    <?= Csrf::field('change_password') ?>
    <div class="field">
        <label for="current_password">Current password</label>
        <input type="password" id="current_password" name="current_password" required autocomplete="current-password">
    </div>
    <div class="field">
        <label for="new_password">New password <span class="hint">at least 10 characters</span></label>
        <input type="password" id="new_password" name="new_password" required minlength="10" autocomplete="new-password">
    </div>
    <div class="field">
        <label for="new_password_confirm">Repeat new password</label>
        <input type="password" id="new_password_confirm" name="new_password_confirm" required minlength="10" autocomplete="new-password">
    </div>
    <button type="submit">Change password</button>
</form>
<?php render_footer(); ?>
