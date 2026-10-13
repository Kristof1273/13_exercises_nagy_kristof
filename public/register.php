<?php

declare(strict_types=1);

require __DIR__ . '/../private/bootstrap.php';

$errors = [];
$old = ['username' => '', 'email' => ''];
$registered = session_pull('registered_username');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Csrf::check('register');

    $old = [
        'username' => trim(post_string('username')),
        'email' => trim(post_string('email')),
    ];

    $password = post_string('password');
    $passwordConfirm = post_string('password_confirm');

    // Allow-list validation: only the characters we expect, nothing else.
    if (preg_match('/^[A-Za-z0-9_.-]{3,30}$/D', $old['username']) !== 1) {
        $errors['username'] = 'Username must be 3–30 characters: letters, digits, dot, dash or underscore.';
    }
    if (mb_strlen($old['email'], 'UTF-8') > 254 || filter_var($old['email'], FILTER_VALIDATE_EMAIL) === false) {
        $errors['email'] = 'Please enter a valid email address.';
    }
    foreach (Auth::validateNewPassword($password, $passwordConfirm, $old['username']) as $i => $message) {
        $errors['password' . $i] = $message;
    }

    if ($errors === []) {
        $users = UserRepository::default();
        try {
            if ($users->usernameOrEmailTaken($old['username'], $old['email'])) {
                $errors['username'] = 'This username or email address is already registered.';
            } else {
                // Exercise 05: only the bcrypt hash is stored, never the password itself.
                // Prepared statement with bound parameters (see UserRepository::create).
                $id = $users->create($old['username'], $old['email'], Auth::hashPassword($password));
                SecurityLogger::info('USER_REGISTERED', 'New account created', ['user_id' => $id, 'username' => $old['username']]);
                $_SESSION['registered_username'] = $old['username'];
                redirect('/register.php');
            }
        } catch (PDOException $e) {
            // UNIQUE constraint hit by a concurrent request (SQLSTATE 23000).
            if ($e->getCode() !== '23000') {
                throw $e;
            }
            $errors['username'] = 'This username or email address is already registered.';
        }
    }
}

render_header('Register');
?>
<h1>Register</h1>

<?php if (is_string($registered)): ?>
    <div class="alert alert-ok">User <strong><?= e($registered) ?></strong> was registered. You can now <a href="/login.php">log in</a>.</div>
<?php endif; ?>

<?php if ($errors !== []): ?>
    <div class="alert alert-error" role="alert">
        <ul>
            <?php foreach ($errors as $message): ?>
                <li><?= e($message) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form class="card narrow" method="post" action="/register.php">
    <?= Csrf::field('register') ?>
    <div class="field">
        <label for="username">Username <span class="hint">3–30 characters: A–Z, 0–9, . _ -</span></label>
        <input type="text" id="username" name="username" required minlength="3" maxlength="30"
               pattern="[A-Za-z0-9_.\-]{3,30}" autocomplete="username" value="<?= e($old['username']) ?>">
    </div>
    <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required maxlength="254" autocomplete="email" value="<?= e($old['email']) ?>">
    </div>
    <div class="field">
        <label for="password">Password <span class="hint">at least 10 characters</span></label>
        <input type="password" id="password" name="password" required minlength="10" autocomplete="new-password">
    </div>
    <div class="field">
        <label for="password_confirm">Repeat password</label>
        <input type="password" id="password_confirm" name="password_confirm" required minlength="10" autocomplete="new-password">
    </div>
    <button type="submit">Create account</button>
</form>
<?php render_footer(); ?>
