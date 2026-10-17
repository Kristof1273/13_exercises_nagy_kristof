<?php

declare(strict_types=1);


require __DIR__ . '/../private/bootstrap.php';

Auth::requireLogin();

$username = trim(query_string('username'));
$results = null;
$error = null;

if ($username !== '') {
    if (mb_strlen($username, 'UTF-8') > 30) {
        $error = 'Search term is too long (max. 30 characters).';
    } else {
        $results = UserRepository::default()->searchByUsername($username);
    }
}

render_header('Search users');
?>
<h1>Search users</h1>

<form class="card narrow" method="get" action="/search.php">
    <div class="field">
        <label for="username">Username contains</label>
        <input type="search" id="username" name="username" maxlength="30" value="<?= e($username) ?>">
    </div>
    <button type="submit">Search</button>
</form>

<?php if ($error !== null): ?>
    <div class="alert alert-error"><?= e($error) ?></div>
<?php elseif ($results !== null): ?>
    <section class="card">
        <h2><?= e(count($results)) ?> result(s) for “<?= e($username) ?>”</h2>
        <?php if ($results !== []): ?>
            <table>
                <tr><th>ID</th><th>Username</th><th>Email</th></tr>
                <?php foreach ($results as $user): ?>
                    <tr>
                        <td><?= e($user['id']) ?></td>
                        <td><?= e($user['username']) ?></td>
                        <td><?= e($user['email']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </table>
        <?php endif; ?>
    </section>
<?php endif; ?>
<?php render_footer(); ?>
