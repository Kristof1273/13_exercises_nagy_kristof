<?php

declare(strict_types=1);

require __DIR__ . '/../private/bootstrap.php';

/** @var array{name: string, email: string, age: int, website: string, message: string}|null $data */
$data = session_pull('contact_result');

render_header('Thank you');
?>
<h1>Thank you!</h1>

<?php if ($data === null): ?>
    <p>There is nothing to confirm. <a href="/form.php">Go to the contact form</a>.</p>
<?php else: ?>
    <div class="alert alert-ok">Your message was received. This is the sanitized data:</div>
    <section class="card">
        <table>
            <tr>
                <th>Name</th>
                <?php /* name/message were already encoded in process.php -> no double encoding */ ?>
                <td><?= e($data['name'], false) ?></td>
            </tr>
            <tr><th>Email</th><td><?= e($data['email']) ?></td></tr>
            <tr><th>Age</th><td><?= e($data['age']) ?></td></tr>
            <tr>
                <th>Website</th>
                <td>
                    <?php if ($data['website'] !== ''): ?>
                        <a href="<?= e($data['website']) ?>" rel="noopener noreferrer nofollow"><?= e($data['website']) ?></a>
                    <?php else: ?>
                        <span class="muted">—</span>
                    <?php endif; ?>
                </td>
            </tr>
            <tr><th>Message</th><td><?= nl2br(e($data['message'], false)) ?></td></tr>
        </table>
    </section>
    <p><a href="/form.php">Send another message</a></p>
<?php endif; ?>
<?php render_footer(); ?>
