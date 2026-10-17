<?php

declare(strict_types=1);

require __DIR__ . '/../private/bootstrap.php';

/** @var array<string, string> $errors */
$errors = session_pull('contact_errors', []);
/** @var array<string, string> $old */
$old = session_pull('contact_old', []);

$novalidate = query_string('novalidate') === '1';

$value = static fn (string $field): string => (string) ($old[$field] ?? '');

render_header('Contact form');
?>
<h1>Contact form</h1>

<?php if ($errors !== []): ?>
    <div class="alert alert-error" role="alert">
        Please fix the following:
        <ul>
            <?php foreach ($errors as $message): ?>
                <li><?= e($message) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form class="card narrow" method="post" action="/process.php"<?= $novalidate ? ' novalidate' : '' ?>>
    <?= Csrf::field('contact')?>
    <div class="field">
        <label for="name">Name <span class="hint">required, max. 50 characters</span></label>
        <input type="text" id="name" name="name" required maxlength="50" value="<?= e($value('name')) ?>">
        <?php if (isset($errors['name'])): ?><div class="field-error"><?= e($errors['name']) ?></div><?php endif; ?>
    </div>

    <div class="field">
        <label for="email">Email <span class="hint">required</span></label>
        <input type="email" id="email" name="email" required maxlength="254" value="<?= e($value('email')) ?>">
        <?php if (isset($errors['email'])): ?><div class="field-error"><?= e($errors['email']) ?></div><?php endif; ?>
    </div>

    <div class="field">
        <label for="age">Age <span class="hint">required, number</span></label>
        <input type="number" id="age" name="age" required min="1" max="150" step="1" value="<?= e($value('age')) ?>">
        <?php if (isset($errors['age'])): ?><div class="field-error"><?= e($errors['age']) ?></div><?php endif; ?>
    </div>

    <div class="field">
        <label for="website">Website <span class="hint">optional, http(s) URL</span></label>
        <input type="url" id="website" name="website" maxlength="2048" placeholder="https://example.com" value="<?= e($value('website')) ?>">
        <?php if (isset($errors['website'])): ?><div class="field-error"><?= e($errors['website']) ?></div><?php endif; ?>
    </div>

    <div class="field">
        <label for="message">Message <span class="hint">required, max. 500 characters</span></label>
        <textarea id="message" name="message" required maxlength="500"><?= e($value('message')) ?></textarea>
        <?php if (isset($errors['message'])): ?><div class="field-error"><?= e($errors['message']) ?></div><?php endif; ?>
    </div>

    <button type="submit">Send</button>
</form>
<?php render_footer(); ?>
