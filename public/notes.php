<?php

declare(strict_types=1);

/*
 * Extra Mile 2 — encrypted personal notes (AES-256-CBC + HMAC, see Crypto.php).
 */

require __DIR__ . '/../private/bootstrap.php';

$user = Auth::requireLogin();
$notes = NoteRepository::default();
$errors = [];

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Csrf::check('notes');

    if (post_string('action') === 'delete') {
        $noteId = filter_var(post_string('note_id'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($noteId !== false && $notes->delete($user['id'], $noteId)) {
            SecurityLogger::info('NOTE_DELETED', 'Encrypted note deleted', ['note_id' => $noteId]);
        } else {
            // Not found OR someone else's note — same answer, and worth logging.
            SecurityLogger::warning('NOTE_DELETE_DENIED', 'Delete of a missing or foreign note refused', ['note_id' => post_string('note_id')]);
        }
        redirect('/notes.php');
    }

    $text = trim(post_string('note'));
    if ($text === '') {
        $errors[] = 'The note must not be empty.';
    } elseif (mb_strlen($text, 'UTF-8') > 1000) {
        $errors[] = 'The note must not exceed 1000 characters.';
    } else {
        $notes->add($user['id'], $text);
        redirect('/notes.php');
    }
}

$list = $notes->forUser($user['id']);

render_header('Encrypted notes');
?>
<h1>Encrypted notes</h1>
<p class="muted">Notes are encrypted with AES-256-CBC (random IV, HMAC-SHA256) before they reach the database. The key lives outside the database (<code>APP_KEY</code> or <code>private/keys/app.key</code>).</p>

<?php if ($errors !== []): ?>
    <div class="alert alert-error" role="alert"><?= e(implode(' ', $errors)) ?></div>
<?php endif; ?>

<form class="card" method="post" action="/notes.php">
    <?= Csrf::field('notes') ?>
    <div class="field">
        <label for="note">New note <span class="hint">max. 1000 characters</span></label>
        <textarea id="note" name="note" required maxlength="1000"></textarea>
    </div>
    <button type="submit">Save encrypted</button>
</form>

<?php foreach ($list as $note): ?>
    <section class="card">
        <?php if ($note['error'] !== null): ?>
            <div class="alert alert-error">Cannot decrypt note #<?= e($note['id']) ?>: <?= e($note['error']) ?></div>
        <?php else: ?>
            <p><?= nl2br(e($note['text'])) ?></p>
        <?php endif; ?>
        <p class="muted">#<?= e($note['id']) ?> · <?= e($note['created_at']) ?> UTC</p>
        <details>
            <summary class="muted">Stored in the database as</summary>
            <pre><?= e($note['ciphertext']) ?></pre>
        </details>
        <form class="inline-form" method="post" action="/notes.php">
            <?= Csrf::field('notes') ?>
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="note_id" value="<?= e($note['id']) ?>">
            <button type="submit" class="secondary">Delete</button>
        </form>
    </section>
<?php endforeach; ?>

<?php if ($list === []): ?>
    <p class="muted">No notes yet.</p>
<?php endif; ?>
<?php render_footer(); ?>
