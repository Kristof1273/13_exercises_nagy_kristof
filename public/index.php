<?php

declare(strict_types=1);

require __DIR__ . '/../private/bootstrap.php';

$exercises = [
    ['01', 'Secure PHP configuration & error handling', [
        '/error_test.php' => 'Trigger E_NOTICE / E_WARNING / E_ERROR and check the log',
    ]],
    ['02', 'Input validation & sanitization', [
        '/form.php' => 'Contact form (server-side validation)',
        '/form.php?novalidate=1' => 'Same form with browser validation switched off (to test the server side)',
    ]],
];

render_header('Home');
?>
<h1>PHP Security Exercises</h1>
<p class="muted">Each exercise builds on the previous one. Pages marked <span class="badge">demo</span> are localhost-only teaching aids.</p>

<?php foreach ($exercises as [$number, $title, $links]): ?>
    <section class="card">
        <h2>Exercise <?= e($number) ?> — <?= e($title) ?></h2>
        <ul class="list-links">
            <?php foreach ($links as $href => $label): ?>
                <li><a href="<?= e($href) ?>"><?= e($label) ?></a></li>
            <?php endforeach; ?>
        </ul>
    </section>
<?php endforeach; ?>
<?php render_footer(); ?>
