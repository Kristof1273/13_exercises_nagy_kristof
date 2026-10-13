<?php
/** @var string $title */
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title) ?> · <?= e(config('app.name')) ?></title>
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="site-header">
    <div class="container header-inner">
        <a class="brand" href="/"><?= e(config('app.name')) ?></a>
        <nav class="nav">
            <?php foreach (nav_items() as $href => $label): ?>
                <a href="<?= e($href) ?>"<?= current_path() === $href ? ' aria-current="page"' : '' ?>><?= e($label) ?></a>
            <?php endforeach; ?>
        </nav>
    </div>
</header>
<main class="container">
