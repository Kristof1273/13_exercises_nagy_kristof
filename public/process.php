<?php

declare(strict_types=1);

/*
 * Thin public front controller.
 * The real form handling lives in private/process.php (Exercise 02), which is
 * outside the document root and therefore cannot be requested directly.
 */

require __DIR__ . '/../private/bootstrap.php';
require PRIVATE_DIR . '/process.php';
