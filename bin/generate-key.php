<?php

declare(strict_types=1);

/**
 * Prints a new random 256-bit key for APP_KEY (Extra Mile: encryption).
 *
 *   php bin/generate-key.php
 *   export APP_KEY="<output>"
 *
 * Changing the key makes existing encrypted notes unreadable.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

echo base64_encode(random_bytes(32)), PHP_EOL;
