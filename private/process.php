<?php

declare(strict_types=1);

/*
 * Exercise 02 — contact form handler (POST only).
 *
 * Included by public/process.php after the bootstrap.
 * Flow:  validate -> sanitize -> on error redirect back to the form,
 *        on success redirect to the confirmation page (Post/Redirect/Get).
 */

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method Not Allowed');
}

// ---------------------------------------------------------------------------
// 1) Read the raw input. post_string() rejects arrays (name[]=x) outright.
// ---------------------------------------------------------------------------
$input = [
    'name' => trim(post_string('name')),
    'email' => trim(post_string('email')),
    'age' => trim(post_string('age')),
    'website' => trim(post_string('website')),
    'message' => trim(post_string('message')),
];

// ---------------------------------------------------------------------------
// 2) Validation — reject anything that does not match the expected format.
//    Lengths are counted in characters (mb_strlen), not bytes.
// ---------------------------------------------------------------------------
$errors = [];

if ($input['name'] === '') {
    $errors['name'] = 'Name is required.';
} elseif (mb_strlen($input['name'], 'UTF-8') > 50) {
    $errors['name'] = 'Name must not exceed 50 characters.';
}

if ($input['email'] === '') {
    $errors['email'] = 'Email is required.';
} elseif (mb_strlen($input['email'], 'UTF-8') > 254 || filter_var($input['email'], FILTER_VALIDATE_EMAIL) === false) {
    $errors['email'] = 'Please enter a valid email address.';
}

if ($input['age'] === '') {
    $errors['age'] = 'Age is required.';
} elseif (!is_numeric($input['age'])) {
    $errors['age'] = 'Age must be a number.';
} elseif (filter_var($input['age'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 150]]) === false) {
    // is_numeric() also accepts "1e3", "-5" or "12.5" — narrow it down to a plausible age.
    $errors['age'] = 'Age must be a whole number between 1 and 150.';
}

if ($input['website'] !== '') {
    $scheme = strtolower((string) parse_url($input['website'], PHP_URL_SCHEME));
    if (
        mb_strlen($input['website'], 'UTF-8') > 2048
        || filter_var($input['website'], FILTER_VALIDATE_URL) === false
        // FILTER_VALIDATE_URL happily accepts "javascript://..." — allow web links only.
        || !in_array($scheme, ['http', 'https'], true)
    ) {
        $errors['website'] = 'Website must be a valid http:// or https:// URL.';
    }
}

if ($input['message'] === '') {
    $errors['message'] = 'Message is required.';
} elseif (mb_strlen($input['message'], 'UTF-8') > 500) {
    $errors['message'] = 'Message must not exceed 500 characters.';
}

// ---------------------------------------------------------------------------
// 3) Sanitization.
//    Order matters for name/message: strip_tags() FIRST removes HTML/PHP tags,
//    THEN htmlspecialchars() encodes whatever special characters remain.
//    (Encoding first would turn "<b>" into "&lt;b&gt;" and strip_tags() would
//    have nothing left to strip.)
// ---------------------------------------------------------------------------
$sanitized = [];
if ($errors === []) {
    $sanitized = [
        'name' => htmlspecialchars(strip_tags($input['name']), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        'email' => (string) filter_var($input['email'], FILTER_SANITIZE_EMAIL),
        'age' => (int) $input['age'],
        'website' => $input['website'] === '' ? '' : (string) filter_var($input['website'], FILTER_SANITIZE_URL),
        'message' => htmlspecialchars(strip_tags($input['message']), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
    ];

    // A value made only of tags ("<b></b>") is empty after strip_tags().
    if (trim($sanitized['name']) === '') {
        $errors['name'] = 'Name must contain text, not only HTML tags.';
    }
    if (trim($sanitized['message']) === '') {
        $errors['message'] = 'Message must contain text, not only HTML tags.';
    }
}

// ---------------------------------------------------------------------------
// 4) Redirect back with errors, or forward to the confirmation page.
// ---------------------------------------------------------------------------
if ($errors !== []) {
    $_SESSION['contact_errors'] = $errors;
    // Raw values are sent back so the user can correct them; the form encodes
    // them on output. Capped so a huge payload doesn't bloat the session.
    $_SESSION['contact_old'] = array_map(
        static fn (string $v): string => mb_substr($v, 0, 2048, 'UTF-8'),
        $input
    );
    redirect('/form.php');
}

$_SESSION['contact_result'] = $sanitized;
redirect('/confirmation.php');
