<?php
/*
 * Exercise 03 — simulated attacker site for a manual CSRF test.
 *
 * Run it on a DIFFERENT origin than the app:
 *     php -S localhost:9000 -t tools/csrf-attacker
 * then, with the app running on http://localhost:8000, open
 * http://localhost:9000 and press the button (or wait for the auto-submit).
 *
 * The browser sends the victim's cookies along with this forged POST, but the
 * page cannot know the CSRF token, so the app must answer 403.
 */
$target = 'http://localhost:8000/process.php';
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Totally harmless page</title></head>
<body>
<h1>You won a prize! 🎁</h1>
<p>This page silently posts a forged contact form to <code><?= htmlspecialchars($target, ENT_QUOTES, 'UTF-8') ?></code>.</p>
<form id="forged" method="post" action="<?= htmlspecialchars($target, ENT_QUOTES, 'UTF-8') ?>">
    <input type="hidden" name="name" value="CSRF victim">
    <input type="hidden" name="email" value="victim@example.com">
    <input type="hidden" name="age" value="30">
    <input type="hidden" name="message" value="This message was sent without my consent.">
    <!-- no csrf_token: the attacker cannot read it from the app -->
    <button type="submit">Claim prize</button>
</form>
</body>
</html>
