<?php

declare(strict_types=1);

/*
 * ⚠️  Exercise 04 — DELIBERATELY VULNERABLE search. DO NOT COPY THIS PATTERN. ⚠️
 *
 * The username from the URL is concatenated straight into the SQL string, so
 * the database cannot tell where our query ends and the attacker's input
 * begins. Try:
 *
 *   ?username=alice                                   -> 1 row (intended use)
 *   ?username=' OR '1'='1                             -> EVERY row
 *   ?username=' UNION SELECT id, username, password FROM users --
 *                                                     -> password hashes in the email column
 *
 * Safe version: search.php + UserRepository::searchByUsername().
 * Explanation:  docs/SQL_INJECTION.md
 *
 * Protection of the demo itself: only served to localhost while demo pages are
 * enabled (APP_DEMO_PAGES), so it can never be reached in production.
 */

require __DIR__ . '/../private/bootstrap.php';
require_demo_mode();

$username = query_string('username');
$sql = null;
$rows = null;

if ($username !== '') {
    // ❌ VULNERABLE: user input becomes part of the SQL code.
    $sql = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";
    $rows = Database::connection()->query($sql)->fetchAll();
}

render_header('Vulnerable search');
?>
<div class="danger-banner">⚠️ Deliberately vulnerable to SQL injection — for demonstration only.</div>
<h1>Vulnerable search <span class="badge">demo</span></h1>

<form class="card narrow" method="get" action="/vulnerable_search.php">
    <div class="field">
        <label for="username">Exact username</label>
        <input type="text" id="username" name="username" value="<?= e($username) ?>">
    </div>
    <button type="submit">Search</button>
    <p class="muted">Try <code>' OR '1'='1</code> or <code>' UNION SELECT id, username, password FROM users --</code></p>
</form>

<?php if ($sql !== null): ?>
    <section class="card">
        <h2>Executed SQL</h2>
        <pre><?= e($sql) ?></pre>
        <h2><?= e(count($rows)) ?> row(s) returned</h2>
        <?php if ($rows !== []): ?>
            <table>
                <tr><th>id</th><th>username</th><th>email</th></tr>
                <?php foreach ($rows as $row): ?>
                    <tr>
                        <?php // Output is still HTML-encoded: this page demonstrates SQLi, not XSS. ?>
                        <td><?= e($row['id']) ?></td>
                        <td><?= e($row['username']) ?></td>
                        <td><?= e($row['email']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </table>
        <?php endif; ?>
    </section>
<?php endif; ?>
<?php render_footer(); ?>
