# PHP Security Exercises

A small PHP application that implements the seven PHP security exercises and
all three Extra Mile tasks: secure configuration, input validation, XSS/CSRF
protection, SQL injection prevention, password handling, session hardening,
security logging, an OWASP Top 10 (2025) audit, encryption and a
Content-Security-Policy.

No framework and no third-party dependencies — plain PHP 8 with PDO, so every
security mechanism is visible in the code. The commit history follows the
exercises one by one.

---

## Requirements

- **PHP 8.1 or newer** (developed and tested with PHP 8.3) with the extensions
  `pdo_sqlite`, `openssl`, `mbstring` and `session` (all enabled in typical
  installs; on Windows/XAMPP check `extension=pdo_sqlite` in php.ini)
- `curl` extension — only for the automated tests
- No database server needed: SQLite is used by default (MySQL/MariaDB optional)

## Quick start

```bash
git clone <this repository> php-security-exercises
cd php-security-exercises

php bin/init-db.php --seed      # create the SQLite database + demo users
php bin/serve.php               # → http://localhost:8000
```

`bin/serve.php` starts PHP's built-in server with **`public/` as the document
root** and passes every directive from the project's `php.ini` with `-d`
(your system php.ini, with its extensions, still loads). Use
`php bin/serve.php --port=8080` for another port.

> ⚠️ Always serve `public/` as the document root. Never run `php -S` from the
> project root — that would expose `private/` (config, logs, database).

### Demo accounts (created by `--seed`, local use only)

| Username | Password |
|---|---|
| alice | `Wonderland-2026` |
| bob | `Builder-Bob-2026` |
| carol | `Christmas-Carol-2026` |

`php bin/init-db.php --reset --seed` recreates the database from scratch;
`php bin/init-db.php --unblock` lifts a brute-force block (Exercise 07).

## Automated tests

```bash
php tests/run.php          # all 76 tests
php tests/run.php ex06     # only one exercise
```

The runner starts three throw-away servers (normal, 3-second session timeout,
forced Secure cookie) on ports 8089–8091, uses a separate test database and
exercises every requirement over real HTTP: error display vs. log, validation,
XSS payloads, CSRF (missing / tampered / foreign / replayed tokens), SQL
injection, password hashing, session fixation, cookie flags, timeouts,
fingerprinting, every log event, brute-force blocking, encryption and CSP.

---

## Project structure

```text
├── php.ini                    Ex01 hardened directives (applied by bin/serve.php)
├── bin/
│   ├── serve.php              dev server with public/ as docroot + php.ini via -d
│   ├── init-db.php            create schema, --seed demo users, --reset
│   └── generate-key.php       new APP_KEY for encryption
├── public/                    ← DOCUMENT ROOT (the only web-accessible folder)
│   ├── index.php              overview of all exercises
│   ├── error_test.php         Ex01 error-level demo                    [demo]
│   ├── form.php               Ex02/03 contact form
│   ├── process.php            thin front controller → private/process.php
│   ├── confirmation.php       Ex02 sanitized output
│   ├── register.php           Ex04/05 registration
│   ├── search.php             Ex04 safe search (prepared statement)
│   ├── vulnerable_search.php  Ex04 deliberately injectable            [demo]
│   ├── login.php · logout.php · dashboard.php      Ex05/06
│   ├── change_password.php    Ex07 sensitive action
│   ├── notes.php              Extra: encrypted notes
│   ├── csp_test.php           Extra: CSP check
│   └── assets/                app.css, csp-test.js
├── private/                   ← never served (outside the document root)
│   ├── bootstrap.php          ini_set(), autoloader, headers, session, detection
│   ├── config.php             configuration (env-overridable)
│   ├── process.php            Ex02 form handler
│   ├── src/                   ErrorHandler, Csrf, Database, UserRepository, Auth,
│   │                          Session, SecurityLogger, AttackDetector,
│   │                          LoginThrottle, Crypto, NoteRepository, helpers
│   ├── templates/             header / footer
│   ├── db/                    schema.sqlite.sql, schema.mysql.sql, *.sqlite
│   ├── logs/                  php_errors.log, security.log
│   ├── sessions/              session files
│   └── keys/                  app.key (generated, git-ignored)
├── docs/
│   ├── SQL_INJECTION.md       Ex04 comparison of the two search versions
│   └── OWASP_TOP10_2025_AUDIT.md   Extra Mile 1
├── tests/                     run.php + ex01…ex09 test files
└── tools/csrf-attacker/       fake attacker site for a manual CSRF test
```

Every directory contains an `index.php` guard (empty 403) so no directory
listing can ever be shown; `private/.htaccess` additionally denies access on
Apache.

---

## The exercises — where they live and how to try them

### Exercise 01 — Secure configuration & error handling
- `php.ini`: `display_errors=Off`, `log_errors=On`, `error_log` in
  `private/logs/`, `expose_php=Off`, `disable_functions=exec,system,passthru`
  (+ `shell_exec`, `proc_open`, `popen`, `pcntl_exec`).
- `expose_php` and `disable_functions` are `PHP_INI_SYSTEM` and **cannot** be
  set with `ini_set()`; the `PHP_INI_ALL` directives are enforced again at
  runtime in `private/bootstrap.php`.
- `private/src/ErrorHandler.php`: generic HTTP 500 page for fatal errors and
  uncaught exceptions, details only in the log.
- **Try it:** open `/error_test.php`, click *E_NOTICE*, *E_WARNING*, *E_ERROR*,
  *exception*, *exec()*; the browser shows nothing technical, while
  `tail private/logs/php_errors.log` shows each entry. `curl -I localhost:8000`
  shows no `X-Powered-By` header.

### Exercise 02 — Input validation & sanitization
- `public/form.php` → `public/process.php` → **`private/process.php`** (POST only).
- Validation: required fields, `mb_strlen` limits (50/500), `filter_var(…, FILTER_VALIDATE_EMAIL)`,
  `is_numeric()` + integer range for age, `FILTER_VALIDATE_URL` + http(s) only for the website.
- Sanitization: `strip_tags()` then `htmlspecialchars()` for name/message,
  `FILTER_SANITIZE_EMAIL` for email. Errors go back to the form (PRG pattern),
  valid data to `confirmation.php`.
- **Try it:** `/form.php?novalidate=1` switches off the browser's own checks
  so the server-side validation can be tested; enter
  `<script>alert('XSS')</script>` as the name.

### Exercise 03 — XSS & CSRF protection
- `e()` in `private/src/helpers.php` = `htmlspecialchars(…, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`;
  used for **every** value printed, including values echoed back into `value="…"`.
- `private/src/Csrf.php`: `bin2hex(random_bytes(32))` per form load, stored in
  `$_SESSION`, hidden field, `hash_equals()`, single use → 403 on mismatch.
  Used by every POST form (contact, register, login, logout, password, notes).
- **Try it:** submit normally (works); remove or edit the hidden
  `csrf_token` in DevTools (403). Cross-site test:
  `php -S localhost:9000 -t tools/csrf-attacker`, open http://localhost:9000.

### Exercise 04 — SQL injection prevention
- `users` table (`id, username, email, password`), `private/db/schema.*.sql`.
- `register.php` and `search.php` use PDO prepared statements with bound
  parameters only (`private/src/UserRepository.php`).
- `public/vulnerable_search.php` concatenates `$_GET['username']` on purpose
  (localhost + demo mode only).
- **Try it:** `/vulnerable_search.php?username=' OR '1'='1` lists every user;
  `' UNION SELECT id, username, password FROM users --` leaks the hashes.
  The same input on `/search.php` returns 0 rows. Explanation:
  [`docs/SQL_INJECTION.md`](docs/SQL_INJECTION.md).

### Exercise 05 — Secure password handling
- `password_hash(…, PASSWORD_DEFAULT)` (bcrypt, cost 12), column `VARCHAR(255)`.
- `login.php`: `password_verify()`, generic error, `session_regenerate_id(true)`.
- `dashboard.php` is protected by `Auth::requireLogin()` (redirect to login).
- `logout.php` (POST + CSRF) empties the session, deletes the cookie and calls
  `session_destroy()`.

### Exercise 06 — Session security & cookie hardening
- `private/src/Session.php`: `session_set_cookie_params()` with `HttpOnly`,
  `SameSite=Strict`, `Secure` on HTTPS (`__Host-` prefix), strict mode,
  cookie-only IDs; 30-minute idle timeout; IP + User-Agent fingerprint.
- **Try it:** log in and browse (works). In DevTools → Application → Cookies
  change the `SECSESSID` value → you are logged out and get a new ID. Wait
  30 minutes (or start the server with `SESSION_IDLE_TIMEOUT=60`) → "session
  expired". Switch the User-Agent (DevTools → Network conditions) → session ended.
- **Secure flag:** the built-in server speaks only HTTP, so in `auto` mode the
  cookie is not marked `Secure` locally. See [HTTPS](#https-with-a-self-signed-certificate).

### Exercise 07 — Security logging
- `private/src/SecurityLogger.php` → `private/logs/security.log`, one line per event:
  ```text
  [2026-10-13T11:38:38.339+00:00] ALERT   BRUTE_FORCE_DETECTED ip="127.0.0.1" user="-" req="POST /login.php" msg="5 failed logins from this IP within 10 minutes — further attempts are blocked" ctx={"username":"alice","failures_in_window":5}
  ```
- Errors: `PHP_ERROR`, `UNCAUGHT_EXCEPTION`, `FATAL_ERROR`.
  Sensitive actions: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `USER_REGISTERED`,
  `PASSWORD_CHANGED`, `PASSWORD_CHANGE_FAILED`.
  Attacks: `CSRF_TOKEN_MISMATCH`, `SQLI_ATTEMPT`, `XSS_ATTEMPT`,
  `REPEATED_FAILED_LOGINS`, `BRUTE_FORCE_DETECTED`, `LOGIN_BLOCKED`,
  `SESSION_FINGERPRINT_MISMATCH`, `SESSION_ID_REJECTED`, `DECRYPTION_FAILED`.
- Brute force (`private/src/LoginThrottle.php`): 5 failed logins from one IP
  within 10 minutes → HTTP 429, further attempts refused (even with the right
  password) until the window has passed.
- **Try it:** `tail -f private/logs/security.log`, then fail the login 5 times.
  Wait 10 minutes or run `php bin/init-db.php --unblock` to lift the block.

### Extra Mile
1. **OWASP Top 10 (2025) audit** — [`docs/OWASP_TOP10_2025_AUDIT.md`](docs/OWASP_TOP10_2025_AUDIT.md).
2. **Encryption** — `private/src/Crypto.php` (AES-256-CBC via `openssl_encrypt()`,
   random IV, HMAC-SHA256, key from `APP_KEY` or `private/keys/app.key`;
   the comments explain encryption vs. hashing vs. encoding vs. obfuscation).
   `/notes.php` stores notes encrypted and shows the ciphertext for comparison.
3. **Content-Security-Policy** — sent on every response
   (`send_security_headers()`); `/csp_test.php` contains inline code and shows
   that the browser blocks it (DevTools console lists the violations).

---

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `production` disables demo pages by default |
| `APP_DEMO_PAGES` | `1` (`0` in production) | enable `error_test.php` / `vulnerable_search.php` (localhost only) |
| `APP_TIMEZONE` | `UTC` | timezone for logs and pages |
| `DB_DSN` | `sqlite:private/db/app.sqlite` | PDO DSN |
| `DB_USERNAME`, `DB_PASSWORD` | – | for MySQL/MariaDB |
| `SESSION_IDLE_TIMEOUT` | `1800` | idle timeout in seconds |
| `SESSION_COOKIE_SECURE` | `auto` | `1` forces the Secure flag (behind HTTPS) |
| `SESSION_BIND_IP` | `1` | include the IP address in the session fingerprint |
| `APP_KEY` | – | base64 32-byte encryption key (`php bin/generate-key.php`) |

Example: `SESSION_IDLE_TIMEOUT=60 php bin/serve.php` (Windows PowerShell:
`$env:SESSION_IDLE_TIMEOUT=60; php bin/serve.php`).

## HTTPS with a self-signed certificate

PHP's built-in server cannot do TLS. For a local HTTPS test put a TLS proxy in
front of it, e.g. with [Caddy](https://caddyserver.com/) (creates and trusts a
local certificate automatically):

```bash
SESSION_COOKIE_SECURE=1 php bin/serve.php --port=8000
caddy reverse-proxy --from https://localhost:8443 --to localhost:8000
```

or create a self-signed certificate yourself for nginx/Apache:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout localhost.key -out localhost.crt -subj "/CN=localhost"
```

With `SESSION_COOKIE_SECURE=1` the cookie becomes `__Host-SECSESSID` with the
`Secure` attribute (verified by the tests). In production run behind real
HTTPS, set `SESSION_COOKIE_SECURE=1` and `APP_ENV=production`.

## Using MySQL / MariaDB instead of SQLite

```bash
mysql -u root -p -e "CREATE DATABASE security_lab CHARACTER SET utf8mb4"
export DB_DSN="mysql:host=127.0.0.1;dbname=security_lab;charset=utf8mb4"
export DB_USERNAME=lab DB_PASSWORD=secret
php bin/init-db.php --seed && php bin/serve.php
```

The tables are created automatically from `private/db/schema.mysql.sql`.

## Before deploying anything based on this code

- Delete `public/vulnerable_search.php` and `public/error_test.php` (or keep `APP_ENV=production`).
- Use nginx/Apache + PHP-FPM with `public/` as document root and the `php.ini` directives.
- Serve over HTTPS, set `SESSION_COOKIE_SECURE=1` and an `APP_KEY` from a secret store.
- See the remaining gaps in the [OWASP audit](docs/OWASP_TOP10_2025_AUDIT.md#summary-of-the-most-important-remaining-gaps).
