# PHP Security Exercises

A small plain-PHP 8 application (PDO, no framework, no dependencies) that
implements the seven PHP security exercises and the three Extra Mile tasks.
The commit history follows the exercises one by one.

## Requirements

- PHP 8.1+ with the `pdo_sqlite`, `openssl`, `mbstring` and `session` extensions
- `curl` extension for the automated tests
- No database server needed: SQLite is used by default

On Ubuntu / WSL the extensions that are usually missing:

```bash
sudo apt install php-sqlite3 php-mbstring php-curl
```

## Quick start

```bash
php bin/init-db.php --seed   # create the SQLite database + demo users
php bin/serve.php            # → http://localhost:8000
```

`bin/serve.php` starts PHP's built-in server with `public/` as the document
root and applies the project's `php.ini`. Never run `php -S` from the project
root, as that would expose `private/`.

Demo accounts (local use only):

| Username | Password |
|---|---|
| alice | `Wonderland-2026` |
| bob | `Builder-Bob-2026` |
| carol | `Christmas-Carol-2026` |

`php bin/init-db.php --reset --seed` recreates the database;
`php bin/init-db.php --unblock` lifts a brute-force block.

## Tests

```bash
php tests/run.php          # all tests
php tests/run.php ex06     # one exercise only
```

## Project structure

```text
├── php.ini     hardened PHP settings (Exercise 01)
├── bin/        dev server, database setup, key generator
├── public/     DOCUMENT ROOT — the only web-accessible folder (pages, assets)
├── private/    bootstrap, config, classes (src/), templates, database, logs, sessions, keys
├── docs/       SQL injection comparison, OWASP Top 10 audit
├── tests/      test runner + one test file per exercise
└── tools/      fake attacker site for the manual CSRF test
```

Every directory contains an `index.php` guard (empty 403) to prevent
directory listing.

## Exercises

| # | Topic | Main files | Try it |
|---|---|---|---|
| 01 | Secure configuration | `php.ini`, `private/src/ErrorHandler.php` | `/error_test.php` — nothing technical in the browser, details in `private/logs/php_errors.log` |
| 02 | Validation & sanitization | `public/form.php`, `private/process.php` | `/form.php?novalidate=1` with `<script>alert('XSS')</script>` as the name |
| 03 | XSS & CSRF | `e()` in `private/src/helpers.php`, `private/src/Csrf.php` | remove or edit the hidden `csrf_token` in DevTools → 403 |
| 04 | SQL injection | `private/src/UserRepository.php`, `public/vulnerable_search.php` | `' OR '1'='1` on `/vulnerable_search.php` vs. `/search.php` — see [docs/SQL_INJECTION.md](docs/SQL_INJECTION.md) |
| 05 | Password handling | `public/register.php`, `login.php`, `dashboard.php`, `logout.php` | bcrypt hash in the database; `/dashboard.php` redirects to login when logged out |
| 06 | Session & cookies | `private/src/Session.php` | edit `SECSESSID` in DevTools → logged out; `SESSION_IDLE_TIMEOUT=60 php bin/serve.php` → expires after 1 minute |
| 07 | Security logging | `private/src/SecurityLogger.php`, `private/src/LoginThrottle.php` | `tail -f private/logs/security.log`, fail the login 5 times → HTTP 429 |

The `Secure` cookie flag is only set over HTTPS, and PHP's built-in server
speaks HTTP only. In production, run behind HTTPS with
`SESSION_COOKIE_SECURE=1`.

### Extra Mile

1. **OWASP Top 10 (2025) audit** — [docs/OWASP_TOP10_2025_AUDIT.md](docs/OWASP_TOP10_2025_AUDIT.md)
2. **Encryption** — `private/src/Crypto.php` (AES-256-CBC + HMAC-SHA256); try it on `/notes.php`
3. **Content-Security-Policy** — `script-src 'self'` on every response; `/csp_test.php` shows the blocked inline code in the DevTools console

`/error_test.php` and `/vulnerable_search.php` are localhost-only demo pages.
Remove them, or set `APP_ENV=production`, before deploying anything based on
this code.
