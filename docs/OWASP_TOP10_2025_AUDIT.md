# OWASP Top 10 (2025) — audit of this application

Scope: everything in this repository (Exercises 01–07 + Extra Mile), reviewed
against the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).
Status legend: ✅ addressed · 🟡 partly addressed · ⚪ mostly outside the app's scope.

| # | Category | Status | Main measures in this project |
|---|---|---|---|
| A01 | Broken Access Control | ✅ | login guard, owner-scoped queries, CSRF tokens, private/ outside docroot |
| A02 | Security Misconfiguration | ✅ | hardened php.ini, no error display, security headers, CSP |
| A03 | Software Supply Chain Failures | 🟡 | zero third-party dependencies; PHP runtime itself must be patched |
| A04 | Cryptographic Failures | 🟡 | bcrypt, AES-256 + HMAC, CSPRNG tokens; no HTTPS in local dev |
| A05 | Injection | ✅ | prepared statements, output encoding, CSP, allow-list validation |
| A06 | Insecure Design | 🟡 | rate limiting, PRG, single-use tokens; no MFA / recovery flow |
| A07 | Authentication Failures | ✅ | bcrypt, session regeneration, timeout, fingerprint, brute-force block |
| A08 | Software or Data Integrity Failures | 🟡 | HMAC on encrypted data, no unserialize, no external scripts |
| A09 | Security Logging & Alerting Failures | 🟡 | complete security log; no alerting or central log storage |
| A10 | Mishandling of Exceptional Conditions | ✅ | central error handler, fail-closed checks, generic error page |

---

## A01:2025 — Broken Access Control ✅

**Addressed**
- Protected pages call `Auth::requireLogin()` (dashboard, search, notes, change password); anonymous users are redirected (`private/src/Auth.php`).
- Notes are always queried with `WHERE user_id = :user_id` — reading or deleting another user's note by guessing its ID (IDOR) is impossible (`NoteRepository.php`, tested in `ex08`).
- User search (which shows email addresses) requires login.
- CSRF (CWE-352, part of A01): single-use synchronizer tokens on every state-changing form, including login and logout (`Csrf.php`), plus `SameSite=Strict` cookies.
- Open redirects (CWE-601) are prevented: `redirect()` only accepts local paths.
- Code, config, logs, database, sessions and keys are in `private/`, outside the document root; every directory has an `index.php` guard; `private/.htaccess` denies access on Apache.
- Demo pages (`error_test.php`, `vulnerable_search.php`) answer 404 unless the request comes from localhost **and** demo mode is on.
- Authenticated pages send `Cache-Control: no-store`.

**Remaining gaps**
- No roles/permissions (every user has the same rights); a real app would need an authorization layer (e.g. admin vs. user) with deny-by-default checks.
- Any logged-in user can list all users' email addresses through the search — acceptable for the exercise, too generous for production.

## A02:2025 — Security Misconfiguration ✅

**Addressed**
- `php.ini`: `display_errors=Off`, `log_errors=On`, `expose_php=Off`, `disable_functions` (exec, system, passthru + equivalents), `allow_url_include/fopen=Off`, hardened session defaults; the runtime-changeable ones are enforced again with `ini_set()` in `bootstrap.php`.
- Response headers: CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, HSTS on HTTPS.
- Generic error page — no stack traces, paths or versions are ever shown.
- `APP_ENV=production` switches the demo pages off by default.

**Remaining gaps**
- PHP's built-in server is for development only; production needs a real web server (nginx/Apache + PHP-FPM) configured with `public/` as document root and the php.ini directives above.
- HTTPS/TLS configuration and certificate management are deployment tasks (see README).
- There is no automated check that a production deployment really runs with `APP_ENV=production`.

## A03:2025 — Software Supply Chain Failures 🟡

**Addressed**
- The application has **no third-party dependencies**: no Composer packages, no npm packages, no CDN-hosted scripts, styles or fonts. The attack surface of the supply chain is limited to PHP itself.
- The CSP (`script-src 'self'`) would block any script injected from a foreign origin.

**Remaining gaps**
- PHP and its extensions (OpenSSL, PDO, …) must be kept patched; there is no version pinning or automated update/vulnerability alert (e.g. Dependabot/Renovate, `composer audit` once dependencies exist).
- No CI pipeline, no signed commits/releases, no SBOM.

## A04:2025 — Cryptographic Failures 🟡

**Addressed**
- Passwords: `password_hash()` (bcrypt, cost 12, per-password salt) + `password_verify()`; `password_needs_rehash()` upgrades old hashes; 72-byte bcrypt limit enforced.
- Sensitive data at rest (notes): AES-256-CBC with a random IV per message and HMAC-SHA256 (encrypt-then-MAC, verified with `hash_equals()` before decrypting), HKDF-derived sub-keys (`Crypto.php`).
- The key lives outside the database (`APP_KEY` or `private/keys/app.key`, mode 0600, git-ignored).
- All tokens and keys come from the CSPRNG (`random_bytes()`); comparisons are constant-time (`hash_equals()`).
- `Secure` + `__Host-` cookie and HSTS when served over HTTPS.

**Remaining gaps**
- Local development runs over plain HTTP; HTTPS must be provided by the deployment.
- No key rotation: changing the key makes existing notes unreadable (the `v1:` prefix is prepared for it).
- With the key file on the same server as the database, a full server compromise exposes both — production should use a secret manager / KMS.
- AES-CBC + HMAC is correct but more error-prone than an AEAD (AES-256-GCM or `sodium_crypto_secretbox`).
- Email addresses (personal data) are stored in plain text.

## A05:2025 — Injection ✅

**Addressed**
- SQL: every query uses PDO prepared statements with bound parameters; native prepares (`ATTR_EMULATE_PREPARES=false`); LIKE wildcards escaped (`UserRepository.php`, `docs/SQL_INJECTION.md`).
- XSS: every output goes through `e()` (`htmlspecialchars`, `ENT_QUOTES`, UTF-8); URLs restricted to http/https; strict CSP as a second line of defense (verified in Chromium).
- Input validation with allow-lists (username pattern, `filter_var`, length limits counted with `mb_strlen`); arrays in parameters are rejected (`post_string()`).
- OS command injection: shell functions are disabled in `php.ini`.
- Log injection: log fields are JSON-encoded, so newlines cannot forge entries (tested).

**Remaining gaps**
- `public/vulnerable_search.php` is **intentionally** injectable (localhost + demo mode only). Delete it before any real deployment.
- Exercise 02 asks for HTML encoding at input time; the encoded values are only safe for HTML. If they were reused in another context (JSON API, email, CSV) they would need decoding and context-specific encoding there.

## A06:2025 — Insecure Design 🟡

**Addressed**
- Defense in depth throughout: e.g. SQLi is prevented (prepared statements), detected (AttackDetector) and limited (allow-list validation); XSS is prevented (encoding) and contained (CSP).
- Brute-force limit (5 failures / 10 min / IP, sliding window, stored server-side); single-use CSRF tokens; Post/Redirect/Get; generic error messages; password policy.
- Security behaviour is pinned down by 76 automated tests (`php tests/run.php`).

**Remaining gaps**
- No multi-factor authentication, password reset or email verification flow.
- Per-IP throttling can be bypassed by attackers with many IPs and can lock out users sharing one NAT/proxy IP; a combination with per-account delays or CAPTCHAs would be stronger.
- Registration has no rate limit or bot protection.
- No written threat model.

## A07:2025 — Authentication Failures ✅

**Addressed**
- bcrypt hashing; dummy-hash verification for unknown users (no timing-based user enumeration); identical error message for wrong user / wrong password.
- `session_regenerate_id(true)` after login and password change (session fixation); strict mode rejects forged IDs.
- Session cookie: `HttpOnly`, `SameSite=Strict`, `Secure` on HTTPS, host-only, no persistent expiry.
- 30-minute idle timeout; IP + User-Agent fingerprint; logout destroys data and cookie.
- 5 failed attempts per IP in 10 minutes → blocked (HTTP 429 + `Retry-After`), even for the correct password.
- Password change requires the current password and counts failures toward the same limit.

**Remaining gaps**
- No MFA; no check against breached-password lists (e.g. the HIBP k-anonymity API).
- Registration reveals whether a username/email exists ("already registered").
- Other active sessions of the same user are not terminated after a password change.
- IP binding can log out mobile users when their IP changes (configurable via `SESSION_BIND_IP`).

## A08:2025 — Software or Data Integrity Failures 🟡

**Addressed**
- Encrypted notes are authenticated (HMAC); any modification in the database is detected, shown as an error and logged (`DECRYPTION_FAILED`).
- Session data stays on the server; the client only holds a random ID.
- No `unserialize()` of user-controlled data anywhere; no external scripts (no need for Subresource Integrity).

**Remaining gaps**
- No integrity protection for deployments (CI, signed artifacts) or for the log files.
- Users' other data (username, email) is not integrity-protected beyond database access control.

## A09:2025 — Security Logging & Alerting Failures 🟡

**Addressed**
- `SecurityLogger` records, with timestamp, level, IP, user and request: PHP errors/exceptions/fatals; logins, failed logins, logouts, registrations, password changes; CSRF mismatches, SQLi/XSS patterns, repeated failures, brute-force blocks, session fingerprint mismatches, rejected session IDs, decryption failures.
- No secrets in logs (password fields are never inspected; sensitive context keys are redacted); values truncated; log injection impossible.
- PHP's own error log in `private/logs/php_errors.log`.

**Remaining gaps**
- **No alerting**: nobody is notified of `ALERT` events; logs must be watched manually.
- Logs are local files: no rotation/retention policy, no shipping to a central, tamper-resistant store (SIEM), no integrity protection.
- The SQLi/XSS detector is pattern-based (bypassable, some false positives) — it is a visibility aid only.

## A10:2025 — Mishandling of Exceptional Conditions ✅

**Addressed**
- Central `ErrorHandler`: warnings are logged; uncaught exceptions and fatal errors (including out-of-memory, thanks to reserved memory) are logged and answered with a generic 500 page; output buffering discards half-rendered pages.
- **Fail closed** everywhere: missing/invalid CSRF token → 403; unknown session ID → new empty session; fingerprint mismatch → session wiped; MAC failure → no plaintext returned; DB errors → exception (`ERRMODE_EXCEPTION`), never silently ignored; brute-force check happens before the password check.
- Unexpected input types (arrays instead of strings) are rejected; `declare(strict_types=1)` in all scripts and classes.
- A failing logger cannot take the application down (guarded, recursion-safe).

**Remaining gaps**
- No explicit limits beyond PHP defaults for request size / execution time per endpoint (`post_max_size`, `max_input_vars`, …) — should be tuned for production.
- Multi-step operations are not wrapped in database transactions (none currently need it, but future features might).

---

## Summary of the most important remaining gaps

1. HTTPS is not part of the local setup (deployment task) → cookies are only `Secure` behind TLS.
2. No MFA, no password reset/verification flow, no breached-password check.
3. No alerting / central log storage for the security log.
4. No authorization roles beyond "logged in".
5. `vulnerable_search.php` and `error_test.php` must be removed (or demo mode kept off) in any real deployment.
6. Key management (rotation, KMS) for the encryption key.
