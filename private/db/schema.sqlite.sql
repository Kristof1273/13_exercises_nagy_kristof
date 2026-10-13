-- SQLite schema. Executed automatically (idempotent) by Database::connection().

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   VARCHAR(30)  NOT NULL UNIQUE COLLATE NOCASE,
    email      VARCHAR(254) NOT NULL UNIQUE COLLATE NOCASE,
    -- password_hash() output (Exercise 05). bcrypt needs 60 characters today;
    -- 255 leaves room for future algorithms (PHP's recommendation).
    password   VARCHAR(255) NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Failed login attempts for brute-force protection (Exercise 07)
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           VARCHAR(45)  NOT NULL,
    username     VARCHAR(255) NOT NULL,
    attempted_at INTEGER      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts (ip, attempted_at);
