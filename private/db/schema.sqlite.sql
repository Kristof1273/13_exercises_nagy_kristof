-- SQLite schema. Executed automatically (idempotent) by Database::connection().

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   VARCHAR(30)  NOT NULL UNIQUE COLLATE NOCASE,
    email      VARCHAR(254) NOT NULL UNIQUE COLLATE NOCASE,
    -- Password hash (Exercise 05). 255 characters leave room for future algorithms.
    password   VARCHAR(255) NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
