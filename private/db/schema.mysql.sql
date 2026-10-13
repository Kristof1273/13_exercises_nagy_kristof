-- MySQL / MariaDB schema. Executed automatically (idempotent) by Database::connection().

CREATE TABLE IF NOT EXISTS users (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(30)  NOT NULL UNIQUE,
    email      VARCHAR(254) NOT NULL UNIQUE,
    -- password_hash() output (Exercise 05). bcrypt needs 60 characters today;
    -- 255 leaves room for future algorithms (PHP's recommendation).
    password   VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
