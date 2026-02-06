-- Secure API Database Schema
-- OWASP A03: Injection prevention - use parameterized queries in application code
-- OWASP A02: Passwords stored as bcrypt hashes only

CREATE TABLE IF NOT EXISTS `users` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL COMMENT 'bcrypt hashed',
    `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    `active` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_users_email` (`email`),
    KEY `idx_users_active` (`active`),
    KEY `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed an admin user (password: Admin123! — CHANGE THIS immediately after setup)
-- Generated with: password_hash('Admin123!', PASSWORD_BCRYPT, ['cost' => 12])
INSERT INTO `users` (`name`, `email`, `password`, `role`, `active`)
VALUES ('Admin', 'admin@example.com', '$2y$12$MSfEm0G9tGMMl8ljP6kzxumsMct7pdyPipLbXkRBwhMDW1GLUaUiq', 'admin', 1)
ON DUPLICATE KEY UPDATE `id` = `id`;
