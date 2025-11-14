-- MySQL dump for secure_chat (Assignment 2)
-- WARNING: Sample salts and hashes for illustration only.

DROP TABLE IF EXISTS users;

CREATE TABLE users (
  email VARCHAR(255) PRIMARY KEY,
  username VARCHAR(255) UNIQUE,
  salt VARBINARY(16),
  pwd_hash CHAR(64)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample user records (password derivation: SHA256(salt || UTF8(password)))
-- password = P@ssw0rd!
INSERT INTO users (email, username, salt, pwd_hash) VALUES
  ('test@example.com', 'testuser', x'A1B2C3D4E5F60718293A4B5C6D7E8F90', '4d9188d1c3c5bd9f3e4e4b2f9ea7c0ab0e7cf7f8a5e7e6d8b2e8f3d1c9b7a6e5'),
  ('tester@example.com', 'tester',   x'0102030405060708090A0B0C0D0E0F10', '9bd6f1ea1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6');

-- End of dump
