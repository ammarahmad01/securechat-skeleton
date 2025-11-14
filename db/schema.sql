-- Secure Chat Assignment 2 — MySQL schema
-- Users table stores email (PK), unique username, per-user salt (16 bytes),
-- and SHA-256 password hash (hex-encoded, 64 chars).

CREATE TABLE IF NOT EXISTS users (
  email VARCHAR(255) PRIMARY KEY,
  username VARCHAR(255) UNIQUE,
  salt VARBINARY(16),
  pwd_hash CHAR(64)
);
