-- V8: Add created_at column to trusted_devices table
-- The TrustedDevice entity has @CreatedDate createdAt field but the table is missing this column

ALTER TABLE trusted_devices
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
