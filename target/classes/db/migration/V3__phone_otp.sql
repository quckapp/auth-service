-- Phone OTP table for phone-based authentication
-- MySQL Database

CREATE TABLE phone_otps (
    id CHAR(36) PRIMARY KEY,
    phone_number VARCHAR(20) NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP NULL,
    attempt_count INT DEFAULT 0,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indexes for efficient querying
CREATE INDEX idx_phone_otps_phone_number ON phone_otps(phone_number);
CREATE INDEX idx_phone_otps_expires_at ON phone_otps(expires_at);
CREATE INDEX idx_phone_otps_verified ON phone_otps(verified);
CREATE INDEX idx_phone_otps_phone_expires ON phone_otps(phone_number, expires_at);
