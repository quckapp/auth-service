-- Email OTP table for email-based verification
-- MySQL Database

CREATE TABLE email_otps (
    id CHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP NULL,
    attempt_count INT DEFAULT 0,
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    user_id CHAR(36) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indexes for efficient querying
CREATE INDEX idx_email_otps_email ON email_otps(email);
CREATE INDEX idx_email_otps_expires_at ON email_otps(expires_at);
CREATE INDEX idx_email_otps_verified ON email_otps(verified);
CREATE INDEX idx_email_otps_email_expires ON email_otps(email, expires_at);
CREATE INDEX idx_email_otps_user_id ON email_otps(user_id);
