-- V5__oauth2_enhancements.sql
-- Migration to enhance OAuth2 support and add missing columns
-- MySQL Database

-- =====================================================
-- SECTION 1: AUTH_USERS TABLE ENHANCEMENTS
-- =====================================================

-- Add email_verified column for OAuth users (they come pre-verified)
ALTER TABLE auth_users
ADD COLUMN email_verified BOOLEAN DEFAULT FALSE AFTER email;

-- Make password_hash nullable for OAuth-only users
ALTER TABLE auth_users
MODIFY COLUMN password_hash VARCHAR(255) NULL;

-- Add index for email verification status
CREATE INDEX idx_auth_users_email_verified ON auth_users(email_verified);

-- =====================================================
-- SECTION 2: OAUTH_CONNECTIONS ENHANCEMENTS
-- =====================================================

-- Add profile information from OAuth providers
ALTER TABLE oauth_connections
ADD COLUMN provider_email VARCHAR(255) AFTER provider_user_id,
ADD COLUMN provider_name VARCHAR(255) AFTER provider_email,
ADD COLUMN provider_avatar_url VARCHAR(500) AFTER provider_name;

-- Add scopes column to track granted permissions
ALTER TABLE oauth_connections
ADD COLUMN scopes TEXT AFTER provider_avatar_url;

-- Add index for faster lookups
CREATE INDEX idx_oauth_connections_provider_user ON oauth_connections(provider, provider_user_id);

-- =====================================================
-- SECTION 3: REFRESH_TOKENS ENHANCEMENTS
-- =====================================================

-- Add OAuth-related fields to refresh tokens
ALTER TABLE refresh_tokens
ADD COLUMN oauth_provider VARCHAR(50) AFTER user_agent,
ADD COLUMN session_id CHAR(36) AFTER oauth_provider;

-- Add index for session-based lookups
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);

-- =====================================================
-- SECTION 4: NEW TABLE - OAUTH_STATE_TOKENS
-- For CSRF protection during OAuth flow
-- =====================================================

CREATE TABLE oauth_state_tokens (
    id CHAR(36) PRIMARY KEY,
    state VARCHAR(255) NOT NULL UNIQUE,
    provider VARCHAR(50) NOT NULL,
    redirect_uri VARCHAR(500),
    client_info JSON,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_oauth_state_tokens_state ON oauth_state_tokens(state);
CREATE INDEX idx_oauth_state_tokens_expires_at ON oauth_state_tokens(expires_at);

-- =====================================================
-- SECTION 5: NEW TABLE - LINKED_ACCOUNTS_HISTORY
-- Track OAuth account linking/unlinking events
-- =====================================================

CREATE TABLE oauth_link_history (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    action VARCHAR(20) NOT NULL, -- 'LINKED', 'UNLINKED', 'UPDATED'
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_oauth_link_history_user_id ON oauth_link_history(user_id);
CREATE INDEX idx_oauth_link_history_provider ON oauth_link_history(provider);
CREATE INDEX idx_oauth_link_history_created_at ON oauth_link_history(created_at);

-- =====================================================
-- SECTION 6: UPDATE LOGIN_HISTORY FOR OAUTH
-- =====================================================

-- Add OAuth-specific fields to login history
ALTER TABLE login_history
ADD COLUMN oauth_provider VARCHAR(50) AFTER login_method;

-- Update login_method enum to include OAUTH values
-- Note: MySQL doesn't support ALTER ENUM easily, so we use VARCHAR
-- The application will validate the values

-- =====================================================
-- SECTION 7: SCHEDULED CLEANUP EVENTS
-- =====================================================

-- Create event to cleanup expired OAuth state tokens
DELIMITER //
CREATE EVENT IF NOT EXISTS cleanup_oauth_state_tokens
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM oauth_state_tokens
    WHERE expires_at < NOW() OR (used = TRUE AND used_at < DATE_SUB(NOW(), INTERVAL 1 DAY));
END //
DELIMITER ;

-- =====================================================
-- SECTION 8: VIEWS FOR OAUTH MANAGEMENT
-- =====================================================

-- View for users with their linked OAuth providers
CREATE OR REPLACE VIEW user_oauth_providers_view AS
SELECT
    u.id AS user_id,
    u.email,
    u.email_verified,
    u.password_hash IS NOT NULL AS has_password,
    COUNT(oc.id) AS linked_providers_count,
    GROUP_CONCAT(DISTINCT oc.provider ORDER BY oc.provider) AS linked_providers
FROM auth_users u
LEFT JOIN oauth_connections oc ON u.id = oc.user_id
GROUP BY u.id, u.email, u.email_verified, u.password_hash;

-- View for OAuth connection details
CREATE OR REPLACE VIEW oauth_connections_detail_view AS
SELECT
    oc.id,
    oc.user_id,
    u.email AS user_email,
    oc.provider,
    oc.provider_user_id,
    oc.provider_email,
    oc.provider_name,
    oc.created_at,
    oc.last_used_at,
    TIMESTAMPDIFF(DAY, oc.last_used_at, NOW()) AS days_since_last_use
FROM oauth_connections oc
JOIN auth_users u ON oc.user_id = u.id
ORDER BY oc.last_used_at DESC;
