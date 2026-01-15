-- V4__rbac_sessions_login_history.sql
-- Migration to add enhanced RBAC, sessions management, login history, and user preferences
-- MySQL Database

-- =====================================================
-- SECTION 1: ROLE-BASED ACCESS CONTROL (RBAC)
-- =====================================================

-- Roles Table
CREATE TABLE roles (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    is_system_role BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    priority INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_is_active ON roles(is_active);

-- Permissions Table
CREATE TABLE permissions (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_resource_action (resource, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);

-- Role-Permission Mapping
CREATE TABLE role_permissions (
    role_id CHAR(36) NOT NULL,
    permission_id CHAR(36) NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by CHAR(36),
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- User-Role Mapping
CREATE TABLE user_roles (
    user_id CHAR(36) NOT NULL,
    role_id CHAR(36) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by CHAR(36),
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles(expires_at);

-- Insert Default Roles
INSERT INTO roles (id, name, description, is_system_role, priority) VALUES
    (UUID(), 'SUPER_ADMIN', 'Full system access with all permissions', TRUE, 100),
    (UUID(), 'ADMIN', 'Administrative access for managing users and settings', TRUE, 90),
    (UUID(), 'MODERATOR', 'Moderation access for content and user management', TRUE, 50),
    (UUID(), 'USER', 'Standard user with basic permissions', TRUE, 10),
    (UUID(), 'GUEST', 'Limited access for unauthenticated or trial users', TRUE, 0);

-- Insert Default Permissions
INSERT INTO permissions (id, name, description, resource, action) VALUES
    -- User Management
    (UUID(), 'users:read', 'View user information', 'users', 'read'),
    (UUID(), 'users:create', 'Create new users', 'users', 'create'),
    (UUID(), 'users:update', 'Update user information', 'users', 'update'),
    (UUID(), 'users:delete', 'Delete users', 'users', 'delete'),
    (UUID(), 'users:ban', 'Ban/unban users', 'users', 'ban'),
    -- Role Management
    (UUID(), 'roles:read', 'View roles', 'roles', 'read'),
    (UUID(), 'roles:create', 'Create new roles', 'roles', 'create'),
    (UUID(), 'roles:update', 'Update roles', 'roles', 'update'),
    (UUID(), 'roles:delete', 'Delete roles', 'roles', 'delete'),
    (UUID(), 'roles:assign', 'Assign roles to users', 'roles', 'assign'),
    -- Settings Management
    (UUID(), 'settings:read', 'View system settings', 'settings', 'read'),
    (UUID(), 'settings:update', 'Update system settings', 'settings', 'update'),
    -- Audit Logs
    (UUID(), 'audit:read', 'View audit logs', 'audit', 'read'),
    (UUID(), 'audit:export', 'Export audit logs', 'audit', 'export'),
    -- Sessions
    (UUID(), 'sessions:read', 'View active sessions', 'sessions', 'read'),
    (UUID(), 'sessions:revoke', 'Revoke user sessions', 'sessions', 'revoke');

-- =====================================================
-- SECTION 2: SESSIONS MANAGEMENT
-- =====================================================

-- Active Sessions Table
CREATE TABLE active_sessions (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    session_token_hash VARCHAR(255) NOT NULL UNIQUE,
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    device_type VARCHAR(50) DEFAULT 'UNKNOWN',
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    browser_name VARCHAR(100),
    browser_version VARCHAR(50),
    ip_address VARCHAR(45),
    country VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    is_active BOOLEAN DEFAULT TRUE,
    is_trusted BOOLEAN DEFAULT FALSE,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_active_sessions_user_id ON active_sessions(user_id);
CREATE INDEX idx_active_sessions_device_id ON active_sessions(device_id);
CREATE INDEX idx_active_sessions_is_active ON active_sessions(is_active);
CREATE INDEX idx_active_sessions_expires_at ON active_sessions(expires_at);
CREATE INDEX idx_active_sessions_last_activity ON active_sessions(last_activity_at);

-- Session Activity Log
CREATE TABLE session_activities (
    id CHAR(36) PRIMARY KEY,
    session_id CHAR(36) NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES active_sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_session_activities_session_id ON session_activities(session_id);
CREATE INDEX idx_session_activities_type ON session_activities(activity_type);
CREATE INDEX idx_session_activities_created_at ON session_activities(created_at);

-- =====================================================
-- SECTION 3: LOGIN HISTORY
-- =====================================================

-- Login History Table
CREATE TABLE login_history (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36),
    email VARCHAR(255),
    login_status VARCHAR(20) NOT NULL,
    login_method VARCHAR(50) DEFAULT 'PASSWORD',
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    browser_name VARCHAR(100),
    browser_version VARCHAR(50),
    country VARCHAR(100),
    country_code VARCHAR(10),
    region VARCHAR(100),
    city VARCHAR(100),
    postal_code VARCHAR(20),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    isp VARCHAR(255),
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_proxy BOOLEAN DEFAULT FALSE,
    risk_score INT DEFAULT 0,
    failure_reason VARCHAR(255),
    two_factor_used BOOLEAN DEFAULT FALSE,
    two_factor_method VARCHAR(50),
    session_id CHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_login_history_user_id ON login_history(user_id);
CREATE INDEX idx_login_history_email ON login_history(email);
CREATE INDEX idx_login_history_status ON login_history(login_status);
CREATE INDEX idx_login_history_ip ON login_history(ip_address);
CREATE INDEX idx_login_history_created_at ON login_history(created_at);
CREATE INDEX idx_login_history_device_id ON login_history(device_id);
CREATE INDEX idx_login_history_country ON login_history(country_code);
CREATE INDEX idx_login_history_method ON login_history(login_method);

-- Login Anomalies Table (for suspicious login detection)
CREATE TABLE login_anomalies (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    login_history_id CHAR(36),
    anomaly_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'MEDIUM',
    description VARCHAR(500),
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL,
    resolved_by CHAR(36),
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (login_history_id) REFERENCES login_history(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_login_anomalies_user_id ON login_anomalies(user_id);
CREATE INDEX idx_login_anomalies_type ON login_anomalies(anomaly_type);
CREATE INDEX idx_login_anomalies_severity ON login_anomalies(severity);
CREATE INDEX idx_login_anomalies_is_resolved ON login_anomalies(is_resolved);

-- =====================================================
-- SECTION 4: ENHANCED USER PREFERENCES
-- =====================================================

-- User Notification Preferences (extends user_settings)
CREATE TABLE user_notification_preferences (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL UNIQUE,
    -- Email Notifications
    email_marketing BOOLEAN DEFAULT FALSE,
    email_security_alerts BOOLEAN DEFAULT TRUE,
    email_login_alerts BOOLEAN DEFAULT TRUE,
    email_weekly_digest BOOLEAN DEFAULT FALSE,
    email_product_updates BOOLEAN DEFAULT FALSE,
    -- Push Notification Categories
    push_direct_messages BOOLEAN DEFAULT TRUE,
    push_mentions BOOLEAN DEFAULT TRUE,
    push_replies BOOLEAN DEFAULT TRUE,
    push_likes BOOLEAN DEFAULT TRUE,
    push_follows BOOLEAN DEFAULT TRUE,
    push_system_alerts BOOLEAN DEFAULT TRUE,
    -- Quiet Hours
    quiet_hours_enabled BOOLEAN DEFAULT FALSE,
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    quiet_hours_timezone VARCHAR(50) DEFAULT 'UTC',
    -- Notification Channels
    sms_enabled BOOLEAN DEFAULT FALSE,
    sms_security_only BOOLEAN DEFAULT TRUE,
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User Security Preferences
CREATE TABLE user_security_preferences (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL UNIQUE,
    -- Login Security
    require_2fa_for_sensitive_actions BOOLEAN DEFAULT FALSE,
    login_notification_enabled BOOLEAN DEFAULT TRUE,
    new_device_notification BOOLEAN DEFAULT TRUE,
    suspicious_activity_notification BOOLEAN DEFAULT TRUE,
    -- Session Preferences
    session_timeout_minutes INT DEFAULT 1440,
    max_concurrent_sessions INT DEFAULT 5,
    remember_trusted_devices BOOLEAN DEFAULT TRUE,
    trusted_device_expiry_days INT DEFAULT 30,
    -- Password Preferences
    password_expiry_days INT DEFAULT 0,
    require_password_change_on_next_login BOOLEAN DEFAULT FALSE,
    -- IP Restrictions
    ip_whitelist_enabled BOOLEAN DEFAULT FALSE,
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User IP Whitelist
CREATE TABLE user_ip_whitelist (
    user_id CHAR(36) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    description VARCHAR(255),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by CHAR(36),
    PRIMARY KEY (user_id, ip_address),
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Trusted Devices Table
CREATE TABLE trusted_devices (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    os_name VARCHAR(100),
    browser_name VARCHAR(100),
    is_trusted BOOLEAN DEFAULT TRUE,
    trusted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    UNIQUE KEY uk_user_device_fingerprint (user_id, device_fingerprint),
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_expires_at ON trusted_devices(expires_at);

-- =====================================================
-- SECTION 5: VIEWS FOR COMMON QUERIES
-- =====================================================

-- View for user with roles and permissions
CREATE VIEW user_roles_view AS
SELECT
    u.id AS user_id,
    u.email,
    r.id AS role_id,
    r.name AS role_name,
    r.priority AS role_priority,
    ur.assigned_at,
    ur.expires_at
FROM auth_users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE ur.is_active = TRUE
  AND (ur.expires_at IS NULL OR ur.expires_at > NOW());

-- View for active sessions summary
CREATE VIEW active_sessions_summary AS
SELECT
    u.id AS user_id,
    u.email,
    COUNT(s.id) AS session_count,
    MAX(s.last_activity_at) AS last_activity,
    GROUP_CONCAT(DISTINCT s.device_type) AS device_types
FROM auth_users u
LEFT JOIN active_sessions s ON u.id = s.user_id AND s.is_active = TRUE
GROUP BY u.id, u.email;

-- View for recent login activity
CREATE VIEW recent_login_activity AS
SELECT
    lh.user_id,
    lh.email,
    lh.login_status,
    lh.login_method,
    lh.ip_address,
    lh.country,
    lh.city,
    lh.device_type,
    lh.browser_name,
    lh.is_vpn,
    lh.risk_score,
    lh.created_at
FROM login_history lh
WHERE lh.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
ORDER BY lh.created_at DESC;
