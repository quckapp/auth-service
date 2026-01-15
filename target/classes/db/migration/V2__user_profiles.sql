-- V2__user_profiles.sql
-- Migration to add user profiles, settings, and linked devices tables
-- MySQL Database

-- User Profiles Table (One-to-One with auth_users)
CREATE TABLE user_profiles (
    id CHAR(36) PRIMARY KEY,
    phone_number VARCHAR(20) UNIQUE,
    username VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    avatar TEXT,
    bio VARCHAR(500),
    public_key TEXT,
    status VARCHAR(20) DEFAULT 'OFFLINE',
    last_seen TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    role VARCHAR(20) DEFAULT 'USER',
    is_banned BOOLEAN DEFAULT FALSE,
    ban_reason VARCHAR(500),
    banned_at TIMESTAMP NULL,
    banned_by CHAR(36),
    phone_verified BOOLEAN DEFAULT FALSE,
    phone_verified_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (id) REFERENCES auth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indexes for user_profiles
CREATE INDEX idx_user_profiles_phone ON user_profiles(phone_number);
CREATE INDEX idx_user_profiles_username ON user_profiles(username);
CREATE INDEX idx_user_profiles_email ON user_profiles(email);
CREATE INDEX idx_user_profiles_status ON user_profiles(status);
CREATE INDEX idx_user_profiles_role ON user_profiles(role);
CREATE INDEX idx_user_profiles_is_banned ON user_profiles(is_banned);

-- User Permissions Table (ElementCollection for UserProfile)
CREATE TABLE user_permissions (
    user_profile_id CHAR(36) NOT NULL,
    permission VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_profile_id, permission),
    FOREIGN KEY (user_profile_id) REFERENCES user_profiles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_user_permissions_permission ON user_permissions(permission);

-- User Settings Table (One-to-One with user_profiles)
CREATE TABLE user_settings (
    id CHAR(36) PRIMARY KEY,
    -- Appearance
    dark_mode BOOLEAN DEFAULT FALSE,
    -- Media & Storage
    auto_download_media BOOLEAN DEFAULT TRUE,
    save_to_gallery BOOLEAN DEFAULT FALSE,
    -- Notifications
    push_notifications BOOLEAN DEFAULT TRUE,
    message_notifications BOOLEAN DEFAULT TRUE,
    group_notifications BOOLEAN DEFAULT TRUE,
    call_notifications BOOLEAN DEFAULT TRUE,
    sound_enabled BOOLEAN DEFAULT TRUE,
    vibration_enabled BOOLEAN DEFAULT TRUE,
    show_preview BOOLEAN DEFAULT TRUE,
    in_app_notifications BOOLEAN DEFAULT TRUE,
    notification_light BOOLEAN DEFAULT TRUE,
    -- Privacy
    read_receipts BOOLEAN DEFAULT TRUE,
    last_seen_visible BOOLEAN DEFAULT TRUE,
    profile_photo_visibility VARCHAR(20) DEFAULT 'EVERYONE',
    status_visibility VARCHAR(20) DEFAULT 'EVERYONE',
    -- Security
    fingerprint_lock BOOLEAN DEFAULT FALSE,
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (id) REFERENCES user_profiles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Blocked Users Table (ElementCollection for UserSettings)
CREATE TABLE blocked_users (
    user_settings_id CHAR(36) NOT NULL,
    blocked_user_id CHAR(36) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_settings_id, blocked_user_id),
    FOREIGN KEY (user_settings_id) REFERENCES user_settings(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_blocked_users_blocked ON blocked_users(blocked_user_id);

-- Linked Devices Table
CREATE TABLE linked_devices (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(20) DEFAULT 'MOBILE',
    fcm_token TEXT,
    last_active TIMESTAMP NULL,
    linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_linked_devices_user_device (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES user_profiles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_linked_devices_user_id ON linked_devices(user_id);
CREATE INDEX idx_linked_devices_device_id ON linked_devices(device_id);
CREATE INDEX idx_linked_devices_last_active ON linked_devices(last_active);

-- View for user search (commonly used fields)
CREATE VIEW user_search_view AS
SELECT
    up.id,
    au.external_id,
    up.phone_number,
    up.username,
    up.display_name,
    up.email,
    up.avatar,
    up.bio,
    up.status,
    up.last_seen,
    up.is_active,
    up.is_verified,
    up.role,
    up.is_banned,
    up.created_at
FROM user_profiles up
JOIN auth_users au ON au.id = up.id
WHERE up.is_active = TRUE AND up.is_banned = FALSE;
