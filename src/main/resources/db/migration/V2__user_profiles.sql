-- V2__user_profiles.sql
-- Migration to add user profiles, settings, and linked devices tables

-- User Profiles Table (One-to-One with auth_users)
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) UNIQUE,
    username VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    avatar TEXT,
    bio VARCHAR(500),
    public_key TEXT,
    status VARCHAR(20) DEFAULT 'OFFLINE',
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    role VARCHAR(20) DEFAULT 'USER',
    is_banned BOOLEAN DEFAULT FALSE,
    ban_reason VARCHAR(500),
    banned_at TIMESTAMP WITH TIME ZONE,
    banned_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for user_profiles
CREATE INDEX idx_user_profiles_phone ON user_profiles(phone_number);
CREATE INDEX idx_user_profiles_username ON user_profiles(username);
CREATE INDEX idx_user_profiles_email ON user_profiles(email);
CREATE INDEX idx_user_profiles_status ON user_profiles(status);
CREATE INDEX idx_user_profiles_role ON user_profiles(role);
CREATE INDEX idx_user_profiles_is_banned ON user_profiles(is_banned) WHERE is_banned = TRUE;

-- User Permissions Table (ElementCollection for UserProfile)
CREATE TABLE user_permissions (
    user_profile_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    permission VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_profile_id, permission)
);

CREATE INDEX idx_user_permissions_permission ON user_permissions(permission);

-- User Settings Table (One-to-One with user_profiles)
CREATE TABLE user_settings (
    id UUID PRIMARY KEY REFERENCES user_profiles(id) ON DELETE CASCADE,
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Blocked Users Table (ElementCollection for UserSettings)
CREATE TABLE blocked_users (
    user_settings_id UUID NOT NULL REFERENCES user_settings(id) ON DELETE CASCADE,
    blocked_user_id UUID NOT NULL,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_settings_id, blocked_user_id)
);

CREATE INDEX idx_blocked_users_blocked ON blocked_users(blocked_user_id);

-- Linked Devices Table
CREATE TABLE linked_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(20) DEFAULT 'MOBILE',
    fcm_token TEXT,
    last_active TIMESTAMP WITH TIME ZONE,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_linked_devices_user_device UNIQUE(user_id, device_id)
);

CREATE INDEX idx_linked_devices_user_id ON linked_devices(user_id);
CREATE INDEX idx_linked_devices_device_id ON linked_devices(device_id);
CREATE INDEX idx_linked_devices_fcm ON linked_devices(fcm_token) WHERE fcm_token IS NOT NULL;
CREATE INDEX idx_linked_devices_last_active ON linked_devices(last_active);

-- View for easy FCM token lookups (for push notifications)
CREATE VIEW user_fcm_tokens AS
SELECT
    up.id as user_id,
    up.username,
    up.display_name,
    array_agg(ld.fcm_token) FILTER (WHERE ld.fcm_token IS NOT NULL) as fcm_tokens
FROM user_profiles up
LEFT JOIN linked_devices ld ON ld.user_id = up.id
GROUP BY up.id, up.username, up.display_name;

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

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for user_profiles updated_at
CREATE TRIGGER update_user_profiles_updated_at
    BEFORE UPDATE ON user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for user_settings updated_at
CREATE TRIGGER update_user_settings_updated_at
    BEFORE UPDATE ON user_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE user_profiles IS 'User profile information - extends auth_users with full profile data';
COMMENT ON TABLE user_settings IS 'User preferences and privacy settings';
COMMENT ON TABLE user_permissions IS 'User permissions for admin/moderator access';
COMMENT ON TABLE blocked_users IS 'Users blocked by each user';
COMMENT ON TABLE linked_devices IS 'User devices with FCM tokens for push notifications';
COMMENT ON VIEW user_fcm_tokens IS 'Aggregated FCM tokens per user for push notification service';
COMMENT ON VIEW user_search_view IS 'Optimized view for user search operations';
