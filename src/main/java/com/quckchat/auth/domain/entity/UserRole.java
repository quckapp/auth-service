package com.quckchat.auth.domain.entity;

/**
 * User role enumeration for authorization.
 */
public enum UserRole {
    USER,
    MODERATOR,
    ADMIN,
    SUPER_ADMIN;

    public static UserRole fromString(String role) {
        if (role == null) {
            return USER;
        }
        try {
            return valueOf(role.toUpperCase());
        } catch (IllegalArgumentException e) {
            return USER;
        }
    }

    public boolean hasAdminAccess() {
        return this == ADMIN || this == SUPER_ADMIN;
    }

    public boolean hasModeratorAccess() {
        return this == MODERATOR || hasAdminAccess();
    }
}
