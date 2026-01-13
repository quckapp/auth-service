package com.quckchat.auth.domain.entity;

/**
 * Privacy visibility level enumeration.
 */
public enum VisibilityLevel {
    EVERYONE,
    CONTACTS,
    NOBODY;

    public static VisibilityLevel fromString(String level) {
        if (level == null) {
            return EVERYONE;
        }
        try {
            return valueOf(level.toUpperCase());
        } catch (IllegalArgumentException e) {
            return EVERYONE;
        }
    }
}
