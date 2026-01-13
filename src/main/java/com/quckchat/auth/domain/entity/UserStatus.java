package com.quckchat.auth.domain.entity;

/**
 * User online status enumeration.
 */
public enum UserStatus {
    ONLINE,
    OFFLINE,
    AWAY,
    BUSY;

    public static UserStatus fromString(String status) {
        if (status == null) {
            return OFFLINE;
        }
        try {
            return valueOf(status.toUpperCase());
        } catch (IllegalArgumentException e) {
            return OFFLINE;
        }
    }
}
