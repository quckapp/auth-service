package com.quckchat.auth.domain.entity;

/**
 * Device type enumeration for linked devices.
 */
public enum DeviceType {
    MOBILE,
    WEB,
    DESKTOP;

    public static DeviceType fromString(String type) {
        if (type == null) {
            return MOBILE;
        }
        try {
            return valueOf(type.toUpperCase());
        } catch (IllegalArgumentException e) {
            return MOBILE;
        }
    }
}
