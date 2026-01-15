package com.quckapp.auth.domain.entity;

/**
 * Types of session activities
 */
public enum SessionActivityType {
    SESSION_CREATED,
    SESSION_REFRESHED,
    SESSION_TERMINATED,
    PASSWORD_CHANGED,
    PROFILE_UPDATED,
    SETTINGS_CHANGED,
    TWO_FACTOR_ENABLED,
    TWO_FACTOR_DISABLED,
    API_KEY_CREATED,
    API_KEY_REVOKED,
    SENSITIVE_ACTION,
    LOCATION_CHANGED,
    DEVICE_TRUSTED,
    DEVICE_UNTRUSTED
}
