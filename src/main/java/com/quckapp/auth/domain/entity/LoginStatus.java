package com.quckapp.auth.domain.entity;

/**
 * Login attempt status
 */
public enum LoginStatus {
    SUCCESS,
    FAILED,
    BLOCKED,
    PENDING_2FA,
    EXPIRED,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    ACCOUNT_DISABLED,
    IP_BLOCKED,
    DEVICE_BLOCKED,
    CAPTCHA_REQUIRED,
    CAPTCHA_FAILED
}
