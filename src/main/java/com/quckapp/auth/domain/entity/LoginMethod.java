package com.quckapp.auth.domain.entity;

/**
 * Authentication method used for login
 */
public enum LoginMethod {
    PASSWORD,
    OAUTH,
    OAUTH_GOOGLE,
    OAUTH_GITHUB,
    OAUTH_FACEBOOK,
    OAUTH_APPLE,
    OAUTH_MICROSOFT,
    MAGIC_LINK,
    OTP_SMS,
    OTP_EMAIL,
    API_KEY,
    SSO,
    BIOMETRIC,
    PASSKEY
}
