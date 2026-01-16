package com.quckapp.auth.dto;

import com.quckapp.auth.domain.entity.*;
import lombok.*;

import java.time.Instant;
import java.time.LocalTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * DTOs for User Preferences operations
 */
public class UserPreferencesDtos {

    // ==================== Notification Preferences DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NotificationPreferencesDto {
        private UUID id;
        private UUID userId;
        // Email
        private boolean emailMarketing;
        private boolean emailSecurityAlerts;
        private boolean emailLoginAlerts;
        private boolean emailWeeklyDigest;
        private boolean emailProductUpdates;
        // Push
        private boolean pushDirectMessages;
        private boolean pushMentions;
        private boolean pushReplies;
        private boolean pushLikes;
        private boolean pushFollows;
        private boolean pushSystemAlerts;
        // Quiet Hours
        private boolean quietHoursEnabled;
        private LocalTime quietHoursStart;
        private LocalTime quietHoursEnd;
        private String quietHoursTimezone;
        // SMS
        private boolean smsEnabled;
        private boolean smsSecurityOnly;
        // Timestamps
        private Instant createdAt;
        private Instant updatedAt;

        public static NotificationPreferencesDto from(UserNotificationPreferences prefs) {
            return NotificationPreferencesDto.builder()
                    .id(prefs.getId())
                    .userId(prefs.getUser().getId())
                    .emailMarketing(prefs.isEmailMarketing())
                    .emailSecurityAlerts(prefs.isEmailSecurityAlerts())
                    .emailLoginAlerts(prefs.isEmailLoginAlerts())
                    .emailWeeklyDigest(prefs.isEmailWeeklyDigest())
                    .emailProductUpdates(prefs.isEmailProductUpdates())
                    .pushDirectMessages(prefs.isPushDirectMessages())
                    .pushMentions(prefs.isPushMentions())
                    .pushReplies(prefs.isPushReplies())
                    .pushLikes(prefs.isPushLikes())
                    .pushFollows(prefs.isPushFollows())
                    .pushSystemAlerts(prefs.isPushSystemAlerts())
                    .quietHoursEnabled(prefs.isQuietHoursEnabled())
                    .quietHoursStart(prefs.getQuietHoursStart())
                    .quietHoursEnd(prefs.getQuietHoursEnd())
                    .quietHoursTimezone(prefs.getQuietHoursTimezone())
                    .smsEnabled(prefs.isSmsEnabled())
                    .smsSecurityOnly(prefs.isSmsSecurityOnly())
                    .createdAt(prefs.getCreatedAt())
                    .updatedAt(prefs.getUpdatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateNotificationPreferencesRequest {
        // Email
        private Boolean emailMarketing;
        private Boolean emailSecurityAlerts;
        private Boolean emailLoginAlerts;
        private Boolean emailWeeklyDigest;
        private Boolean emailProductUpdates;
        // Push
        private Boolean pushDirectMessages;
        private Boolean pushMentions;
        private Boolean pushReplies;
        private Boolean pushLikes;
        private Boolean pushFollows;
        private Boolean pushSystemAlerts;
        // Quiet Hours
        private Boolean quietHoursEnabled;
        private LocalTime quietHoursStart;
        private LocalTime quietHoursEnd;
        private String quietHoursTimezone;
        // SMS
        private Boolean smsEnabled;
        private Boolean smsSecurityOnly;
    }

    // ==================== Security Preferences DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SecurityPreferencesDto {
        private UUID id;
        private UUID userId;
        // Login Security
        private boolean require2faForSensitiveActions;
        private boolean loginNotificationEnabled;
        private boolean newDeviceNotification;
        private boolean suspiciousActivityNotification;
        // Session
        private int sessionTimeoutMinutes;
        private int maxConcurrentSessions;
        private boolean rememberTrustedDevices;
        private int trustedDeviceExpiryDays;
        // Password
        private int passwordExpiryDays;
        private boolean requirePasswordChangeOnNextLogin;
        // IP Restrictions
        private boolean ipWhitelistEnabled;
        private Set<String> ipWhitelist;
        // Timestamps
        private Instant createdAt;
        private Instant updatedAt;

        public static SecurityPreferencesDto from(UserSecurityPreferences prefs) {
            return SecurityPreferencesDto.builder()
                    .id(prefs.getId())
                    .userId(prefs.getUser().getId())
                    .require2faForSensitiveActions(prefs.isRequire2faForSensitiveActions())
                    .loginNotificationEnabled(prefs.isLoginNotificationEnabled())
                    .newDeviceNotification(prefs.isNewDeviceNotification())
                    .suspiciousActivityNotification(prefs.isSuspiciousActivityNotification())
                    .sessionTimeoutMinutes(prefs.getSessionTimeoutMinutes())
                    .maxConcurrentSessions(prefs.getMaxConcurrentSessions())
                    .rememberTrustedDevices(prefs.isRememberTrustedDevices())
                    .trustedDeviceExpiryDays(prefs.getTrustedDeviceExpiryDays())
                    .passwordExpiryDays(prefs.getPasswordExpiryDays())
                    .requirePasswordChangeOnNextLogin(prefs.isRequirePasswordChangeOnNextLogin())
                    .ipWhitelistEnabled(prefs.isIpWhitelistEnabled())
                    .ipWhitelist(prefs.getIpWhitelist())
                    .createdAt(prefs.getCreatedAt())
                    .updatedAt(prefs.getUpdatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateSecurityPreferencesRequest {
        // Login Security
        private Boolean require2faForSensitiveActions;
        private Boolean loginNotificationEnabled;
        private Boolean newDeviceNotification;
        private Boolean suspiciousActivityNotification;
        // Session
        private Integer sessionTimeoutMinutes;
        private Integer maxConcurrentSessions;
        private Boolean rememberTrustedDevices;
        private Integer trustedDeviceExpiryDays;
        // Password
        private Integer passwordExpiryDays;
        // IP Restrictions
        private Boolean ipWhitelistEnabled;
    }

    // ==================== Trusted Device DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TrustedDeviceDto {
        private UUID id;
        private UUID userId;
        private String deviceFingerprint;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String browserName;
        private boolean trusted;
        private Instant trustedAt;
        private Instant lastUsedAt;
        private Instant expiresAt;

        public static TrustedDeviceDto from(TrustedDevice device) {
            return TrustedDeviceDto.builder()
                    .id(device.getId())
                    .userId(device.getUser().getId())
                    .deviceFingerprint(device.getDeviceFingerprint())
                    .deviceName(device.getDeviceName())
                    .deviceType(device.getDeviceType())
                    .osName(device.getOsName())
                    .browserName(device.getBrowserName())
                    .trusted(device.isTrusted())
                    .trustedAt(device.getTrustedAt())
                    .lastUsedAt(device.getLastUsedAt())
                    .expiresAt(device.getExpiresAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TrustDeviceRequest {
        private String deviceFingerprint;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String browserName;
        private Integer expiryDays;
    }

    // ==================== Combined Preferences DTO ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserPreferencesDto {
        private UUID userId;
        private NotificationPreferencesDto notificationPreferences;
        private SecurityPreferencesDto securityPreferences;
        private List<TrustedDeviceDto> trustedDevices;
    }
}
