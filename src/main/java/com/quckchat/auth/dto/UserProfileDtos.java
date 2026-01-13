package com.quckchat.auth.dto;

import com.quckchat.auth.domain.entity.*;
import jakarta.validation.constraints.*;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * DTOs for User Profile operations
 */
public class UserProfileDtos {

    // ==================== Profile DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CreateProfileRequest {
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be 3-50 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
        private String username;

        @NotBlank(message = "Display name is required")
        @Size(min = 2, max = 100, message = "Display name must be 2-100 characters")
        private String displayName;

        @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid phone number format")
        private String phoneNumber;

        @Email(message = "Invalid email format")
        private String email;

        private String avatar;

        @Size(max = 500, message = "Bio cannot exceed 500 characters")
        private String bio;

        private String publicKey;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateProfileRequest {
        @Size(min = 3, max = 50, message = "Username must be 3-50 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
        private String username;

        @Size(min = 2, max = 100, message = "Display name must be 2-100 characters")
        private String displayName;

        @Email(message = "Invalid email format")
        private String email;

        private String avatar;

        @Size(max = 500, message = "Bio cannot exceed 500 characters")
        private String bio;

        private String publicKey;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserProfileDto {
        private UUID id;
        private String externalId;
        private String phoneNumber;
        private String username;
        private String displayName;
        private String email;
        private String avatar;
        private String bio;
        private String publicKey;
        private UserStatus status;
        private Instant lastSeen;
        private boolean isActive;
        private boolean isVerified;
        private UserRole role;
        private Set<String> permissions;
        private boolean isBanned;
        private String banReason;
        private Instant bannedAt;
        private UUID bannedBy;
        private Instant createdAt;
        private Instant updatedAt;

        public static UserProfileDto from(UserProfile profile) {
            if (profile == null) return null;
            return UserProfileDto.builder()
                    .id(profile.getId())
                    .externalId(profile.getAuthUser() != null ? profile.getAuthUser().getExternalId() : null)
                    .phoneNumber(profile.getPhoneNumber())
                    .username(profile.getUsername())
                    .displayName(profile.getDisplayName())
                    .email(profile.getEmail())
                    .avatar(profile.getAvatar())
                    .bio(profile.getBio())
                    .publicKey(profile.getPublicKey())
                    .status(profile.getStatus())
                    .lastSeen(profile.getLastSeen())
                    .isActive(profile.isActive())
                    .isVerified(profile.isVerified())
                    .role(profile.getRole())
                    .permissions(profile.getPermissions())
                    .isBanned(profile.isBanned())
                    .banReason(profile.getBanReason())
                    .bannedAt(profile.getBannedAt())
                    .bannedBy(profile.getBannedBy())
                    .createdAt(profile.getCreatedAt())
                    .updatedAt(profile.getUpdatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserProfileSummaryDto {
        private UUID id;
        private String externalId;
        private String username;
        private String displayName;
        private String avatar;
        private UserStatus status;
        private Instant lastSeen;
        private boolean isVerified;

        public static UserProfileSummaryDto from(UserProfile profile) {
            if (profile == null) return null;
            return UserProfileSummaryDto.builder()
                    .id(profile.getId())
                    .externalId(profile.getAuthUser() != null ? profile.getAuthUser().getExternalId() : null)
                    .username(profile.getUsername())
                    .displayName(profile.getDisplayName())
                    .avatar(profile.getAvatar())
                    .status(profile.getStatus())
                    .lastSeen(profile.getLastSeen())
                    .isVerified(profile.isVerified())
                    .build();
        }
    }

    // ==================== Status DTOs ====================

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateStatusRequest {
        @NotNull(message = "Status is required")
        private UserStatus status;
    }

    // ==================== Settings DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateSettingsRequest {
        // Appearance
        private Boolean darkMode;

        // Media & Storage
        private Boolean autoDownloadMedia;
        private Boolean saveToGallery;

        // Notifications
        private Boolean pushNotifications;
        private Boolean messageNotifications;
        private Boolean groupNotifications;
        private Boolean callNotifications;
        private Boolean soundEnabled;
        private Boolean vibrationEnabled;
        private Boolean showPreview;
        private Boolean inAppNotifications;
        private Boolean notificationLight;

        // Privacy
        private Boolean readReceipts;
        private Boolean lastSeenVisible;
        private VisibilityLevel profilePhotoVisibility;
        private VisibilityLevel statusVisibility;

        // Security
        private Boolean fingerprintLock;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserSettingsDto {
        private UUID userId;
        private boolean darkMode;
        private boolean autoDownloadMedia;
        private boolean saveToGallery;
        private boolean pushNotifications;
        private boolean messageNotifications;
        private boolean groupNotifications;
        private boolean callNotifications;
        private boolean soundEnabled;
        private boolean vibrationEnabled;
        private boolean showPreview;
        private boolean inAppNotifications;
        private boolean notificationLight;
        private boolean readReceipts;
        private boolean lastSeenVisible;
        private VisibilityLevel profilePhotoVisibility;
        private VisibilityLevel statusVisibility;
        private boolean fingerprintLock;
        private Set<UUID> blockedUserIds;
        private Instant createdAt;
        private Instant updatedAt;

        public static UserSettingsDto from(UserSettings settings) {
            if (settings == null) return null;
            return UserSettingsDto.builder()
                    .userId(settings.getId())
                    .darkMode(settings.isDarkMode())
                    .autoDownloadMedia(settings.isAutoDownloadMedia())
                    .saveToGallery(settings.isSaveToGallery())
                    .pushNotifications(settings.isPushNotifications())
                    .messageNotifications(settings.isMessageNotifications())
                    .groupNotifications(settings.isGroupNotifications())
                    .callNotifications(settings.isCallNotifications())
                    .soundEnabled(settings.isSoundEnabled())
                    .vibrationEnabled(settings.isVibrationEnabled())
                    .showPreview(settings.isShowPreview())
                    .inAppNotifications(settings.isInAppNotifications())
                    .notificationLight(settings.isNotificationLight())
                    .readReceipts(settings.isReadReceipts())
                    .lastSeenVisible(settings.isLastSeenVisible())
                    .profilePhotoVisibility(settings.getProfilePhotoVisibility())
                    .statusVisibility(settings.getStatusVisibility())
                    .fingerprintLock(settings.isFingerprintLock())
                    .blockedUserIds(settings.getBlockedUserIds())
                    .createdAt(settings.getCreatedAt())
                    .updatedAt(settings.getUpdatedAt())
                    .build();
        }
    }

    // ==================== Block User DTOs ====================

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BlockUserRequest {
        @NotNull(message = "User ID is required")
        private UUID userId;
    }

    // ==================== Device DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LinkDeviceRequest {
        @NotBlank(message = "Device ID is required")
        private String deviceId;

        @Size(max = 255, message = "Device name cannot exceed 255 characters")
        private String deviceName;

        private DeviceType deviceType;

        private String fcmToken;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateFcmTokenRequest {
        private String fcmToken;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LinkedDeviceDto {
        private UUID id;
        private String deviceId;
        private String deviceName;
        private DeviceType deviceType;
        private boolean hasFcmToken;
        private Instant lastActive;
        private Instant linkedAt;

        public static LinkedDeviceDto from(LinkedDevice device) {
            if (device == null) return null;
            return LinkedDeviceDto.builder()
                    .id(device.getId())
                    .deviceId(device.getDeviceId())
                    .deviceName(device.getDeviceName())
                    .deviceType(device.getDeviceType())
                    .hasFcmToken(device.hasFcmToken())
                    .lastActive(device.getLastActive())
                    .linkedAt(device.getLinkedAt())
                    .build();
        }
    }

    // ==================== Admin DTOs ====================

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BanUserRequest {
        @NotNull(message = "User ID is required")
        private UUID userId;

        @Size(max = 500, message = "Ban reason cannot exceed 500 characters")
        private String reason;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateRoleRequest {
        @NotNull(message = "User ID is required")
        private UUID userId;

        @NotNull(message = "Role is required")
        private UserRole role;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdatePermissionsRequest {
        @NotNull(message = "User ID is required")
        private UUID userId;

        @NotNull(message = "Permissions are required")
        private Set<String> permissions;
    }

    // ==================== Migration DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MigratedUserRequest {
        private String externalId;
        private String phoneNumber;
        private String username;
        private String displayName;
        private String email;
        private String passwordHash;
        private String avatar;
        private String bio;
        private String publicKey;
        private String status;
        private Instant lastSeen;
        private boolean isActive;
        private boolean isVerified;
        private String role;
        private Set<String> permissions;
        private boolean isBanned;
        private String banReason;
        private Instant bannedAt;
        private String bannedBy;
        private List<MigratedOAuthProvider> oauthProviders;
        private List<MigratedLinkedDevice> linkedDevices;
        private List<String> legacyFcmTokens;
        private boolean twoFactorEnabled;
        private String twoFactorSecret;
        private Set<String> backupCodes;
        private Instant createdAt;
        private Instant updatedAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MigratedOAuthProvider {
        private String provider;
        private String providerId;
        private String email;
        private Instant linkedAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MigratedLinkedDevice {
        private String deviceId;
        private String deviceName;
        private String deviceType;
        private String fcmToken;
        private Instant lastActive;
        private Instant linkedAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MigratedSettingsRequest {
        private String externalId;
        private boolean darkMode;
        private boolean autoDownloadMedia;
        private boolean saveToGallery;
        private boolean pushNotifications;
        private boolean messageNotifications;
        private boolean groupNotifications;
        private boolean callNotifications;
        private boolean soundEnabled;
        private boolean vibrationEnabled;
        private boolean showPreview;
        private boolean inAppNotifications;
        private boolean notificationLight;
        private boolean readReceipts;
        private boolean lastSeenVisible;
        private String profilePhotoVisibility;
        private String statusVisibility;
        private boolean fingerprintLock;
        private List<String> blockedUserExternalIds;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MigrationResult {
        private int total;
        private int successful;
        private int failed;
        private List<MigrationError> errors;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MigrationError {
        private String externalId;
        private String error;
    }

    // ==================== FCM Token DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FcmTokensResponse {
        private UUID userId;
        private List<String> fcmTokens;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BatchFcmTokensRequest {
        @NotNull
        private List<UUID> userIds;
    }

    // ==================== Statistics DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserStatisticsDto {
        private long totalUsers;
        private long activeUsers;
        private long onlineUsers;
        private long bannedUsers;
        private java.util.Map<String, Long> usersByRole;
    }
}
