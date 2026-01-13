package com.quckchat.auth.service;

import com.quckchat.auth.domain.entity.*;
import com.quckchat.auth.domain.repository.*;
import com.quckchat.auth.dto.UserProfileDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for migrating users from MongoDB to PostgreSQL
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class MigrationService {

    private final UserProfileRepository profileRepository;
    private final UserSettingsRepository settingsRepository;
    private final LinkedDeviceRepository deviceRepository;

    // We need to inject AuthUserRepository to create auth users
    // For now, we'll assume AuthUser is created by AuthService during registration

    /**
     * Import a batch of users from MongoDB migration
     */
    public MigrationResult importUsersBatch(List<MigratedUserRequest> users, AuthUserRepository authUserRepository) {
        int successful = 0;
        int failed = 0;
        List<MigrationError> errors = new ArrayList<>();

        for (MigratedUserRequest user : users) {
            try {
                importUser(user, authUserRepository);
                successful++;
            } catch (Exception e) {
                failed++;
                errors.add(MigrationError.builder()
                        .externalId(user.getExternalId())
                        .error(e.getMessage())
                        .build());
                log.error("Failed to import user {}: {}", user.getExternalId(), e.getMessage());
            }
        }

        return MigrationResult.builder()
                .total(users.size())
                .successful(successful)
                .failed(failed)
                .errors(errors)
                .build();
    }

    /**
     * Import a single user with all related data
     */
    private void importUser(MigratedUserRequest request, AuthUserRepository authUserRepository) {
        log.debug("Importing user: {}", request.getExternalId());

        // Create AuthUser first
        AuthUser authUser = AuthUser.builder()
                .email(request.getEmail() != null ? request.getEmail() : request.getPhoneNumber() + "@placeholder.local")
                .passwordHash(request.getPasswordHash())
                .externalId(request.getExternalId())
                .status(AuthUser.AuthStatus.ACTIVE)
                .twoFactorEnabled(request.isTwoFactorEnabled())
                .twoFactorSecret(request.getTwoFactorSecret())
                .backupCodes(request.getBackupCodes() != null ? request.getBackupCodes() : new HashSet<>())
                .build();

        authUser = authUserRepository.save(authUser);

        // Create UserProfile
        UserProfile profile = UserProfile.builder()
                .authUser(authUser)
                .phoneNumber(request.getPhoneNumber())
                .username(request.getUsername())
                .displayName(request.getDisplayName())
                .email(request.getEmail())
                .avatar(request.getAvatar())
                .bio(request.getBio())
                .publicKey(request.getPublicKey())
                .status(UserStatus.fromString(request.getStatus()))
                .lastSeen(request.getLastSeen())
                .isActive(request.isActive())
                .isVerified(request.isVerified())
                .role(UserRole.fromString(request.getRole()))
                .permissions(request.getPermissions() != null ? request.getPermissions() : new HashSet<>())
                .isBanned(request.isBanned())
                .banReason(request.getBanReason())
                .bannedAt(request.getBannedAt())
                .bannedBy(request.getBannedBy() != null ? UUID.fromString(request.getBannedBy()) : null)
                .createdAt(request.getCreatedAt())
                .updatedAt(request.getUpdatedAt())
                .build();

        profile = profileRepository.save(profile);

        // Create default UserSettings (will be updated by settings migration)
        UserSettings settings = UserSettings.createDefault(profile);
        settingsRepository.save(settings);

        // Import linked devices
        if (request.getLinkedDevices() != null) {
            for (MigratedLinkedDevice deviceData : request.getLinkedDevices()) {
                LinkedDevice device = LinkedDevice.builder()
                        .userProfile(profile)
                        .deviceId(deviceData.getDeviceId())
                        .deviceName(deviceData.getDeviceName())
                        .deviceType(DeviceType.fromString(deviceData.getDeviceType()))
                        .fcmToken(deviceData.getFcmToken())
                        .lastActive(deviceData.getLastActive())
                        .linkedAt(deviceData.getLinkedAt())
                        .build();
                deviceRepository.save(device);
            }
        }

        // Import legacy FCM tokens (tokens not associated with devices)
        if (request.getLegacyFcmTokens() != null && !request.getLegacyFcmTokens().isEmpty()) {
            int tokenIndex = 0;
            for (String token : request.getLegacyFcmTokens()) {
                LinkedDevice device = LinkedDevice.builder()
                        .userProfile(profile)
                        .deviceId("legacy_" + request.getExternalId() + "_" + tokenIndex++)
                        .deviceName("Legacy Device")
                        .deviceType(DeviceType.MOBILE)
                        .fcmToken(token)
                        .lastActive(Instant.now())
                        .build();
                deviceRepository.save(device);
            }
        }

        // Import OAuth connections
        if (request.getOauthProviders() != null) {
            for (MigratedOAuthProvider oauth : request.getOauthProviders()) {
                OAuthConnection connection = OAuthConnection.builder()
                        .user(authUser)
                        .provider(OAuthProvider.valueOf(oauth.getProvider().toUpperCase()))
                        .providerUserId(oauth.getProviderId())
                        .createdAt(oauth.getLinkedAt())
                        .build();
                authUser.getOauthConnections().add(connection);
            }
            authUserRepository.save(authUser);
        }

        log.debug("Successfully imported user: {}", request.getExternalId());
    }

    /**
     * Import user settings batch
     */
    public MigrationResult importSettingsBatch(List<MigratedSettingsRequest> settingsList) {
        int successful = 0;
        int failed = 0;
        List<MigrationError> errors = new ArrayList<>();

        for (MigratedSettingsRequest settingsData : settingsList) {
            try {
                importSettings(settingsData);
                successful++;
            } catch (Exception e) {
                failed++;
                errors.add(MigrationError.builder()
                        .externalId(settingsData.getExternalId())
                        .error(e.getMessage())
                        .build());
                log.error("Failed to import settings for {}: {}", settingsData.getExternalId(), e.getMessage());
            }
        }

        return MigrationResult.builder()
                .total(settingsList.size())
                .successful(successful)
                .failed(failed)
                .errors(errors)
                .build();
    }

    /**
     * Import settings for a single user
     */
    private void importSettings(MigratedSettingsRequest request) {
        // Find user by external ID
        UserProfile profile = profileRepository.findByExternalId(request.getExternalId())
                .orElseThrow(() -> new RuntimeException("Profile not found for external ID: " + request.getExternalId()));

        UserSettings settings = settingsRepository.findById(profile.getId())
                .orElseThrow(() -> new RuntimeException("Settings not found for user: " + profile.getId()));

        // Update settings
        settings.setDarkMode(request.isDarkMode());
        settings.setAutoDownloadMedia(request.isAutoDownloadMedia());
        settings.setSaveToGallery(request.isSaveToGallery());
        settings.setPushNotifications(request.isPushNotifications());
        settings.setMessageNotifications(request.isMessageNotifications());
        settings.setGroupNotifications(request.isGroupNotifications());
        settings.setCallNotifications(request.isCallNotifications());
        settings.setSoundEnabled(request.isSoundEnabled());
        settings.setVibrationEnabled(request.isVibrationEnabled());
        settings.setShowPreview(request.isShowPreview());
        settings.setInAppNotifications(request.isInAppNotifications());
        settings.setNotificationLight(request.isNotificationLight());
        settings.setReadReceipts(request.isReadReceipts());
        settings.setLastSeenVisible(request.isLastSeenVisible());
        settings.setProfilePhotoVisibility(VisibilityLevel.fromString(request.getProfilePhotoVisibility()));
        settings.setStatusVisibility(VisibilityLevel.fromString(request.getStatusVisibility()));
        settings.setFingerprintLock(request.isFingerprintLock());

        // Convert blocked user external IDs to UUIDs
        if (request.getBlockedUserExternalIds() != null && !request.getBlockedUserExternalIds().isEmpty()) {
            Set<UUID> blockedUserIds = new HashSet<>();
            for (String externalId : request.getBlockedUserExternalIds()) {
                profileRepository.findByExternalId(externalId)
                        .ifPresent(p -> blockedUserIds.add(p.getId()));
            }
            settings.setBlockedUserIds(blockedUserIds);
        }

        settingsRepository.save(settings);
    }

    /**
     * Validate migrated users against expected data
     */
    @Transactional(readOnly = true)
    public Map<String, Object> validateMigration(List<String> sampleExternalIds) {
        Map<String, Object> result = new HashMap<>();

        int found = 0;
        int notFound = 0;
        List<String> missing = new ArrayList<>();

        for (String externalId : sampleExternalIds) {
            if (profileRepository.findByExternalId(externalId).isPresent()) {
                found++;
            } else {
                notFound++;
                missing.add(externalId);
            }
        }

        result.put("totalChecked", sampleExternalIds.size());
        result.put("found", found);
        result.put("notFound", notFound);
        result.put("missingExternalIds", missing);
        result.put("successRate", sampleExternalIds.isEmpty() ? 100.0 : (found * 100.0 / sampleExternalIds.size()));

        return result;
    }

    /**
     * Get migration status/statistics
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getMigrationStatus() {
        Map<String, Object> status = new HashMap<>();

        status.put("totalProfiles", profileRepository.count());
        status.put("totalSettings", settingsRepository.count());
        status.put("totalDevices", deviceRepository.count());

        return status;
    }
}

// Interface reference (should exist in domain/repository)
interface AuthUserRepository extends org.springframework.data.jpa.repository.JpaRepository<AuthUser, UUID> {
}
