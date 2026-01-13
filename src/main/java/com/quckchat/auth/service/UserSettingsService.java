package com.quckchat.auth.service;

import com.quckchat.auth.domain.entity.UserProfile;
import com.quckchat.auth.domain.entity.UserSettings;
import com.quckchat.auth.domain.repository.UserProfileRepository;
import com.quckchat.auth.domain.repository.UserSettingsRepository;
import com.quckchat.auth.dto.UserProfileDtos.*;
import com.quckchat.auth.kafka.UserEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for user settings management operations
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserSettingsService {

    private final UserSettingsRepository settingsRepository;
    private final UserProfileRepository profileRepository;
    private final UserEventPublisher eventPublisher;

    // ==================== Settings CRUD ====================

    @Transactional(readOnly = true)
    public UserSettingsDto getSettings(UUID userId) {
        UserSettings settings = findSettingsOrThrow(userId);
        return UserSettingsDto.from(settings);
    }

    public UserSettingsDto updateSettings(UUID userId, UpdateSettingsRequest request) {
        log.info("Updating settings for user: {}", userId);
        UserSettings settings = findSettingsOrThrow(userId);

        // Update appearance
        if (request.getDarkMode() != null) {
            settings.setDarkMode(request.getDarkMode());
        }

        // Update media settings
        if (request.getAutoDownloadMedia() != null) {
            settings.setAutoDownloadMedia(request.getAutoDownloadMedia());
        }
        if (request.getSaveToGallery() != null) {
            settings.setSaveToGallery(request.getSaveToGallery());
        }

        // Update notification settings
        if (request.getPushNotifications() != null) {
            settings.setPushNotifications(request.getPushNotifications());
        }
        if (request.getMessageNotifications() != null) {
            settings.setMessageNotifications(request.getMessageNotifications());
        }
        if (request.getGroupNotifications() != null) {
            settings.setGroupNotifications(request.getGroupNotifications());
        }
        if (request.getCallNotifications() != null) {
            settings.setCallNotifications(request.getCallNotifications());
        }
        if (request.getSoundEnabled() != null) {
            settings.setSoundEnabled(request.getSoundEnabled());
        }
        if (request.getVibrationEnabled() != null) {
            settings.setVibrationEnabled(request.getVibrationEnabled());
        }
        if (request.getShowPreview() != null) {
            settings.setShowPreview(request.getShowPreview());
        }
        if (request.getInAppNotifications() != null) {
            settings.setInAppNotifications(request.getInAppNotifications());
        }
        if (request.getNotificationLight() != null) {
            settings.setNotificationLight(request.getNotificationLight());
        }

        // Update privacy settings
        if (request.getReadReceipts() != null) {
            settings.setReadReceipts(request.getReadReceipts());
        }
        if (request.getLastSeenVisible() != null) {
            settings.setLastSeenVisible(request.getLastSeenVisible());
        }
        if (request.getProfilePhotoVisibility() != null) {
            settings.setProfilePhotoVisibility(request.getProfilePhotoVisibility());
        }
        if (request.getStatusVisibility() != null) {
            settings.setStatusVisibility(request.getStatusVisibility());
        }

        // Update security settings
        if (request.getFingerprintLock() != null) {
            settings.setFingerprintLock(request.getFingerprintLock());
        }

        settings = settingsRepository.save(settings);

        // Publish event
        eventPublisher.publishSettingsUpdated(userId);

        log.info("Settings updated successfully for user: {}", userId);
        return UserSettingsDto.from(settings);
    }

    public UserSettingsDto createDefaultSettings(UUID userId) {
        log.info("Creating default settings for user: {}", userId);

        UserProfile profile = profileRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found: " + userId));

        UserSettings settings = UserSettings.createDefault(profile);
        settings = settingsRepository.save(settings);

        log.info("Default settings created for user: {}", userId);
        return UserSettingsDto.from(settings);
    }

    // ==================== Blocked Users ====================

    public void blockUser(UUID userId, UUID userToBlock) {
        log.info("User {} blocking user {}", userId, userToBlock);

        if (userId.equals(userToBlock)) {
            throw new RuntimeException("Cannot block yourself");
        }

        UserSettings settings = findSettingsOrThrow(userId);
        settings.blockUser(userToBlock);
        settingsRepository.save(settings);

        log.info("User {} blocked user {} successfully", userId, userToBlock);
    }

    public void unblockUser(UUID userId, UUID userToUnblock) {
        log.info("User {} unblocking user {}", userId, userToUnblock);

        UserSettings settings = findSettingsOrThrow(userId);
        settings.unblockUser(userToUnblock);
        settingsRepository.save(settings);

        log.info("User {} unblocked user {} successfully", userId, userToUnblock);
    }

    @Transactional(readOnly = true)
    public Set<UUID> getBlockedUserIds(UUID userId) {
        return settingsRepository.findBlockedUserIds(userId);
    }

    @Transactional(readOnly = true)
    public List<UserProfileSummaryDto> getBlockedUsers(UUID userId) {
        Set<UUID> blockedIds = getBlockedUserIds(userId);
        if (blockedIds == null || blockedIds.isEmpty()) {
            return List.of();
        }

        return profileRepository.findByIdIn(blockedIds.stream().toList()).stream()
                .map(UserProfileSummaryDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public boolean isBlocked(UUID userId, UUID targetUserId) {
        return settingsRepository.isUserBlocked(userId, targetUserId);
    }

    @Transactional(readOnly = true)
    public boolean areUsersBlocked(UUID userId1, UUID userId2) {
        return settingsRepository.areUsersBlocked(userId1, userId2);
    }

    // ==================== Privacy Queries ====================

    @Transactional(readOnly = true)
    public boolean areReadReceiptsEnabled(UUID userId) {
        Boolean enabled = settingsRepository.getReadReceiptsEnabled(userId);
        return enabled != null && enabled;
    }

    @Transactional(readOnly = true)
    public boolean isLastSeenVisible(UUID userId) {
        Boolean visible = settingsRepository.getLastSeenVisible(userId);
        return visible != null && visible;
    }

    // ==================== Helper Methods ====================

    private UserSettings findSettingsOrThrow(UUID userId) {
        return settingsRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Settings not found for user: " + userId));
    }
}
