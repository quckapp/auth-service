package com.quckapp.auth.kafka;

import com.quckapp.auth.domain.entity.*;

import java.util.UUID;

/**
 * Interface for user event publishing operations.
 * Extracted for testability with Java 25+ Mockito compatibility.
 */
public interface UserEventOperations {

    // ==================== Auth Events ====================

    void publishUserRegistered(AuthUser user);

    void publishPasswordResetRequested(AuthUser user, String resetToken);

    void publishPasswordChanged(AuthUser user);

    // ==================== Profile Events ====================

    void publishProfileCreated(UserProfile profile);

    void publishProfileUpdated(UserProfile profile);

    void publishProfileDeleted(UserProfile profile);

    // ==================== Status Events ====================

    void publishStatusChanged(UUID userId, UserStatus status);

    // ==================== Moderation Events ====================

    void publishUserBanned(UserProfile profile, UUID bannedBy, String reason);

    void publishUserUnbanned(UUID userId);

    void publishRoleChanged(UUID userId, UserRole role);

    // ==================== Device Events ====================

    void publishDeviceLinked(UUID userId, LinkedDevice device);

    void publishDeviceUnlinked(UUID userId, String deviceId);

    // ==================== Settings Events ====================

    void publishSettingsUpdated(UUID userId);
}
