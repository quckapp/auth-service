package com.quckchat.auth.kafka;

import com.quckchat.auth.domain.entity.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Kafka event publisher for user profile events
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${spring.kafka.enabled:true}")
    private boolean kafkaEnabled;

    // Topic names
    private static final String TOPIC_PROFILE_CREATED = "user.profile.created";
    private static final String TOPIC_PROFILE_UPDATED = "user.profile.updated";
    private static final String TOPIC_PROFILE_DELETED = "user.profile.deleted";
    private static final String TOPIC_STATUS_CHANGED = "user.status.changed";
    private static final String TOPIC_USER_BANNED = "user.banned";
    private static final String TOPIC_USER_UNBANNED = "user.unbanned";
    private static final String TOPIC_ROLE_CHANGED = "user.role.changed";
    private static final String TOPIC_DEVICE_LINKED = "user.device.linked";
    private static final String TOPIC_DEVICE_UNLINKED = "user.device.unlinked";
    private static final String TOPIC_SETTINGS_UPDATED = "user.settings.updated";

    // ==================== Profile Events ====================

    public void publishProfileCreated(UserProfile profile) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "PROFILE_CREATED");
        event.put("userId", profile.getId().toString());
        event.put("externalId", profile.getAuthUser() != null ? profile.getAuthUser().getExternalId() : null);
        event.put("username", profile.getUsername());
        event.put("displayName", profile.getDisplayName());
        event.put("phoneNumber", profile.getPhoneNumber());
        event.put("email", profile.getEmail());
        event.put("avatar", profile.getAvatar());
        event.put("createdAt", Instant.now().toString());

        publish(TOPIC_PROFILE_CREATED, profile.getId().toString(), event);
    }

    public void publishProfileUpdated(UserProfile profile) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "PROFILE_UPDATED");
        event.put("userId", profile.getId().toString());
        event.put("externalId", profile.getAuthUser() != null ? profile.getAuthUser().getExternalId() : null);
        event.put("username", profile.getUsername());
        event.put("displayName", profile.getDisplayName());
        event.put("email", profile.getEmail());
        event.put("avatar", profile.getAvatar());
        event.put("bio", profile.getBio());
        event.put("updatedAt", Instant.now().toString());

        publish(TOPIC_PROFILE_UPDATED, profile.getId().toString(), event);
    }

    public void publishProfileDeleted(UserProfile profile) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "PROFILE_DELETED");
        event.put("userId", profile.getId().toString());
        event.put("externalId", profile.getAuthUser() != null ? profile.getAuthUser().getExternalId() : null);
        event.put("deletedAt", Instant.now().toString());

        publish(TOPIC_PROFILE_DELETED, profile.getId().toString(), event);
    }

    // ==================== Status Events ====================

    public void publishStatusChanged(UUID userId, UserStatus status) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "STATUS_CHANGED");
        event.put("userId", userId.toString());
        event.put("status", status.name());
        event.put("changedAt", Instant.now().toString());

        publish(TOPIC_STATUS_CHANGED, userId.toString(), event);
    }

    // ==================== Moderation Events ====================

    public void publishUserBanned(UserProfile profile, UUID bannedBy, String reason) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "USER_BANNED");
        event.put("userId", profile.getId().toString());
        event.put("externalId", profile.getAuthUser() != null ? profile.getAuthUser().getExternalId() : null);
        event.put("bannedBy", bannedBy.toString());
        event.put("reason", reason);
        event.put("bannedAt", Instant.now().toString());

        publish(TOPIC_USER_BANNED, profile.getId().toString(), event);
    }

    public void publishUserUnbanned(UUID userId) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "USER_UNBANNED");
        event.put("userId", userId.toString());
        event.put("unbannedAt", Instant.now().toString());

        publish(TOPIC_USER_UNBANNED, userId.toString(), event);
    }

    public void publishRoleChanged(UUID userId, UserRole role) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "ROLE_CHANGED");
        event.put("userId", userId.toString());
        event.put("newRole", role.name());
        event.put("changedAt", Instant.now().toString());

        publish(TOPIC_ROLE_CHANGED, userId.toString(), event);
    }

    // ==================== Device Events ====================

    public void publishDeviceLinked(UUID userId, LinkedDevice device) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "DEVICE_LINKED");
        event.put("userId", userId.toString());
        event.put("deviceId", device.getDeviceId());
        event.put("deviceName", device.getDeviceName());
        event.put("deviceType", device.getDeviceType().name());
        event.put("hasFcmToken", device.hasFcmToken());
        event.put("linkedAt", Instant.now().toString());

        publish(TOPIC_DEVICE_LINKED, userId.toString(), event);
    }

    public void publishDeviceUnlinked(UUID userId, String deviceId) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "DEVICE_UNLINKED");
        event.put("userId", userId.toString());
        event.put("deviceId", deviceId);
        event.put("unlinkedAt", Instant.now().toString());

        publish(TOPIC_DEVICE_UNLINKED, userId.toString(), event);
    }

    // ==================== Settings Events ====================

    public void publishSettingsUpdated(UUID userId) {
        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "SETTINGS_UPDATED");
        event.put("userId", userId.toString());
        event.put("updatedAt", Instant.now().toString());

        publish(TOPIC_SETTINGS_UPDATED, userId.toString(), event);
    }

    // ==================== Helper Methods ====================

    private void publish(String topic, String key, Object message) {
        if (!kafkaEnabled) {
            log.debug("Kafka disabled, skipping event: {} -> {}", topic, message);
            return;
        }

        try {
            kafkaTemplate.send(topic, key, message)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish event to {}: {}", topic, ex.getMessage());
                        } else {
                            log.debug("Published event to {}: partition={}, offset={}",
                                    topic,
                                    result.getRecordMetadata().partition(),
                                    result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception e) {
            log.error("Error publishing event to {}: {}", topic, e.getMessage(), e);
        }
    }
}
