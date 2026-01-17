package com.quckapp.auth.kafka;

import com.quckapp.auth.domain.entity.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserEventPublisher
 */
@ExtendWith(MockitoExtension.class)
class UserEventPublisherTest {

    @Mock
    private KafkaTemplate<String, Object> kafkaTemplate;

    private UserEventPublisher userEventPublisher;

    private UUID testUserId;
    private AuthUser testAuthUser;
    private UserProfile testUserProfile;
    private LinkedDevice testDevice;

    @BeforeEach
    void setUp() {
        userEventPublisher = new UserEventPublisher(kafkaTemplate);
        ReflectionTestUtils.setField(userEventPublisher, "kafkaEnabled", true);

        testUserId = UUID.randomUUID();

        testAuthUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .build();

        testUserProfile = UserProfile.builder()
                .id(testUserId)
                .authUser(testAuthUser)
                .username("testuser")
                .displayName("Test User")
                .email("test@example.com")
                .phoneNumber("+1234567890")
                .avatar("https://example.com/avatar.jpg")
                .bio("Test bio")
                .build();

        testDevice = LinkedDevice.builder()
                .id(UUID.randomUUID())
                .deviceId("device-123")
                .deviceName("Test Device")
                .deviceType(DeviceType.MOBILE)
                .fcmToken("fcm-token-123")
                .build();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void mockKafkaSendSuccess() {
        CompletableFuture future = new CompletableFuture();
        future.complete(null);
        given(kafkaTemplate.send(anyString(), anyString(), any())).willReturn(future);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void mockKafkaSendFailure() {
        CompletableFuture future = new CompletableFuture();
        future.completeExceptionally(new RuntimeException("Kafka send failed"));
        given(kafkaTemplate.send(anyString(), anyString(), any())).willReturn(future);
    }

    @Nested
    @DisplayName("Auth Events Tests")
    class AuthEventsTests {

        @Test
        @DisplayName("should publish user registered event")
        void shouldPublishUserRegisteredEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishUserRegistered(testAuthUser);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), keyCaptor.capture(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.registered");
            assertThat(keyCaptor.getValue()).isEqualTo(testUserId.toString());

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("USER_REGISTERED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("email")).isEqualTo("test@example.com");
            assertThat(event.get("externalId")).isEqualTo("ext-123");
            assertThat(event.get("registeredAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish password reset requested event")
        void shouldPublishPasswordResetRequestedEvent() {
            mockKafkaSendSuccess();
            String resetToken = "reset-token-123";

            userEventPublisher.publishPasswordResetRequested(testAuthUser, resetToken);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.password.reset.requested");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("PASSWORD_RESET_REQUESTED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("email")).isEqualTo("test@example.com");
            assertThat(event.get("resetToken")).isEqualTo(resetToken);
            assertThat(event.get("requestedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish password changed event")
        void shouldPublishPasswordChangedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishPasswordChanged(testAuthUser);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.password.changed");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("PASSWORD_CHANGED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("changedAt")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Profile Events Tests")
    class ProfileEventsTests {

        @Test
        @DisplayName("should publish profile created event")
        void shouldPublishProfileCreatedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishProfileCreated(testUserProfile);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.profile.created");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("PROFILE_CREATED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("externalId")).isEqualTo("ext-123");
            assertThat(event.get("username")).isEqualTo("testuser");
            assertThat(event.get("displayName")).isEqualTo("Test User");
            assertThat(event.get("email")).isEqualTo("test@example.com");
            assertThat(event.get("phoneNumber")).isEqualTo("+1234567890");
            assertThat(event.get("avatar")).isEqualTo("https://example.com/avatar.jpg");
            assertThat(event.get("createdAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish profile created event without auth user")
        void shouldPublishProfileCreatedEventWithoutAuthUser() {
            mockKafkaSendSuccess();

            UserProfile profileWithoutAuth = UserProfile.builder()
                    .id(testUserId)
                    .username("orphan")
                    .displayName("Orphan User")
                    .email("orphan@example.com")
                    .build();

            userEventPublisher.publishProfileCreated(profileWithoutAuth);

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);
            verify(kafkaTemplate).send(anyString(), anyString(), messageCaptor.capture());

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("externalId")).isNull();
        }

        @Test
        @DisplayName("should publish profile updated event")
        void shouldPublishProfileUpdatedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishProfileUpdated(testUserProfile);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.profile.updated");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("PROFILE_UPDATED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("bio")).isEqualTo("Test bio");
            assertThat(event.get("updatedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish profile deleted event")
        void shouldPublishProfileDeletedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishProfileDeleted(testUserProfile);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.profile.deleted");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("PROFILE_DELETED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("deletedAt")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Status Events Tests")
    class StatusEventsTests {

        @Test
        @DisplayName("should publish status changed event")
        void shouldPublishStatusChangedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishStatusChanged(testUserId, UserStatus.ONLINE);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.status.changed");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("STATUS_CHANGED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("status")).isEqualTo("ONLINE");
            assertThat(event.get("changedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish away status")
        void shouldPublishAwayStatus() {
            mockKafkaSendSuccess();

            userEventPublisher.publishStatusChanged(testUserId, UserStatus.AWAY);

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);
            verify(kafkaTemplate).send(anyString(), anyString(), messageCaptor.capture());

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("status")).isEqualTo("AWAY");
        }
    }

    @Nested
    @DisplayName("Moderation Events Tests")
    class ModerationEventsTests {

        @Test
        @DisplayName("should publish user banned event")
        void shouldPublishUserBannedEvent() {
            mockKafkaSendSuccess();
            UUID adminId = UUID.randomUUID();
            String reason = "Violation of terms";

            userEventPublisher.publishUserBanned(testUserProfile, adminId, reason);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.banned");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("USER_BANNED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("bannedBy")).isEqualTo(adminId.toString());
            assertThat(event.get("reason")).isEqualTo(reason);
            assertThat(event.get("bannedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish user unbanned event")
        void shouldPublishUserUnbannedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishUserUnbanned(testUserId);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.unbanned");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("USER_UNBANNED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("unbannedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish role changed event")
        void shouldPublishRoleChangedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishRoleChanged(testUserId, UserRole.ADMIN);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.role.changed");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("ROLE_CHANGED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("newRole")).isEqualTo("ADMIN");
            assertThat(event.get("changedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish role changed to moderator")
        void shouldPublishRoleChangedToModerator() {
            mockKafkaSendSuccess();

            userEventPublisher.publishRoleChanged(testUserId, UserRole.MODERATOR);

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);
            verify(kafkaTemplate).send(anyString(), anyString(), messageCaptor.capture());

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("newRole")).isEqualTo("MODERATOR");
        }
    }

    @Nested
    @DisplayName("Device Events Tests")
    class DeviceEventsTests {

        @Test
        @DisplayName("should publish device linked event")
        void shouldPublishDeviceLinkedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishDeviceLinked(testUserId, testDevice);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.device.linked");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("DEVICE_LINKED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("deviceId")).isEqualTo("device-123");
            assertThat(event.get("deviceName")).isEqualTo("Test Device");
            assertThat(event.get("deviceType")).isEqualTo("MOBILE");
            assertThat(event.get("hasFcmToken")).isEqualTo(true);
            assertThat(event.get("linkedAt")).isNotNull();
        }

        @Test
        @DisplayName("should publish device linked event without FCM token")
        void shouldPublishDeviceLinkedEventWithoutFcmToken() {
            mockKafkaSendSuccess();

            LinkedDevice deviceWithoutFcm = LinkedDevice.builder()
                    .id(UUID.randomUUID())
                    .deviceId("device-no-fcm")
                    .deviceName("Desktop Device")
                    .deviceType(DeviceType.DESKTOP)
                    .build();

            userEventPublisher.publishDeviceLinked(testUserId, deviceWithoutFcm);

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);
            verify(kafkaTemplate).send(anyString(), anyString(), messageCaptor.capture());

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("hasFcmToken")).isEqualTo(false);
            assertThat(event.get("deviceType")).isEqualTo("DESKTOP");
        }

        @Test
        @DisplayName("should publish device unlinked event")
        void shouldPublishDeviceUnlinkedEvent() {
            mockKafkaSendSuccess();
            String deviceId = "device-to-unlink";

            userEventPublisher.publishDeviceUnlinked(testUserId, deviceId);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.device.unlinked");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("DEVICE_UNLINKED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("deviceId")).isEqualTo(deviceId);
            assertThat(event.get("unlinkedAt")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Settings Events Tests")
    class SettingsEventsTests {

        @Test
        @DisplayName("should publish settings updated event")
        void shouldPublishSettingsUpdatedEvent() {
            mockKafkaSendSuccess();

            userEventPublisher.publishSettingsUpdated(testUserId);

            ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> messageCaptor = ArgumentCaptor.forClass(Map.class);

            verify(kafkaTemplate).send(topicCaptor.capture(), anyString(), messageCaptor.capture());

            assertThat(topicCaptor.getValue()).isEqualTo("user.settings.updated");

            Map<String, Object> event = messageCaptor.getValue();
            assertThat(event.get("eventType")).isEqualTo("SETTINGS_UPDATED");
            assertThat(event.get("userId")).isEqualTo(testUserId.toString());
            assertThat(event.get("updatedAt")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Kafka Disabled Tests")
    class KafkaDisabledTests {

        @Test
        @DisplayName("should skip publishing when kafka is disabled")
        void shouldSkipPublishingWhenKafkaDisabled() {
            ReflectionTestUtils.setField(userEventPublisher, "kafkaEnabled", false);

            userEventPublisher.publishUserRegistered(testAuthUser);
            userEventPublisher.publishProfileCreated(testUserProfile);
            userEventPublisher.publishStatusChanged(testUserId, UserStatus.ONLINE);

            verify(kafkaTemplate, never()).send(anyString(), anyString(), any());
        }

        @Test
        @DisplayName("should skip all event types when kafka is disabled")
        void shouldSkipAllEventTypesWhenKafkaDisabled() {
            ReflectionTestUtils.setField(userEventPublisher, "kafkaEnabled", false);

            userEventPublisher.publishPasswordResetRequested(testAuthUser, "token");
            userEventPublisher.publishPasswordChanged(testAuthUser);
            userEventPublisher.publishProfileUpdated(testUserProfile);
            userEventPublisher.publishProfileDeleted(testUserProfile);
            userEventPublisher.publishUserBanned(testUserProfile, UUID.randomUUID(), "reason");
            userEventPublisher.publishUserUnbanned(testUserId);
            userEventPublisher.publishRoleChanged(testUserId, UserRole.USER);
            userEventPublisher.publishDeviceLinked(testUserId, testDevice);
            userEventPublisher.publishDeviceUnlinked(testUserId, "device-id");
            userEventPublisher.publishSettingsUpdated(testUserId);

            verify(kafkaTemplate, never()).send(anyString(), anyString(), any());
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("should handle kafka send failure gracefully")
        void shouldHandleKafkaSendFailureGracefully() {
            mockKafkaSendFailure();

            // Should not throw exception
            assertThatCode(() -> userEventPublisher.publishUserRegistered(testAuthUser))
                    .doesNotThrowAnyException();

            verify(kafkaTemplate).send(anyString(), anyString(), any());
        }

        @Test
        @DisplayName("should handle kafka template exception gracefully")
        void shouldHandleKafkaTemplateExceptionGracefully() {
            given(kafkaTemplate.send(anyString(), anyString(), any()))
                    .willThrow(new RuntimeException("Kafka unavailable"));

            // Should not throw exception
            assertThatCode(() -> userEventPublisher.publishProfileCreated(testUserProfile))
                    .doesNotThrowAnyException();

            verify(kafkaTemplate).send(anyString(), anyString(), any());
        }

        @Test
        @DisplayName("should handle multiple failures gracefully")
        void shouldHandleMultipleFailuresGracefully() {
            given(kafkaTemplate.send(anyString(), anyString(), any()))
                    .willThrow(new RuntimeException("Connection refused"));

            assertThatCode(() -> {
                userEventPublisher.publishUserRegistered(testAuthUser);
                userEventPublisher.publishProfileCreated(testUserProfile);
                userEventPublisher.publishStatusChanged(testUserId, UserStatus.OFFLINE);
            }).doesNotThrowAnyException();

            verify(kafkaTemplate, times(3)).send(anyString(), anyString(), any());
        }
    }

    @Nested
    @DisplayName("Message Key Tests")
    class MessageKeyTests {

        @Test
        @DisplayName("should use userId as message key for all events")
        void shouldUseUserIdAsMessageKey() {
            mockKafkaSendSuccess();

            userEventPublisher.publishUserRegistered(testAuthUser);
            userEventPublisher.publishProfileCreated(testUserProfile);
            userEventPublisher.publishStatusChanged(testUserId, UserStatus.ONLINE);

            ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
            verify(kafkaTemplate, times(3)).send(anyString(), keyCaptor.capture(), any());

            assertThat(keyCaptor.getAllValues())
                    .containsOnly(testUserId.toString());
        }
    }
}
