package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for ActiveSession entity
 */
@DisplayName("ActiveSession Entity Tests")
class ActiveSessionTest {

    private ActiveSession session;

    @BeforeEach
    void setUp() {
        session = ActiveSession.builder()
                .id(UUID.randomUUID())
                .sessionTokenHash("hashed-token-abc123")
                .deviceId("device-123")
                .deviceName("Chrome on Windows")
                .deviceType("DESKTOP")
                .ipAddress("192.168.1.1")
                .isActive(true)
                .expiresAt(Instant.now().plus(24, ChronoUnit.HOURS))
                .activities(new HashSet<>())
                .build();
    }

    @Nested
    @DisplayName("isExpired() Tests")
    class IsExpiredTests {

        @Test
        @DisplayName("should return false when expiration is in the future")
        void shouldReturnFalseWhenExpirationInFuture() {
            session.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

            assertThat(session.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return true when expiration is in the past")
        void shouldReturnTrueWhenExpirationInPast() {
            session.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(session.isExpired()).isTrue();
        }

        @Test
        @DisplayName("should return true when expiration just passed")
        void shouldReturnTrueWhenExpirationJustPassed() {
            session.setExpiresAt(Instant.now().minus(1, ChronoUnit.SECONDS));

            assertThat(session.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("isValid() Tests")
    class IsValidTests {

        @Test
        @DisplayName("should return true when active and not expired")
        void shouldReturnTrueWhenActiveAndNotExpired() {
            session.setActive(true);
            session.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

            assertThat(session.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return false when not active")
        void shouldReturnFalseWhenNotActive() {
            session.setActive(false);
            session.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

            assertThat(session.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when expired")
        void shouldReturnFalseWhenExpired() {
            session.setActive(true);
            session.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(session.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when both inactive and expired")
        void shouldReturnFalseWhenInactiveAndExpired() {
            session.setActive(false);
            session.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(session.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("updateActivity() Tests")
    class UpdateActivityTests {

        @Test
        @DisplayName("should update lastActivityAt timestamp")
        void shouldUpdateLastActivityAtTimestamp() {
            Instant before = Instant.now();

            session.updateActivity();

            assertThat(session.getLastActivityAt()).isNotNull();
            assertThat(session.getLastActivityAt()).isAfterOrEqualTo(before);
        }

        @Test
        @DisplayName("should update lastActivityAt when called multiple times")
        void shouldUpdateLastActivityAtWhenCalledMultipleTimes() throws InterruptedException {
            session.updateActivity();
            Instant first = session.getLastActivityAt();

            Thread.sleep(10);

            session.updateActivity();
            Instant second = session.getLastActivityAt();

            assertThat(second).isAfterOrEqualTo(first);
        }
    }

    @Nested
    @DisplayName("terminate() Tests")
    class TerminateTests {

        @Test
        @DisplayName("should set isActive to false")
        void shouldSetIsActiveToFalse() {
            session.setActive(true);

            session.terminate();

            assertThat(session.isActive()).isFalse();
        }

        @Test
        @DisplayName("should make isValid return false")
        void shouldMakeIsValidReturnFalse() {
            session.setActive(true);
            session.setExpiresAt(Instant.now().plus(24, ChronoUnit.HOURS));
            assertThat(session.isValid()).isTrue();

            session.terminate();

            assertThat(session.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("addActivity() Tests")
    class AddActivityTests {

        @Test
        @DisplayName("should add activity to session")
        void shouldAddActivityToSession() {
            session.addActivity(
                    SessionActivityType.SESSION_CREATED,
                    "192.168.1.1",
                    "Mozilla/5.0",
                    "User logged in"
            );

            assertThat(session.getActivities()).hasSize(1);
            SessionActivity activity = session.getActivities().iterator().next();
            assertThat(activity.getActivityType()).isEqualTo(SessionActivityType.SESSION_CREATED);
            assertThat(activity.getIpAddress()).isEqualTo("192.168.1.1");
            assertThat(activity.getUserAgent()).isEqualTo("Mozilla/5.0");
            assertThat(activity.getDetails()).isEqualTo("User logged in");
            assertThat(activity.getSession()).isEqualTo(session);
        }

        @Test
        @DisplayName("should add multiple activities to session")
        void shouldAddMultipleActivitiesToSession() {
            session.addActivity(SessionActivityType.SESSION_CREATED, "192.168.1.1", "Chrome", "Login");
            session.addActivity(SessionActivityType.SESSION_REFRESHED, "192.168.1.1", "Chrome", "Token refresh");
            session.addActivity(SessionActivityType.SESSION_TERMINATED, "192.168.1.2", "Chrome", "Logout");

            assertThat(session.getActivities()).hasSize(3);
        }

        @Test
        @DisplayName("should handle null details")
        void shouldHandleNullDetails() {
            session.addActivity(
                    SessionActivityType.SESSION_CREATED,
                    "192.168.1.1",
                    "Mozilla/5.0",
                    null
            );

            assertThat(session.getActivities()).hasSize(1);
            SessionActivity activity = session.getActivities().iterator().next();
            assertThat(activity.getDetails()).isNull();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create session with default values")
        void shouldCreateSessionWithDefaultValues() {
            ActiveSession newSession = ActiveSession.builder()
                    .sessionTokenHash("token-hash")
                    .expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                    .build();

            assertThat(newSession.getDeviceType()).isEqualTo("UNKNOWN");
            assertThat(newSession.isActive()).isTrue();
            assertThat(newSession.isTrusted()).isFalse();
            assertThat(newSession.getLastActivityAt()).isNotNull();
            assertThat(newSession.getActivities()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("should create session with all fields")
        void shouldCreateSessionWithAllFields() {
            Instant expiry = Instant.now().plus(7, ChronoUnit.DAYS);

            ActiveSession newSession = ActiveSession.builder()
                    .id(UUID.randomUUID())
                    .sessionTokenHash("token-hash-xyz")
                    .deviceId("device-xyz")
                    .deviceName("iPhone 15")
                    .deviceType("MOBILE")
                    .osName("iOS")
                    .osVersion("17.0")
                    .browserName("Safari")
                    .browserVersion("17.0")
                    .ipAddress("10.0.0.1")
                    .country("United States")
                    .city("San Francisco")
                    .isActive(true)
                    .isTrusted(true)
                    .expiresAt(expiry)
                    .build();

            assertThat(newSession.getDeviceType()).isEqualTo("MOBILE");
            assertThat(newSession.getOsName()).isEqualTo("iOS");
            assertThat(newSession.isTrusted()).isTrue();
            assertThat(newSession.getCountry()).isEqualTo("United States");
            assertThat(newSession.getExpiresAt()).isEqualTo(expiry);
        }
    }

    @Nested
    @DisplayName("SessionActivityType Enum Tests")
    class SessionActivityTypeEnumTests {

        @Test
        @DisplayName("should have all expected activity types")
        void shouldHaveAllExpectedActivityTypes() {
            SessionActivityType[] types = SessionActivityType.values();

            assertThat(types).contains(
                    SessionActivityType.SESSION_CREATED,
                    SessionActivityType.SESSION_TERMINATED,
                    SessionActivityType.SESSION_REFRESHED,
                    SessionActivityType.PASSWORD_CHANGED,
                    SessionActivityType.PROFILE_UPDATED
            );
        }
    }
}
