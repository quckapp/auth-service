package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for UserNotificationPreferences entity
 */
@DisplayName("UserNotificationPreferences Entity Tests")
class UserNotificationPreferencesTest {

    private UserNotificationPreferences preferences;

    @BeforeEach
    void setUp() {
        preferences = UserNotificationPreferences.builder()
                .id(UUID.randomUUID())
                .quietHoursEnabled(false)
                .build();
    }

    @Nested
    @DisplayName("isInQuietHours() Tests")
    class IsInQuietHoursTests {

        @Test
        @DisplayName("should return false when quiet hours is disabled")
        void shouldReturnFalseWhenQuietHoursDisabled() {
            preferences.setQuietHoursEnabled(false);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(23, 0))).isFalse();
        }

        @Test
        @DisplayName("should return false when quiet hours start is null")
        void shouldReturnFalseWhenQuietHoursStartNull() {
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(null);
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(23, 0))).isFalse();
        }

        @Test
        @DisplayName("should return false when quiet hours end is null")
        void shouldReturnFalseWhenQuietHoursEndNull() {
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(null);

            assertThat(preferences.isInQuietHours(LocalTime.of(23, 0))).isFalse();
        }

        @Test
        @DisplayName("should return true when within same-day quiet hours")
        void shouldReturnTrueWhenWithinSameDayQuietHours() {
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(9, 0));
            preferences.setQuietHoursEnd(LocalTime.of(17, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(12, 0))).isTrue();
            assertThat(preferences.isInQuietHours(LocalTime.of(9, 0))).isTrue();
            assertThat(preferences.isInQuietHours(LocalTime.of(16, 59))).isTrue();
        }

        @Test
        @DisplayName("should return false when outside same-day quiet hours")
        void shouldReturnFalseWhenOutsideSameDayQuietHours() {
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(9, 0));
            preferences.setQuietHoursEnd(LocalTime.of(17, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(8, 59))).isFalse();
            assertThat(preferences.isInQuietHours(LocalTime.of(17, 0))).isFalse();
            assertThat(preferences.isInQuietHours(LocalTime.of(20, 0))).isFalse();
        }

        @Test
        @DisplayName("should return true when within overnight quiet hours - late night")
        void shouldReturnTrueWhenWithinOvernightQuietHoursLateNight() {
            // Overnight: 22:00 to 07:00
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(23, 0))).isTrue();
            assertThat(preferences.isInQuietHours(LocalTime.of(22, 0))).isTrue();
            assertThat(preferences.isInQuietHours(LocalTime.MIDNIGHT)).isTrue();
        }

        @Test
        @DisplayName("should return true when within overnight quiet hours - early morning")
        void shouldReturnTrueWhenWithinOvernightQuietHoursEarlyMorning() {
            // Overnight: 22:00 to 07:00
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(3, 0))).isTrue();
            assertThat(preferences.isInQuietHours(LocalTime.of(6, 59))).isTrue();
        }

        @Test
        @DisplayName("should return false when outside overnight quiet hours")
        void shouldReturnFalseWhenOutsideOvernightQuietHours() {
            // Overnight: 22:00 to 07:00
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            assertThat(preferences.isInQuietHours(LocalTime.of(7, 0))).isFalse();
            assertThat(preferences.isInQuietHours(LocalTime.of(12, 0))).isFalse();
            assertThat(preferences.isInQuietHours(LocalTime.of(21, 59))).isFalse();
        }

        @Test
        @DisplayName("should handle boundary case at start time")
        void shouldHandleBoundaryAtStartTime() {
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            // Start time should be included
            assertThat(preferences.isInQuietHours(LocalTime.of(22, 0))).isTrue();
        }

        @Test
        @DisplayName("should handle boundary case at end time")
        void shouldHandleBoundaryAtEndTime() {
            preferences.setQuietHoursEnabled(true);
            preferences.setQuietHoursStart(LocalTime.of(22, 0));
            preferences.setQuietHoursEnd(LocalTime.of(7, 0));

            // End time should be excluded
            assertThat(preferences.isInQuietHours(LocalTime.of(7, 0))).isFalse();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create preferences with default values")
        void shouldCreatePreferencesWithDefaultValues() {
            UserNotificationPreferences prefs = UserNotificationPreferences.builder()
                    .build();

            // Email defaults
            assertThat(prefs.isEmailMarketing()).isFalse();
            assertThat(prefs.isEmailSecurityAlerts()).isTrue();
            assertThat(prefs.isEmailLoginAlerts()).isTrue();
            assertThat(prefs.isEmailWeeklyDigest()).isFalse();
            assertThat(prefs.isEmailProductUpdates()).isFalse();

            // Push defaults
            assertThat(prefs.isPushDirectMessages()).isTrue();
            assertThat(prefs.isPushMentions()).isTrue();
            assertThat(prefs.isPushReplies()).isTrue();
            assertThat(prefs.isPushLikes()).isTrue();
            assertThat(prefs.isPushFollows()).isTrue();
            assertThat(prefs.isPushSystemAlerts()).isTrue();

            // Quiet hours defaults
            assertThat(prefs.isQuietHoursEnabled()).isFalse();
            assertThat(prefs.getQuietHoursTimezone()).isEqualTo("UTC");

            // SMS defaults
            assertThat(prefs.isSmsEnabled()).isFalse();
            assertThat(prefs.isSmsSecurityOnly()).isTrue();
        }

        @Test
        @DisplayName("should create preferences with custom values")
        void shouldCreatePreferencesWithCustomValues() {
            UserNotificationPreferences prefs = UserNotificationPreferences.builder()
                    .emailMarketing(true)
                    .emailSecurityAlerts(false)
                    .pushDirectMessages(false)
                    .quietHoursEnabled(true)
                    .quietHoursStart(LocalTime.of(22, 0))
                    .quietHoursEnd(LocalTime.of(8, 0))
                    .quietHoursTimezone("America/New_York")
                    .smsEnabled(true)
                    .smsSecurityOnly(false)
                    .build();

            assertThat(prefs.isEmailMarketing()).isTrue();
            assertThat(prefs.isEmailSecurityAlerts()).isFalse();
            assertThat(prefs.isPushDirectMessages()).isFalse();
            assertThat(prefs.isQuietHoursEnabled()).isTrue();
            assertThat(prefs.getQuietHoursStart()).isEqualTo(LocalTime.of(22, 0));
            assertThat(prefs.getQuietHoursEnd()).isEqualTo(LocalTime.of(8, 0));
            assertThat(prefs.getQuietHoursTimezone()).isEqualTo("America/New_York");
            assertThat(prefs.isSmsEnabled()).isTrue();
            assertThat(prefs.isSmsSecurityOnly()).isFalse();
        }
    }
}
