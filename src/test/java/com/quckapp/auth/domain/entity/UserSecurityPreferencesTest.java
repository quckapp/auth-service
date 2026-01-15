package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for UserSecurityPreferences entity
 */
@DisplayName("UserSecurityPreferences Entity Tests")
class UserSecurityPreferencesTest {

    private UserSecurityPreferences preferences;

    @BeforeEach
    void setUp() {
        Set<String> whitelist = new HashSet<>();
        whitelist.add("192.168.1.1");
        whitelist.add("10.0.0.1");

        preferences = UserSecurityPreferences.builder()
                .id(UUID.randomUUID())
                .ipWhitelistEnabled(true)
                .ipWhitelist(whitelist)
                .passwordExpiryDays(90)
                .build();
    }

    @Nested
    @DisplayName("isIpAllowed() Tests")
    class IsIpAllowedTests {

        @Test
        @DisplayName("should return true when whitelist is disabled")
        void shouldReturnTrueWhenWhitelistDisabled() {
            preferences.setIpWhitelistEnabled(false);

            assertThat(preferences.isIpAllowed("203.0.113.50")).isTrue();
        }

        @Test
        @DisplayName("should return true when whitelist is empty")
        void shouldReturnTrueWhenWhitelistEmpty() {
            preferences.setIpWhitelistEnabled(true);
            preferences.setIpWhitelist(new HashSet<>());

            assertThat(preferences.isIpAllowed("203.0.113.50")).isTrue();
        }

        @Test
        @DisplayName("should return true when IP is in whitelist")
        void shouldReturnTrueWhenIpInWhitelist() {
            preferences.setIpWhitelistEnabled(true);

            assertThat(preferences.isIpAllowed("192.168.1.1")).isTrue();
            assertThat(preferences.isIpAllowed("10.0.0.1")).isTrue();
        }

        @Test
        @DisplayName("should return false when IP is not in whitelist")
        void shouldReturnFalseWhenIpNotInWhitelist() {
            preferences.setIpWhitelistEnabled(true);

            assertThat(preferences.isIpAllowed("203.0.113.50")).isFalse();
            assertThat(preferences.isIpAllowed("172.16.0.1")).isFalse();
        }
    }

    @Nested
    @DisplayName("isPasswordExpired() Tests")
    class IsPasswordExpiredTests {

        @Test
        @DisplayName("should return false when passwordExpiryDays is 0")
        void shouldReturnFalseWhenExpiryDaysIsZero() {
            preferences.setPasswordExpiryDays(0);
            Instant passwordChangedAt = Instant.now().minus(365, ChronoUnit.DAYS);

            assertThat(preferences.isPasswordExpired(passwordChangedAt)).isFalse();
        }

        @Test
        @DisplayName("should return false when passwordExpiryDays is negative")
        void shouldReturnFalseWhenExpiryDaysIsNegative() {
            preferences.setPasswordExpiryDays(-1);
            Instant passwordChangedAt = Instant.now().minus(365, ChronoUnit.DAYS);

            assertThat(preferences.isPasswordExpired(passwordChangedAt)).isFalse();
        }

        @Test
        @DisplayName("should return false when passwordChangedAt is null")
        void shouldReturnFalseWhenPasswordChangedAtIsNull() {
            preferences.setPasswordExpiryDays(90);

            assertThat(preferences.isPasswordExpired(null)).isFalse();
        }

        @Test
        @DisplayName("should return false when password was changed recently")
        void shouldReturnFalseWhenPasswordChangedRecently() {
            preferences.setPasswordExpiryDays(90);
            Instant passwordChangedAt = Instant.now().minus(30, ChronoUnit.DAYS);

            assertThat(preferences.isPasswordExpired(passwordChangedAt)).isFalse();
        }

        @Test
        @DisplayName("should return true when password expiry has passed")
        void shouldReturnTrueWhenPasswordExpiryPassed() {
            preferences.setPasswordExpiryDays(90);
            Instant passwordChangedAt = Instant.now().minus(100, ChronoUnit.DAYS);

            assertThat(preferences.isPasswordExpired(passwordChangedAt)).isTrue();
        }

        @Test
        @DisplayName("should handle exact expiry boundary")
        void shouldHandleExactExpiryBoundary() {
            preferences.setPasswordExpiryDays(30);
            // Password changed exactly 31 days ago should be expired
            Instant passwordChangedAt = Instant.now().minus(31, ChronoUnit.DAYS);

            assertThat(preferences.isPasswordExpired(passwordChangedAt)).isTrue();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create preferences with default values")
        void shouldCreatePreferencesWithDefaultValues() {
            UserSecurityPreferences newPrefs = UserSecurityPreferences.builder()
                    .build();

            assertThat(newPrefs.isRequire2faForSensitiveActions()).isFalse();
            assertThat(newPrefs.isLoginNotificationEnabled()).isTrue();
            assertThat(newPrefs.isNewDeviceNotification()).isTrue();
            assertThat(newPrefs.isSuspiciousActivityNotification()).isTrue();
            assertThat(newPrefs.getSessionTimeoutMinutes()).isEqualTo(1440);
            assertThat(newPrefs.getMaxConcurrentSessions()).isEqualTo(5);
            assertThat(newPrefs.isRememberTrustedDevices()).isTrue();
            assertThat(newPrefs.getTrustedDeviceExpiryDays()).isEqualTo(30);
            assertThat(newPrefs.getPasswordExpiryDays()).isEqualTo(0);
            assertThat(newPrefs.isRequirePasswordChangeOnNextLogin()).isFalse();
            assertThat(newPrefs.isIpWhitelistEnabled()).isFalse();
            assertThat(newPrefs.getIpWhitelist()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("should create preferences with custom values")
        void shouldCreatePreferencesWithCustomValues() {
            Set<String> whitelist = Set.of("10.0.0.1", "10.0.0.2");

            UserSecurityPreferences newPrefs = UserSecurityPreferences.builder()
                    .require2faForSensitiveActions(true)
                    .loginNotificationEnabled(false)
                    .sessionTimeoutMinutes(720)
                    .maxConcurrentSessions(3)
                    .passwordExpiryDays(60)
                    .ipWhitelistEnabled(true)
                    .ipWhitelist(new HashSet<>(whitelist))
                    .build();

            assertThat(newPrefs.isRequire2faForSensitiveActions()).isTrue();
            assertThat(newPrefs.isLoginNotificationEnabled()).isFalse();
            assertThat(newPrefs.getSessionTimeoutMinutes()).isEqualTo(720);
            assertThat(newPrefs.getMaxConcurrentSessions()).isEqualTo(3);
            assertThat(newPrefs.getPasswordExpiryDays()).isEqualTo(60);
            assertThat(newPrefs.isIpWhitelistEnabled()).isTrue();
            assertThat(newPrefs.getIpWhitelist()).containsExactlyInAnyOrder("10.0.0.1", "10.0.0.2");
        }
    }
}
