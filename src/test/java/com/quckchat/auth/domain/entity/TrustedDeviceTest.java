package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for TrustedDevice entity
 */
@DisplayName("TrustedDevice Entity Tests")
class TrustedDeviceTest {

    private TrustedDevice trustedDevice;

    @BeforeEach
    void setUp() {
        trustedDevice = TrustedDevice.builder()
                .id(UUID.randomUUID())
                .deviceFingerprint("fingerprint-abc123")
                .deviceName("My Laptop")
                .deviceType("DESKTOP")
                .osName("Windows 11")
                .browserName("Chrome")
                .isTrusted(true)
                .build();
    }

    @Nested
    @DisplayName("isExpired() Tests")
    class IsExpiredTests {

        @Test
        @DisplayName("should return false when expiresAt is null")
        void shouldReturnFalseWhenExpiresAtNull() {
            trustedDevice.setExpiresAt(null);

            assertThat(trustedDevice.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return false when expiration is in the future")
        void shouldReturnFalseWhenExpirationInFuture() {
            trustedDevice.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));

            assertThat(trustedDevice.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return true when expiration is in the past")
        void shouldReturnTrueWhenExpirationInPast() {
            trustedDevice.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(trustedDevice.isExpired()).isTrue();
        }

        @Test
        @DisplayName("should return true when expiration is exactly now")
        void shouldReturnTrueWhenExpirationIsNow() {
            trustedDevice.setExpiresAt(Instant.now().minus(1, ChronoUnit.MILLIS));

            assertThat(trustedDevice.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("isValid() Tests")
    class IsValidTests {

        @Test
        @DisplayName("should return true when trusted and not expired")
        void shouldReturnTrueWhenTrustedAndNotExpired() {
            trustedDevice.setTrusted(true);
            trustedDevice.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

            assertThat(trustedDevice.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return true when trusted and no expiration set")
        void shouldReturnTrueWhenTrustedAndNoExpiration() {
            trustedDevice.setTrusted(true);
            trustedDevice.setExpiresAt(null);

            assertThat(trustedDevice.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return false when not trusted")
        void shouldReturnFalseWhenNotTrusted() {
            trustedDevice.setTrusted(false);
            trustedDevice.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

            assertThat(trustedDevice.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when expired")
        void shouldReturnFalseWhenExpired() {
            trustedDevice.setTrusted(true);
            trustedDevice.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(trustedDevice.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when both not trusted and expired")
        void shouldReturnFalseWhenNotTrustedAndExpired() {
            trustedDevice.setTrusted(false);
            trustedDevice.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(trustedDevice.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("updateLastUsed() Tests")
    class UpdateLastUsedTests {

        @Test
        @DisplayName("should update lastUsedAt timestamp")
        void shouldUpdateLastUsedAtTimestamp() {
            Instant before = Instant.now();

            trustedDevice.updateLastUsed();

            assertThat(trustedDevice.getLastUsedAt()).isNotNull();
            assertThat(trustedDevice.getLastUsedAt()).isAfterOrEqualTo(before);
        }

        @Test
        @DisplayName("should update lastUsedAt when called multiple times")
        void shouldUpdateLastUsedAtWhenCalledMultipleTimes() throws InterruptedException {
            trustedDevice.updateLastUsed();
            Instant first = trustedDevice.getLastUsedAt();

            Thread.sleep(10); // Small delay

            trustedDevice.updateLastUsed();
            Instant second = trustedDevice.getLastUsedAt();

            assertThat(second).isAfterOrEqualTo(first);
        }
    }

    @Nested
    @DisplayName("revokeTrust() Tests")
    class RevokeTrustTests {

        @Test
        @DisplayName("should set isTrusted to false")
        void shouldSetIsTrustedToFalse() {
            trustedDevice.setTrusted(true);

            trustedDevice.revokeTrust();

            assertThat(trustedDevice.isTrusted()).isFalse();
        }

        @Test
        @DisplayName("should make isValid return false")
        void shouldMakeIsValidReturnFalse() {
            trustedDevice.setTrusted(true);
            trustedDevice.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
            assertThat(trustedDevice.isValid()).isTrue();

            trustedDevice.revokeTrust();

            assertThat(trustedDevice.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create device with default values")
        void shouldCreateDeviceWithDefaultValues() {
            TrustedDevice device = TrustedDevice.builder()
                    .deviceFingerprint("test-fingerprint")
                    .build();

            assertThat(device.isTrusted()).isTrue();
            assertThat(device.getTrustedAt()).isNotNull();
            assertThat(device.getLastUsedAt()).isNotNull();
        }

        @Test
        @DisplayName("should create device with all fields")
        void shouldCreateDeviceWithAllFields() {
            Instant now = Instant.now();
            Instant expiry = now.plus(90, ChronoUnit.DAYS);

            TrustedDevice device = TrustedDevice.builder()
                    .id(UUID.randomUUID())
                    .deviceFingerprint("fp-123")
                    .deviceName("MacBook Pro")
                    .deviceType("LAPTOP")
                    .osName("macOS")
                    .browserName("Safari")
                    .isTrusted(true)
                    .expiresAt(expiry)
                    .build();

            assertThat(device.getDeviceFingerprint()).isEqualTo("fp-123");
            assertThat(device.getDeviceName()).isEqualTo("MacBook Pro");
            assertThat(device.getDeviceType()).isEqualTo("LAPTOP");
            assertThat(device.getOsName()).isEqualTo("macOS");
            assertThat(device.getBrowserName()).isEqualTo("Safari");
            assertThat(device.getExpiresAt()).isEqualTo(expiry);
        }
    }
}
