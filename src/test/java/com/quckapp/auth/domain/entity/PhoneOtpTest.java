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
 * Unit tests for PhoneOtp entity
 */
@DisplayName("PhoneOtp Entity Tests")
class PhoneOtpTest {

    private PhoneOtp phoneOtp;

    @BeforeEach
    void setUp() {
        phoneOtp = PhoneOtp.builder()
                .id(UUID.randomUUID())
                .phoneNumber("+1234567890")
                .otpHash("hashed-otp-value")
                .expiresAt(Instant.now().plus(10, ChronoUnit.MINUTES))
                .verified(false)
                .attemptCount(0)
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .build();
    }

    @Nested
    @DisplayName("isExpired() Tests")
    class IsExpiredTests {

        @Test
        @DisplayName("should return false when expiration is in the future")
        void shouldReturnFalseWhenExpirationInFuture() {
            phoneOtp.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));

            assertThat(phoneOtp.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return true when expiration is in the past")
        void shouldReturnTrueWhenExpirationInPast() {
            phoneOtp.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));

            assertThat(phoneOtp.isExpired()).isTrue();
        }

        @Test
        @DisplayName("should return true when expiration just passed")
        void shouldReturnTrueWhenExpirationJustPassed() {
            phoneOtp.setExpiresAt(Instant.now().minus(1, ChronoUnit.SECONDS));

            assertThat(phoneOtp.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("isValid() Tests")
    class IsValidTests {

        @Test
        @DisplayName("should return true when not verified and not expired")
        void shouldReturnTrueWhenNotVerifiedAndNotExpired() {
            phoneOtp.setVerified(false);
            phoneOtp.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));

            assertThat(phoneOtp.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return false when already verified")
        void shouldReturnFalseWhenAlreadyVerified() {
            phoneOtp.setVerified(true);
            phoneOtp.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));

            assertThat(phoneOtp.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when expired")
        void shouldReturnFalseWhenExpired() {
            phoneOtp.setVerified(false);
            phoneOtp.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));

            assertThat(phoneOtp.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when both verified and expired")
        void shouldReturnFalseWhenVerifiedAndExpired() {
            phoneOtp.setVerified(true);
            phoneOtp.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));

            assertThat(phoneOtp.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("incrementAttempt() Tests")
    class IncrementAttemptTests {

        @Test
        @DisplayName("should increment attempt count from 0 to 1")
        void shouldIncrementFromZeroToOne() {
            phoneOtp.setAttemptCount(0);

            phoneOtp.incrementAttempt();

            assertThat(phoneOtp.getAttemptCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("should increment attempt count multiple times")
        void shouldIncrementMultipleTimes() {
            phoneOtp.setAttemptCount(0);

            phoneOtp.incrementAttempt();
            phoneOtp.incrementAttempt();
            phoneOtp.incrementAttempt();

            assertThat(phoneOtp.getAttemptCount()).isEqualTo(3);
        }

        @Test
        @DisplayName("should increment from existing count")
        void shouldIncrementFromExistingCount() {
            phoneOtp.setAttemptCount(5);

            phoneOtp.incrementAttempt();

            assertThat(phoneOtp.getAttemptCount()).isEqualTo(6);
        }
    }

    @Nested
    @DisplayName("markVerified() Tests")
    class MarkVerifiedTests {

        @Test
        @DisplayName("should set verified to true")
        void shouldSetVerifiedToTrue() {
            phoneOtp.setVerified(false);

            phoneOtp.markVerified();

            assertThat(phoneOtp.isVerified()).isTrue();
        }

        @Test
        @DisplayName("should set verifiedAt timestamp")
        void shouldSetVerifiedAtTimestamp() {
            Instant before = Instant.now();

            phoneOtp.markVerified();

            assertThat(phoneOtp.getVerifiedAt()).isNotNull();
            assertThat(phoneOtp.getVerifiedAt()).isAfterOrEqualTo(before);
        }

        @Test
        @DisplayName("should make isValid return false after marking verified")
        void shouldMakeIsValidReturnFalse() {
            phoneOtp.setExpiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));
            assertThat(phoneOtp.isValid()).isTrue();

            phoneOtp.markVerified();

            assertThat(phoneOtp.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create phone OTP with default values")
        void shouldCreatePhoneOtpWithDefaultValues() {
            PhoneOtp newOtp = PhoneOtp.builder()
                    .phoneNumber("+1987654321")
                    .otpHash("hash")
                    .expiresAt(Instant.now().plus(10, ChronoUnit.MINUTES))
                    .build();

            assertThat(newOtp.isVerified()).isFalse();
            assertThat(newOtp.getAttemptCount()).isEqualTo(0);
        }

        @Test
        @DisplayName("should create phone OTP with all fields")
        void shouldCreatePhoneOtpWithAllFields() {
            Instant expiry = Instant.now().plus(15, ChronoUnit.MINUTES);

            PhoneOtp newOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber("+1555123456")
                    .otpHash("secure-hash")
                    .expiresAt(expiry)
                    .verified(false)
                    .attemptCount(2)
                    .ipAddress("10.0.0.1")
                    .userAgent("Safari/16.0")
                    .build();

            assertThat(newOtp.getPhoneNumber()).isEqualTo("+1555123456");
            assertThat(newOtp.getOtpHash()).isEqualTo("secure-hash");
            assertThat(newOtp.getExpiresAt()).isEqualTo(expiry);
            assertThat(newOtp.getAttemptCount()).isEqualTo(2);
            assertThat(newOtp.getIpAddress()).isEqualTo("10.0.0.1");
            assertThat(newOtp.getUserAgent()).isEqualTo("Safari/16.0");
        }
    }
}
