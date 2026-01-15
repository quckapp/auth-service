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
 * Unit tests for RefreshToken entity
 */
@DisplayName("RefreshToken Entity Tests")
class RefreshTokenTest {

    private RefreshToken refreshToken;

    @BeforeEach
    void setUp() {
        refreshToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .token("refresh-token-abc123")
                .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                .deviceId("device-123")
                .deviceName("Chrome on Windows")
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .revoked(false)
                .build();
    }

    @Nested
    @DisplayName("isExpired() Tests")
    class IsExpiredTests {

        @Test
        @DisplayName("should return false when expiration is in the future")
        void shouldReturnFalseWhenExpirationInFuture() {
            refreshToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

            assertThat(refreshToken.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return true when expiration is in the past")
        void shouldReturnTrueWhenExpirationInPast() {
            refreshToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(refreshToken.isExpired()).isTrue();
        }

        @Test
        @DisplayName("should return true when expiration just passed")
        void shouldReturnTrueWhenExpirationJustPassed() {
            refreshToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.SECONDS));

            assertThat(refreshToken.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("isValid() Tests")
    class IsValidTests {

        @Test
        @DisplayName("should return true when not revoked and not expired")
        void shouldReturnTrueWhenNotRevokedAndNotExpired() {
            refreshToken.setRevoked(false);
            refreshToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

            assertThat(refreshToken.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return false when revoked")
        void shouldReturnFalseWhenRevoked() {
            refreshToken.setRevoked(true);
            refreshToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

            assertThat(refreshToken.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when expired")
        void shouldReturnFalseWhenExpired() {
            refreshToken.setRevoked(false);
            refreshToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(refreshToken.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when both revoked and expired")
        void shouldReturnFalseWhenRevokedAndExpired() {
            refreshToken.setRevoked(true);
            refreshToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(refreshToken.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("revoke() Tests")
    class RevokeTests {

        @Test
        @DisplayName("should set revoked to true")
        void shouldSetRevokedToTrue() {
            refreshToken.setRevoked(false);

            refreshToken.revoke("User logged out");

            assertThat(refreshToken.isRevoked()).isTrue();
        }

        @Test
        @DisplayName("should set revokedAt timestamp")
        void shouldSetRevokedAtTimestamp() {
            Instant before = Instant.now();

            refreshToken.revoke("Session terminated");

            assertThat(refreshToken.getRevokedAt()).isNotNull();
            assertThat(refreshToken.getRevokedAt()).isAfterOrEqualTo(before);
        }

        @Test
        @DisplayName("should set revokedReason")
        void shouldSetRevokedReason() {
            refreshToken.revoke("Security concern");

            assertThat(refreshToken.getRevokedReason()).isEqualTo("Security concern");
        }

        @Test
        @DisplayName("should make isValid return false after revoking")
        void shouldMakeIsValidReturnFalse() {
            refreshToken.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
            assertThat(refreshToken.isValid()).isTrue();

            refreshToken.revoke("Token rotation");

            assertThat(refreshToken.isValid()).isFalse();
        }

        @Test
        @DisplayName("should handle null reason")
        void shouldHandleNullReason() {
            refreshToken.revoke(null);

            assertThat(refreshToken.isRevoked()).isTrue();
            assertThat(refreshToken.getRevokedReason()).isNull();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create refresh token with default values")
        void shouldCreateRefreshTokenWithDefaultValues() {
            RefreshToken newToken = RefreshToken.builder()
                    .token("new-token")
                    .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                    .build();

            assertThat(newToken.isRevoked()).isFalse();
        }

        @Test
        @DisplayName("should create refresh token with all fields")
        void shouldCreateRefreshTokenWithAllFields() {
            Instant expiry = Instant.now().plus(14, ChronoUnit.DAYS);

            RefreshToken newToken = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token("full-token")
                    .expiresAt(expiry)
                    .deviceId("device-xyz")
                    .deviceName("Safari on macOS")
                    .ipAddress("10.0.0.1")
                    .userAgent("Safari/17.0")
                    .oauthProvider("google")
                    .sessionId("session-123")
                    .parentToken("parent-token")
                    .build();

            assertThat(newToken.getToken()).isEqualTo("full-token");
            assertThat(newToken.getExpiresAt()).isEqualTo(expiry);
            assertThat(newToken.getDeviceId()).isEqualTo("device-xyz");
            assertThat(newToken.getOauthProvider()).isEqualTo("google");
            assertThat(newToken.getSessionId()).isEqualTo("session-123");
            assertThat(newToken.getParentToken()).isEqualTo("parent-token");
        }
    }
}
