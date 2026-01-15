package com.quckapp.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TokenBlacklistService
 */
@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    @Mock
    private StringRedisOperations redisOperations;

    private TokenBlacklistService tokenBlacklistService;

    private static final String BLACKLIST_PREFIX = "token:blacklist:";
    private static final String USER_BLACKLIST_PREFIX = "user:token:blacklist:";

    @BeforeEach
    void setUp() {
        tokenBlacklistService = new TokenBlacklistService(redisOperations);
    }

    @Nested
    @DisplayName("Token blacklist tests")
    class TokenBlacklistTests {

        @Test
        @DisplayName("should blacklist token with Date expiration")
        void shouldBlacklistTokenWithDate() {
            String token = "jwt-token-123";
            Date expiresAt = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));
            String reason = "User logout";

            tokenBlacklistService.blacklistToken(token, expiresAt, reason);

            verify(redisOperations).set(
                    startsWith(BLACKLIST_PREFIX),
                    eq(reason),
                    any(Duration.class)
            );
        }

        @Test
        @DisplayName("should blacklist token with Instant expiration")
        void shouldBlacklistTokenWithInstant() {
            String token = "jwt-token-123";
            Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS);
            String reason = "Manual revocation";

            tokenBlacklistService.blacklistToken(token, expiresAt, reason);

            verify(redisOperations).set(
                    startsWith(BLACKLIST_PREFIX),
                    eq(reason),
                    any(Duration.class)
            );
        }

        @Test
        @DisplayName("should skip blacklisting null token")
        void shouldSkipNullToken() {
            tokenBlacklistService.blacklistToken(null, new Date(), "reason");

            verify(redisOperations, never()).set(anyString(), anyString(), any(Duration.class));
        }

        @Test
        @DisplayName("should skip blacklisting null expiration date")
        void shouldSkipNullExpiration() {
            tokenBlacklistService.blacklistToken("token", (Date) null, "reason");

            verify(redisOperations, never()).set(anyString(), anyString(), any(Duration.class));
        }

        @Test
        @DisplayName("should skip blacklisting already expired token")
        void shouldSkipExpiredToken() {
            String token = "jwt-token-123";
            Date expiresAt = Date.from(Instant.now().minus(1, ChronoUnit.HOURS));

            tokenBlacklistService.blacklistToken(token, expiresAt, "reason");

            verify(redisOperations, never()).set(anyString(), anyString(), any(Duration.class));
        }

        @Test
        @DisplayName("should use default reason when null")
        void shouldUseDefaultReasonWhenNull() {
            String token = "jwt-token-123";
            Date expiresAt = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));

            tokenBlacklistService.blacklistToken(token, expiresAt, null);

            verify(redisOperations).set(
                    startsWith(BLACKLIST_PREFIX),
                    eq("revoked"),
                    any(Duration.class)
            );
        }
    }

    @Nested
    @DisplayName("Blacklist check tests")
    class BlacklistCheckTests {

        @Test
        @DisplayName("should return true for blacklisted token")
        void shouldReturnTrueForBlacklistedToken() {
            String token = "blacklisted-token";

            when(redisOperations.hasKey(startsWith(BLACKLIST_PREFIX))).thenReturn(true);

            boolean result = tokenBlacklistService.isBlacklisted(token);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false for non-blacklisted token")
        void shouldReturnFalseForNonBlacklistedToken() {
            String token = "valid-token";

            when(redisOperations.hasKey(startsWith(BLACKLIST_PREFIX))).thenReturn(false);

            boolean result = tokenBlacklistService.isBlacklisted(token);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false for null token")
        void shouldReturnFalseForNullToken() {
            boolean result = tokenBlacklistService.isBlacklisted(null);

            assertThat(result).isFalse();
            verify(redisOperations, never()).hasKey(anyString());
        }
    }

    @Nested
    @DisplayName("User blacklist tests")
    class UserBlacklistTests {

        @Test
        @DisplayName("should blacklist all user tokens")
        void shouldBlacklistAllUserTokens() {
            String userId = "user-123";

            tokenBlacklistService.blacklistAllUserTokens(userId);

            verify(redisOperations).set(
                    eq(USER_BLACKLIST_PREFIX + userId),
                    anyString(),
                    eq(Duration.ofDays(7))
            );
        }

        @Test
        @DisplayName("should skip blacklisting for null userId")
        void shouldSkipNullUserId() {
            tokenBlacklistService.blacklistAllUserTokens(null);

            verify(redisOperations, never()).set(anyString(), anyString(), any(Duration.class));
        }

        @Test
        @DisplayName("should get user blacklist timestamp")
        void shouldGetUserBlacklistTimestamp() {
            String userId = "user-123";
            String timestamp = "1704067200000";

            when(redisOperations.get(USER_BLACKLIST_PREFIX + userId)).thenReturn(timestamp);

            Long result = tokenBlacklistService.getUserBlacklistTimestamp(userId);

            assertThat(result).isEqualTo(1704067200000L);
        }

        @Test
        @DisplayName("should return null for non-existent blacklist timestamp")
        void shouldReturnNullForNonExistentTimestamp() {
            String userId = "user-123";

            when(redisOperations.get(USER_BLACKLIST_PREFIX + userId)).thenReturn(null);

            Long result = tokenBlacklistService.getUserBlacklistTimestamp(userId);

            assertThat(result).isNull();
        }

        @Test
        @DisplayName("should return null for null userId")
        void shouldReturnNullForNullUserId() {
            Long result = tokenBlacklistService.getUserBlacklistTimestamp(null);

            assertThat(result).isNull();
            verify(redisOperations, never()).get(anyString());
        }

        @Test
        @DisplayName("should handle invalid timestamp format")
        void shouldHandleInvalidTimestampFormat() {
            String userId = "user-123";

            when(redisOperations.get(USER_BLACKLIST_PREFIX + userId)).thenReturn("invalid");

            Long result = tokenBlacklistService.getUserBlacklistTimestamp(userId);

            assertThat(result).isNull();
        }
    }

    @Nested
    @DisplayName("Token issued before blacklist tests")
    class TokenIssuedBeforeBlacklistTests {

        @Test
        @DisplayName("should return true for token issued before blacklist")
        void shouldReturnTrueForOldToken() {
            String userId = "user-123";
            long issuedAt = 1704067200000L; // Before blacklist
            long blacklistTimestamp = 1704153600000L; // After token issued

            when(redisOperations.get(USER_BLACKLIST_PREFIX + userId)).thenReturn(String.valueOf(blacklistTimestamp));

            boolean result = tokenBlacklistService.isTokenIssuedBeforeBlacklist(userId, issuedAt);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false for token issued after blacklist")
        void shouldReturnFalseForNewToken() {
            String userId = "user-123";
            long issuedAt = 1704153600000L; // After blacklist
            long blacklistTimestamp = 1704067200000L; // Before token issued

            when(redisOperations.get(USER_BLACKLIST_PREFIX + userId)).thenReturn(String.valueOf(blacklistTimestamp));

            boolean result = tokenBlacklistService.isTokenIssuedBeforeBlacklist(userId, issuedAt);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false when no blacklist exists")
        void shouldReturnFalseWhenNoBlacklist() {
            String userId = "user-123";

            when(redisOperations.get(USER_BLACKLIST_PREFIX + userId)).thenReturn(null);

            boolean result = tokenBlacklistService.isTokenIssuedBeforeBlacklist(userId, System.currentTimeMillis());

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("Remove from blacklist tests")
    class RemoveFromBlacklistTests {

        @Test
        @DisplayName("should remove token from blacklist")
        void shouldRemoveTokenFromBlacklist() {
            String token = "token-to-remove";

            tokenBlacklistService.removeFromBlacklist(token);

            verify(redisOperations).delete(startsWith(BLACKLIST_PREFIX));
        }

        @Test
        @DisplayName("should skip removal for null token")
        void shouldSkipRemovalForNullToken() {
            tokenBlacklistService.removeFromBlacklist(null);

            verify(redisOperations, never()).delete(anyString());
        }

        @Test
        @DisplayName("should clear user blacklist")
        void shouldClearUserBlacklist() {
            String userId = "user-123";

            tokenBlacklistService.clearUserBlacklist(userId);

            verify(redisOperations).delete(USER_BLACKLIST_PREFIX + userId);
        }

        @Test
        @DisplayName("should skip clearing for null userId")
        void shouldSkipClearingForNullUserId() {
            tokenBlacklistService.clearUserBlacklist(null);

            verify(redisOperations, never()).delete(anyString());
        }
    }
}
