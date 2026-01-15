package com.quckapp.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/**
 * Service for managing blacklisted tokens using Redis.
 * Blacklisted tokens are stored with their remaining TTL to auto-expire.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService implements TokenBlacklistOperations {

    private final StringRedisOperations redisOperations;

    private static final String BLACKLIST_PREFIX = "token:blacklist:";
    private static final String USER_BLACKLIST_PREFIX = "user:token:blacklist:";

    /**
     * Blacklist a token until its expiration time.
     *
     * @param token     The JWT token to blacklist
     * @param expiresAt The token's expiration time
     * @param reason    The reason for blacklisting
     */
    public void blacklistToken(String token, Date expiresAt, String reason) {
        if (token == null || expiresAt == null) {
            return;
        }

        // Calculate TTL - only blacklist if token hasn't expired yet
        long ttlSeconds = (expiresAt.getTime() - System.currentTimeMillis()) / 1000;
        if (ttlSeconds <= 0) {
            log.debug("Token already expired, skipping blacklist");
            return;
        }

        String key = BLACKLIST_PREFIX + hashToken(token);
        String value = reason != null ? reason : "revoked";

        redisOperations.set(key, value, Duration.ofSeconds(ttlSeconds));
        log.debug("Token blacklisted for {} seconds: {}", ttlSeconds, reason);
    }

    /**
     * Blacklist a token until its expiration time.
     *
     * @param token     The JWT token to blacklist
     * @param expiresAt The token's expiration instant
     * @param reason    The reason for blacklisting
     */
    public void blacklistToken(String token, Instant expiresAt, String reason) {
        if (expiresAt != null) {
            blacklistToken(token, Date.from(expiresAt), reason);
        }
    }

    /**
     * Check if a token is blacklisted.
     *
     * @param token The JWT token to check
     * @return true if the token is blacklisted
     */
    public boolean isBlacklisted(String token) {
        if (token == null) {
            return false;
        }

        String key = BLACKLIST_PREFIX + hashToken(token);
        return redisOperations.hasKey(key);
    }

    /**
     * Blacklist all tokens for a user by storing a timestamp.
     * Any token issued before this timestamp should be considered invalid.
     *
     * @param userId The user ID
     */
    public void blacklistAllUserTokens(String userId) {
        if (userId == null) {
            return;
        }

        String key = USER_BLACKLIST_PREFIX + userId;
        String timestamp = String.valueOf(System.currentTimeMillis());

        // Store for 7 days (max refresh token lifetime)
        redisOperations.set(key, timestamp, Duration.ofDays(7));
        log.info("All tokens blacklisted for user: {}", userId);
    }

    /**
     * Get the timestamp when all user tokens were blacklisted.
     *
     * @param userId The user ID
     * @return The blacklist timestamp, or null if no blacklist exists
     */
    public Long getUserBlacklistTimestamp(String userId) {
        if (userId == null) {
            return null;
        }

        String key = USER_BLACKLIST_PREFIX + userId;
        String value = redisOperations.get(key);

        if (value != null) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                log.warn("Invalid blacklist timestamp for user {}: {}", userId, value);
            }
        }
        return null;
    }

    /**
     * Check if a token was issued before the user's blacklist timestamp.
     *
     * @param userId   The user ID
     * @param issuedAt The token's issued-at timestamp (milliseconds)
     * @return true if the token was issued before blacklist (and should be rejected)
     */
    public boolean isTokenIssuedBeforeBlacklist(String userId, long issuedAt) {
        Long blacklistTimestamp = getUserBlacklistTimestamp(userId);
        if (blacklistTimestamp == null) {
            return false;
        }
        return issuedAt < blacklistTimestamp;
    }

    /**
     * Remove a token from the blacklist.
     *
     * @param token The JWT token to remove
     */
    public void removeFromBlacklist(String token) {
        if (token == null) {
            return;
        }

        String key = BLACKLIST_PREFIX + hashToken(token);
        redisOperations.delete(key);
        log.debug("Token removed from blacklist");
    }

    /**
     * Clear the user-level blacklist.
     *
     * @param userId The user ID
     */
    public void clearUserBlacklist(String userId) {
        if (userId == null) {
            return;
        }

        String key = USER_BLACKLIST_PREFIX + userId;
        redisOperations.delete(key);
        log.info("User blacklist cleared for: {}", userId);
    }

    /**
     * Hash the token for storage (to avoid storing full tokens in Redis).
     * Uses a simple approach - in production, consider using a proper hash.
     */
    private String hashToken(String token) {
        // Use the last 32 characters of the token as a simple hash
        // In production, you might want to use SHA-256
        if (token.length() > 32) {
            return token.substring(token.length() - 32);
        }
        return token;
    }
}
