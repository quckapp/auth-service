package com.quckapp.auth.service;

import java.time.Instant;
import java.util.Date;

/**
 * Interface for token blacklist operations.
 * Extracted for testability with Java 25+ Mockito compatibility.
 */
public interface TokenBlacklistOperations {

    /**
     * Blacklist a token until its expiration time.
     *
     * @param token     The JWT token to blacklist
     * @param expiresAt The token's expiration time
     * @param reason    The reason for blacklisting
     */
    void blacklistToken(String token, Date expiresAt, String reason);

    /**
     * Blacklist a token until its expiration time.
     *
     * @param token     The JWT token to blacklist
     * @param expiresAt The token's expiration instant
     * @param reason    The reason for blacklisting
     */
    void blacklistToken(String token, Instant expiresAt, String reason);

    /**
     * Check if a token is blacklisted.
     *
     * @param token The JWT token to check
     * @return true if the token is blacklisted
     */
    boolean isBlacklisted(String token);

    /**
     * Blacklist all tokens for a user by storing a timestamp.
     * Any token issued before this timestamp should be considered invalid.
     *
     * @param userId The user ID
     */
    void blacklistAllUserTokens(String userId);

    /**
     * Get the timestamp when all user tokens were blacklisted.
     *
     * @param userId The user ID
     * @return The blacklist timestamp, or null if no blacklist exists
     */
    Long getUserBlacklistTimestamp(String userId);

    /**
     * Check if a token was issued before the user's blacklist timestamp.
     *
     * @param userId   The user ID
     * @param issuedAt The token's issued-at timestamp (milliseconds)
     * @return true if the token was issued before blacklist (and should be rejected)
     */
    boolean isTokenIssuedBeforeBlacklist(String userId, long issuedAt);

    /**
     * Remove a token from the blacklist.
     *
     * @param token The JWT token to remove
     */
    void removeFromBlacklist(String token);

    /**
     * Clear the user-level blacklist.
     *
     * @param userId The user ID
     */
    void clearUserBlacklist(String userId);
}
