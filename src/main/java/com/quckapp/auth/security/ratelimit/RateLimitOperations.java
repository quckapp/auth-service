package com.quckapp.auth.security.ratelimit;

/**
 * Interface for rate limiting operations.
 * Extracted to allow mocking in tests without ByteBuddy class modification issues.
 */
public interface RateLimitOperations {

    /**
     * Check rate limit for a given key
     */
    RateLimitResult checkRateLimit(String key, int maxRequests, int windowSeconds);

    /**
     * Check API rate limit for a user
     */
    RateLimitResult checkApiRateLimit(String userId);

    /**
     * Check IP-based rate limit
     */
    RateLimitResult checkIpRateLimit(String ipAddress);

    /**
     * Check login rate limit for email and IP
     */
    RateLimitResult checkLoginRateLimit(String email, String ipAddress);

    /**
     * Record a failed login attempt
     */
    void recordFailedLogin(String email, String ipAddress);

    /**
     * Clear login attempts after successful login
     */
    void clearLoginAttempts(String email, String ipAddress);

    /**
     * Block login for an email
     */
    void blockLogin(String email);

    /**
     * Unblock login for an email
     */
    void unblockLogin(String email);

    /**
     * Check if login is blocked for an email
     */
    boolean isLoginBlocked(String email);

    /**
     * Get remaining block time in seconds
     */
    long getBlockTimeRemaining(String email);

    /**
     * Reset rate limit for a key
     */
    void resetRateLimit(String key);

    /**
     * Get current count for a key
     */
    long getCurrentCount(String key, int windowSeconds);
}
