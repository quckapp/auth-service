package com.quckapp.auth.security.ratelimit;

import lombok.Getter;

/**
 * Result of a rate limit check
 */
@Getter
public class RateLimitResult {

    private final boolean allowed;
    private final int remaining;
    private final long retryAfterSeconds;
    private final boolean blocked;

    private RateLimitResult(boolean allowed, int remaining, long retryAfterSeconds, boolean blocked) {
        this.allowed = allowed;
        this.remaining = remaining;
        this.retryAfterSeconds = retryAfterSeconds;
        this.blocked = blocked;
    }

    /**
     * Request is allowed
     */
    public static RateLimitResult allowed(int remaining) {
        return new RateLimitResult(true, remaining, 0, false);
    }

    /**
     * Rate limit exceeded (temporary)
     */
    public static RateLimitResult exceeded(long retryAfterSeconds) {
        return new RateLimitResult(false, 0, retryAfterSeconds, false);
    }

    /**
     * User is blocked (e.g., too many failed login attempts)
     */
    public static RateLimitResult blocked(long retryAfterSeconds) {
        return new RateLimitResult(false, 0, retryAfterSeconds, true);
    }

    /**
     * Check if request should be denied
     */
    public boolean isDenied() {
        return !allowed;
    }

    /**
     * Get HTTP headers for rate limit response
     */
    public java.util.Map<String, String> getHeaders(int limit) {
        java.util.Map<String, String> headers = new java.util.HashMap<>();
        headers.put("X-RateLimit-Limit", String.valueOf(limit));
        headers.put("X-RateLimit-Remaining", String.valueOf(remaining));

        if (!allowed) {
            headers.put("X-RateLimit-Reset", String.valueOf(retryAfterSeconds));
            headers.put("Retry-After", String.valueOf(retryAfterSeconds));
        }

        return headers;
    }
}
