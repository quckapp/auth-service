package com.quckapp.auth.security.ratelimit;

import java.lang.annotation.*;

/**
 * Annotation to apply rate limiting to controller methods
 *
 * Usage:
 * @RateLimit(requests = 10, window = 60, key = KeyType.USER)
 * public ResponseEntity<?> myEndpoint() { ... }
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    /**
     * Maximum number of requests allowed in the time window
     */
    int requests() default 60;

    /**
     * Time window in seconds
     */
    int window() default 60;

    /**
     * Key type for rate limiting
     */
    KeyType key() default KeyType.IP;

    /**
     * Custom key prefix (optional)
     */
    String keyPrefix() default "";

    /**
     * Whether to skip rate limiting for authenticated users
     */
    boolean skipAuthenticated() default false;

    /**
     * Message to return when rate limit is exceeded
     */
    String message() default "Rate limit exceeded. Please try again later.";

    /**
     * Key type for rate limiting
     */
    enum KeyType {
        /**
         * Rate limit by IP address
         */
        IP,

        /**
         * Rate limit by authenticated user ID
         */
        USER,

        /**
         * Rate limit by API key
         */
        API_KEY,

        /**
         * Rate limit by IP + endpoint combination
         */
        IP_ENDPOINT,

        /**
         * Rate limit by user + endpoint combination
         */
        USER_ENDPOINT,

        /**
         * Global rate limit (shared across all requests)
         */
        GLOBAL
    }
}
