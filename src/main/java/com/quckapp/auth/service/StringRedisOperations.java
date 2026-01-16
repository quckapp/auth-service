package com.quckapp.auth.service;

import java.time.Duration;

/**
 * Interface for String-based Redis operations.
 * Extracted for testability with Java 25+ Mockito compatibility.
 */
public interface StringRedisOperations {

    /**
     * Set a key with value and TTL.
     */
    void set(String key, String value, Duration ttl);

    /**
     * Get a value by key.
     */
    String get(String key);

    /**
     * Check if a key exists.
     */
    boolean hasKey(String key);

    /**
     * Delete a key.
     */
    void delete(String key);
}
