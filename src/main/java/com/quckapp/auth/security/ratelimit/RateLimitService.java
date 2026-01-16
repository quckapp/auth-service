package com.quckapp.auth.security.ratelimit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Redis-based Rate Limiting Service using Sliding Window algorithm
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService implements RateLimitOperations {

    private final StringRedisTemplate redisTemplate;
    private final RateLimitConfig config;

    private static final String RATE_LIMIT_PREFIX = "ratelimit:";
    private static final String LOGIN_ATTEMPT_PREFIX = "login:attempt:";
    private static final String LOGIN_BLOCK_PREFIX = "login:blocked:";

    /**
     * Sliding window rate limit script (Lua for atomicity)
     */
    private static final String SLIDING_WINDOW_SCRIPT = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])

        -- Remove old entries outside the window
        redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

        -- Count current requests in window
        local count = redis.call('ZCARD', key)

        if count < limit then
            -- Add new request with current timestamp
            redis.call('ZADD', key, now, now .. '-' .. math.random())
            redis.call('EXPIRE', key, window)
            return 1
        else
            return 0
        end
        """;

    /**
     * Check and consume rate limit for a key
     *
     * @param key           Unique identifier (e.g., "api:userId", "ip:192.168.1.1")
     * @param maxRequests   Maximum requests allowed in window
     * @param windowSeconds Time window in seconds
     * @return RateLimitResult with allowed status and remaining requests
     */
    public RateLimitResult checkRateLimit(String key, int maxRequests, int windowSeconds) {
        if (!config.isEnabled()) {
            return RateLimitResult.allowed(maxRequests);
        }

        String redisKey = RATE_LIMIT_PREFIX + key;
        long now = Instant.now().toEpochMilli();
        long windowMillis = windowSeconds * 1000L;

        try {
            RedisScript<Long> script = RedisScript.of(SLIDING_WINDOW_SCRIPT, Long.class);
            Long result = redisTemplate.execute(
                    script,
                    Collections.singletonList(redisKey),
                    String.valueOf(now),
                    String.valueOf(windowMillis),
                    String.valueOf(maxRequests)
            );

            boolean allowed = result != null && result == 1;

            if (allowed) {
                // Get remaining count
                Long count = redisTemplate.opsForZSet().zCard(redisKey);
                int remaining = Math.max(0, maxRequests - (count != null ? count.intValue() : 0));
                return RateLimitResult.allowed(remaining);
            } else {
                // Calculate retry after
                Double oldestScore = redisTemplate.opsForZSet().score(redisKey,
                        redisTemplate.opsForZSet().range(redisKey, 0, 0).stream().findFirst().orElse(""));
                long retryAfter = oldestScore != null
                        ? (long) ((oldestScore + windowMillis - now) / 1000)
                        : windowSeconds;

                log.warn("Rate limit exceeded for key: {}", key);
                return RateLimitResult.exceeded(retryAfter);
            }
        } catch (Exception e) {
            log.error("Rate limit check failed for key {}: {}", key, e.getMessage());
            // Fail open - allow request if Redis is unavailable
            return RateLimitResult.allowed(maxRequests);
        }
    }

    /**
     * Check API rate limit for a user
     */
    public RateLimitResult checkApiRateLimit(String userId) {
        return checkRateLimit(
                "api:" + userId,
                config.getApi().getRequestsPerMinute(),
                60
        );
    }

    /**
     * Check IP-based rate limit
     */
    public RateLimitResult checkIpRateLimit(String ipAddress) {
        if (!config.getIp().isEnabled()) {
            return RateLimitResult.allowed(config.getIp().getRequestsPerMinute());
        }

        return checkRateLimit(
                "ip:" + ipAddress,
                config.getIp().getRequestsPerMinute(),
                60
        );
    }

    /**
     * Check login rate limit for email/IP combination
     */
    public RateLimitResult checkLoginRateLimit(String email, String ipAddress) {
        // Check if already blocked
        String blockKey = LOGIN_BLOCK_PREFIX + email;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(blockKey))) {
            Long ttl = redisTemplate.getExpire(blockKey);
            return RateLimitResult.blocked(ttl != null ? ttl : config.getLogin().getBlockDurationSeconds());
        }

        // Check rate limit
        String attemptKey = LOGIN_ATTEMPT_PREFIX + email + ":" + ipAddress;
        return checkRateLimit(
                attemptKey,
                config.getLogin().getMaxAttempts(),
                config.getLogin().getWindowSeconds()
        );
    }

    /**
     * Record a failed login attempt
     */
    public void recordFailedLogin(String email, String ipAddress) {
        String key = LOGIN_ATTEMPT_PREFIX + email + ":" + ipAddress;
        long now = Instant.now().toEpochMilli();

        try {
            redisTemplate.opsForZSet().add(RATE_LIMIT_PREFIX + key, now + "-failed", now);
            redisTemplate.expire(RATE_LIMIT_PREFIX + key, Duration.ofSeconds(config.getLogin().getWindowSeconds()));

            // Check if should block
            Long count = redisTemplate.opsForZSet().zCard(RATE_LIMIT_PREFIX + key);
            if (count != null && count >= config.getLogin().getMaxAttempts()) {
                blockLogin(email);
            }
        } catch (Exception e) {
            log.error("Failed to record login attempt: {}", e.getMessage());
        }
    }

    /**
     * Block login for an email
     */
    public void blockLogin(String email) {
        String blockKey = LOGIN_BLOCK_PREFIX + email;
        redisTemplate.opsForValue().set(blockKey, "blocked",
                Duration.ofSeconds(config.getLogin().getBlockDurationSeconds()));
        log.warn("Login blocked for email: {} for {} seconds", email, config.getLogin().getBlockDurationSeconds());
    }

    /**
     * Clear login attempts after successful login
     */
    public void clearLoginAttempts(String email, String ipAddress) {
        String key = RATE_LIMIT_PREFIX + LOGIN_ATTEMPT_PREFIX + email + ":" + ipAddress;
        redisTemplate.delete(key);
    }

    /**
     * Unblock a login (admin action)
     */
    public void unblockLogin(String email) {
        String blockKey = LOGIN_BLOCK_PREFIX + email;
        redisTemplate.delete(blockKey);
        log.info("Login unblocked for email: {}", email);
    }

    /**
     * Check if login is blocked
     */
    public boolean isLoginBlocked(String email) {
        String blockKey = LOGIN_BLOCK_PREFIX + email;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey));
    }

    /**
     * Get remaining block time in seconds
     */
    public long getBlockTimeRemaining(String email) {
        String blockKey = LOGIN_BLOCK_PREFIX + email;
        Long ttl = redisTemplate.getExpire(blockKey);
        return ttl != null && ttl > 0 ? ttl : 0;
    }

    /**
     * Reset all rate limits for a key (admin action)
     */
    public void resetRateLimit(String key) {
        redisTemplate.delete(RATE_LIMIT_PREFIX + key);
        log.info("Rate limit reset for key: {}", key);
    }

    /**
     * Get current request count for a key
     */
    public long getCurrentCount(String key, int windowSeconds) {
        String redisKey = RATE_LIMIT_PREFIX + key;
        long now = Instant.now().toEpochMilli();
        long windowStart = now - (windowSeconds * 1000L);

        try {
            // Remove old entries first
            redisTemplate.opsForZSet().removeRangeByScore(redisKey, 0, windowStart);
            Long count = redisTemplate.opsForZSet().zCard(redisKey);
            return count != null ? count : 0;
        } catch (Exception e) {
            log.error("Failed to get rate limit count: {}", e.getMessage());
            return 0;
        }
    }
}
