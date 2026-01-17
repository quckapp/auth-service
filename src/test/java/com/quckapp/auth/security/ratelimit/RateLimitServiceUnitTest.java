package com.quckapp.auth.security.ratelimit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RateLimitService with mocked dependencies
 * Tests exception handling and edge cases
 */
@ExtendWith(MockitoExtension.class)
class RateLimitServiceUnitTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ZSetOperations<String, String> zSetOperations;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private RedisConnectionFactory connectionFactory;

    @Mock
    private RedisConnection redisConnection;

    private RateLimitConfig config;
    private RateLimitService rateLimitService;

    @BeforeEach
    void setUp() {
        config = createDefaultConfig();
        rateLimitService = new RateLimitService(redisTemplate, config);
    }

    private RateLimitConfig createDefaultConfig() {
        RateLimitConfig cfg = new RateLimitConfig();
        cfg.setEnabled(true);

        RateLimitConfig.LoginRateLimit login = new RateLimitConfig.LoginRateLimit();
        login.setMaxAttempts(5);
        login.setWindowSeconds(300);
        login.setBlockDurationSeconds(900);
        cfg.setLogin(login);

        RateLimitConfig.ApiRateLimit api = new RateLimitConfig.ApiRateLimit();
        api.setRequestsPerMinute(100);
        cfg.setApi(api);

        RateLimitConfig.IpRateLimit ip = new RateLimitConfig.IpRateLimit();
        ip.setEnabled(true);
        ip.setRequestsPerMinute(60);
        cfg.setIp(ip);

        return cfg;
    }

    @Nested
    @DisplayName("Exception handling tests")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("should fail open when Redis throws exception in checkRateLimit")
        void shouldFailOpenWhenRedisThrows() {
            when(redisTemplate.execute(any(RedisScript.class), anyList(), any()))
                    .thenThrow(new RuntimeException("Redis connection failed"));

            RateLimitResult result = rateLimitService.checkRateLimit("test-key", 10, 60);

            // Should fail open - allow the request
            assertThat(result.isAllowed()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(10);
        }

        @Test
        @DisplayName("should handle exception in recordFailedLogin gracefully")
        void shouldHandleExceptionInRecordFailedLogin() {
            when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
            when(zSetOperations.add(anyString(), anyString(), anyDouble()))
                    .thenThrow(new RuntimeException("Redis error"));

            // Should not throw exception - logs and continues
            rateLimitService.recordFailedLogin("test@example.com", "192.168.1.1");

            // Verify the method was called but exception was handled
            verify(zSetOperations).add(anyString(), anyString(), anyDouble());
        }

        @Test
        @DisplayName("should return 0 when getCurrentCount throws exception")
        void shouldReturnZeroWhenGetCurrentCountFails() {
            when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
            when(zSetOperations.removeRangeByScore(anyString(), anyDouble(), anyDouble()))
                    .thenThrow(new RuntimeException("Redis error"));

            long count = rateLimitService.getCurrentCount("test-key", 60);

            assertThat(count).isEqualTo(0);
        }
    }


    @Nested
    @DisplayName("Login block with TTL tests")
    class LoginBlockTTLTests {

        @Test
        @DisplayName("should return configured block duration when TTL is null")
        void shouldReturnConfiguredDurationWhenTTLNull() {
            when(redisTemplate.hasKey(anyString())).thenReturn(true);
            when(redisTemplate.getExpire(anyString())).thenReturn(null);

            RateLimitResult result = rateLimitService.checkLoginRateLimit("blocked@test.com", "192.168.1.1");

            assertThat(result.isBlocked()).isTrue();
            assertThat(result.getRetryAfterSeconds()).isEqualTo(900); // configured block duration
        }

        @Test
        @DisplayName("should return actual TTL when available")
        void shouldReturnActualTTLWhenAvailable() {
            when(redisTemplate.hasKey(anyString())).thenReturn(true);
            when(redisTemplate.getExpire(anyString())).thenReturn(500L);

            RateLimitResult result = rateLimitService.checkLoginRateLimit("blocked@test.com", "192.168.1.1");

            assertThat(result.isBlocked()).isTrue();
            assertThat(result.getRetryAfterSeconds()).isEqualTo(500);
        }
    }

    @Nested
    @DisplayName("Record failed login edge cases")
    class RecordFailedLoginEdgeCasesTests {

        @Test
        @DisplayName("should block login when count reaches max attempts")
        void shouldBlockWhenCountReachesMax() {
            when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
            when(zSetOperations.add(anyString(), anyString(), anyDouble())).thenReturn(true);
            when(redisTemplate.expire(anyString(), any())).thenReturn(true);
            when(zSetOperations.zCard(anyString())).thenReturn(5L); // equals maxAttempts

            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            doNothing().when(valueOperations).set(anyString(), anyString(), any());

            rateLimitService.recordFailedLogin("toblock@test.com", "192.168.1.1");

            // Verify block was called
            verify(valueOperations).set(contains("login:blocked:"), eq("blocked"), any());
        }

        @Test
        @DisplayName("should not block when count is below max attempts")
        void shouldNotBlockWhenCountBelowMax() {
            when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
            when(zSetOperations.add(anyString(), anyString(), anyDouble())).thenReturn(true);
            when(redisTemplate.expire(anyString(), any())).thenReturn(true);
            when(zSetOperations.zCard(anyString())).thenReturn(3L); // below maxAttempts

            rateLimitService.recordFailedLogin("safe@test.com", "192.168.1.1");

            // Verify block was NOT called
            verify(redisTemplate, never()).opsForValue();
        }

        @Test
        @DisplayName("should handle null count in recordFailedLogin")
        void shouldHandleNullCountInRecordFailedLogin() {
            when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
            when(zSetOperations.add(anyString(), anyString(), anyDouble())).thenReturn(true);
            when(redisTemplate.expire(anyString(), any())).thenReturn(true);
            when(zSetOperations.zCard(anyString())).thenReturn(null);

            // Should not throw and should not block
            rateLimitService.recordFailedLogin("nullcount@test.com", "192.168.1.1");

            // Verify block was NOT called
            verify(redisTemplate, never()).opsForValue();
        }
    }

    @Nested
    @DisplayName("Get current count edge cases")
    class GetCurrentCountEdgeCasesTests {

        @Test
        @DisplayName("should return 0 when zCard returns null")
        void shouldReturnZeroWhenZCardNull() {
            when(redisTemplate.opsForZSet()).thenReturn(zSetOperations);
            when(zSetOperations.removeRangeByScore(anyString(), anyDouble(), anyDouble())).thenReturn(0L);
            when(zSetOperations.zCard(anyString())).thenReturn(null);

            long count = rateLimitService.getCurrentCount("test-key", 60);

            assertThat(count).isEqualTo(0);
        }
    }
}
