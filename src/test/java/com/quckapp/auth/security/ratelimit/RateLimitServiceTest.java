package com.quckapp.auth.security.ratelimit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for RateLimitService using Redis
 * Requires Redis to be running at localhost:6379 (use docker-compose to start infrastructure)
 */
class RateLimitServiceTest {

    private StringRedisTemplate redisTemplate;
    private RateLimitConfig config;
    private RateLimitService rateLimitService;
    private LettuceConnectionFactory connectionFactory;

    @BeforeEach
    void setUp() {
        config = createDefaultConfig();

        // Connect to local Redis (started via docker-compose)
        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration("localhost", 6379);
        redisConfig.setPassword("redis_secret");
        connectionFactory = new LettuceConnectionFactory(redisConfig);
        connectionFactory.afterPropertiesSet();

        try {
            redisTemplate = new StringRedisTemplate(connectionFactory);
            redisTemplate.afterPropertiesSet();

            // Clear test keys before each test
            redisTemplate.getConnectionFactory().getConnection().flushAll();

            rateLimitService = new RateLimitService(redisTemplate, config);
        } catch (Exception e) {
            assumeTrue(false, "Redis not available at localhost:6379. Start infrastructure with: cd infrastructure/docker && docker compose -f docker-compose.infra.yml up -d redis");
        }
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
    @DisplayName("checkRateLimit tests")
    class CheckRateLimitTests {

        @Test
        @DisplayName("should allow request when rate limiting is disabled")
        void shouldAllowWhenDisabled() {
            config.setEnabled(false);
            rateLimitService = new RateLimitService(redisTemplate, config);

            RateLimitResult result = rateLimitService.checkRateLimit("test-key", 10, 60);

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(10);
        }

        @Test
        @DisplayName("should allow request when under limit")
        void shouldAllowWhenUnderLimit() {
            RateLimitResult result = rateLimitService.checkRateLimit("test-key", 10, 60);

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.getRemaining()).isGreaterThanOrEqualTo(9);
        }

        @Test
        @DisplayName("should deny request when limit exceeded")
        void shouldDenyWhenLimitExceeded() {
            // Make 3 requests with limit of 2
            rateLimitService.checkRateLimit("exceeded-key", 2, 60);
            rateLimitService.checkRateLimit("exceeded-key", 2, 60);
            RateLimitResult result = rateLimitService.checkRateLimit("exceeded-key", 2, 60);

            assertThat(result.isAllowed()).isFalse();
            assertThat(result.isDenied()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("checkApiRateLimit tests")
    class CheckApiRateLimitTests {

        @Test
        @DisplayName("should check API rate limit with configured values")
        void shouldCheckWithConfiguredValues() {
            RateLimitResult result = rateLimitService.checkApiRateLimit("user123");

            assertThat(result.isAllowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("checkIpRateLimit tests")
    class CheckIpRateLimitTests {

        @Test
        @DisplayName("should check IP rate limit")
        void shouldCheckIpRateLimit() {
            RateLimitResult result = rateLimitService.checkIpRateLimit("192.168.1.1");

            assertThat(result.isAllowed()).isTrue();
        }

        @Test
        @DisplayName("should skip IP rate limiting when disabled")
        void shouldSkipWhenDisabled() {
            config.getIp().setEnabled(false);
            rateLimitService = new RateLimitService(redisTemplate, config);

            RateLimitResult result = rateLimitService.checkIpRateLimit("192.168.1.1");

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(60);
        }
    }

    @Nested
    @DisplayName("Login rate limiting tests")
    class LoginRateLimitTests {

        @Test
        @DisplayName("should allow login when user is not blocked")
        void shouldAllowWhenNotBlocked() {
            RateLimitResult result = rateLimitService.checkLoginRateLimit("user@test.com", "192.168.1.1");

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.isBlocked()).isFalse();
        }

        @Test
        @DisplayName("should record failed login attempt")
        void shouldRecordFailedLogin() {
            rateLimitService.recordFailedLogin("user@test.com", "192.168.1.1");

            long count = rateLimitService.getCurrentCount("login:attempt:user@test.com:192.168.1.1", 300);
            assertThat(count).isGreaterThanOrEqualTo(1);
        }

        @Test
        @DisplayName("should block user after max failed attempts")
        void shouldBlockAfterMaxAttempts() {
            String email = "blocked@test.com";
            String ip = "10.0.0.1";

            // Record 5 failed attempts (max is 5)
            for (int i = 0; i < 5; i++) {
                rateLimitService.recordFailedLogin(email, ip);
            }

            boolean blocked = rateLimitService.isLoginBlocked(email);
            assertThat(blocked).isTrue();
        }

        @Test
        @DisplayName("should clear login attempts on success")
        void shouldClearLoginAttempts() {
            String email = "clear@test.com";
            String ip = "10.0.0.2";

            rateLimitService.recordFailedLogin(email, ip);
            rateLimitService.clearLoginAttempts(email, ip);

            long count = rateLimitService.getCurrentCount("login:attempt:" + email + ":" + ip, 300);
            assertThat(count).isEqualTo(0);
        }

        @Test
        @DisplayName("should unblock login")
        void shouldUnblockLogin() {
            String email = "unblock@test.com";
            String ip = "10.0.0.3";

            // Block the user
            for (int i = 0; i < 5; i++) {
                rateLimitService.recordFailedLogin(email, ip);
            }
            assertThat(rateLimitService.isLoginBlocked(email)).isTrue();

            // Unblock
            rateLimitService.unblockLogin(email);

            assertThat(rateLimitService.isLoginBlocked(email)).isFalse();
        }

        @Test
        @DisplayName("should check if login is blocked")
        void shouldCheckIfBlocked() {
            String email = "checkblock@test.com";

            // Initially not blocked
            assertThat(rateLimitService.isLoginBlocked(email)).isFalse();
        }
    }

    @Nested
    @DisplayName("Administrative operations tests")
    class AdminOperationsTests {

        @Test
        @DisplayName("should reset rate limit")
        void shouldResetRateLimit() {
            // Make some requests
            rateLimitService.checkApiRateLimit("resetuser");
            rateLimitService.checkApiRateLimit("resetuser");

            // Reset
            rateLimitService.resetRateLimit("api:resetuser");

            // Count should be 0 or test passes if reset worked
            long count = rateLimitService.getCurrentCount("api:resetuser", 60);
            assertThat(count).isEqualTo(0);
        }

        @Test
        @DisplayName("should get current count")
        void shouldGetCurrentCount() {
            String key = "count-test";
            rateLimitService.checkRateLimit(key, 100, 60);
            rateLimitService.checkRateLimit(key, 100, 60);
            rateLimitService.checkRateLimit(key, 100, 60);

            long count = rateLimitService.getCurrentCount(key, 60);

            assertThat(count).isEqualTo(3);
        }
    }
}
