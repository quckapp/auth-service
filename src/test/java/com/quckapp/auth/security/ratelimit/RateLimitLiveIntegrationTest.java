package com.quckapp.auth.security.ratelimit;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for Rate Limiting using existing local Redis (port 6379)
 *
 * Prerequisites:
 * - Redis must be running on localhost:6379
 * - Run: docker run -d -p 6379:6379 redis:7-alpine
 */
@SpringBootTest(
        properties = {
                "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;MODE=MySQL",
                "spring.datasource.driver-class-name=org.h2.Driver",
                "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.flyway.enabled=false",
                "spring.data.redis.host=localhost",
                "spring.data.redis.port=6379",
                "spring.kafka.bootstrap-servers=localhost:9092",
                "spring.kafka.consumer.auto-offset-reset=earliest",
                "spring.kafka.listener.auto-startup=false",
                // OAuth2 client mock configuration - all providers need mock values
                "spring.security.oauth2.client.registration.google.client-id=test-google-client-id",
                "spring.security.oauth2.client.registration.google.client-secret=test-google-client-secret",
                "spring.security.oauth2.client.registration.apple.client-id=test-apple-client-id",
                "spring.security.oauth2.client.registration.apple.client-secret=test-apple-client-secret",
                "spring.security.oauth2.client.registration.facebook.client-id=test-facebook-client-id",
                "spring.security.oauth2.client.registration.facebook.client-secret=test-facebook-client-secret",
                "spring.security.oauth2.client.registration.github.client-id=test-github-client-id",
                "spring.security.oauth2.client.registration.github.client-secret=test-github-client-secret",
                // Rate limiting configuration
                "security.rate-limit.enabled=true",
                "security.rate-limit.login.max-attempts=5",
                "security.rate-limit.login.window-seconds=300",
                "security.rate-limit.login.block-duration-seconds=900",
                "security.rate-limit.ip.enabled=true",
                "security.rate-limit.ip.requests-per-minute=60",
                "security.jwt.secret=test-secret-key-for-integration-tests-must-be-at-least-256-bits-long",
                "security.jwt.access-token-expiration=900000",
                "security.jwt.refresh-token-expiration=604800000"
        }
)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("integration")
class RateLimitLiveIntegrationTest {

    @Autowired
    private RateLimitService rateLimitService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private RateLimitConfig config;

    @BeforeEach
    void setUp() {
        // Clear test keys before each test
        try {
            redisTemplate.keys("ratelimit:test:*").forEach(redisTemplate::delete);
            redisTemplate.keys("login:*test*").forEach(redisTemplate::delete);
        } catch (Exception e) {
            Assumptions.assumeTrue(false, "Redis not available: " + e.getMessage());
        }
    }

    @Nested
    @DisplayName("Basic rate limiting tests")
    class BasicRateLimitingTests {

        @Test
        @DisplayName("should allow requests under limit")
        void shouldAllowUnderLimit() {
            for (int i = 0; i < 5; i++) {
                RateLimitResult result = rateLimitService.checkRateLimit("test:basic:" + System.nanoTime(), 10, 60);
                assertThat(result.isAllowed()).isTrue();
            }
        }

        @Test
        @DisplayName("should deny requests over limit")
        void shouldDenyOverLimit() {
            String key = "test:deny:" + System.nanoTime();

            // Fill up the limit
            for (int i = 0; i < 5; i++) {
                rateLimitService.checkRateLimit(key, 5, 60);
            }

            // Next request should be denied
            RateLimitResult result = rateLimitService.checkRateLimit(key, 5, 60);
            assertThat(result.isAllowed()).isFalse();
            assertThat(result.isDenied()).isTrue();
            assertThat(result.getRetryAfterSeconds()).isGreaterThan(0);
        }

        @Test
        @DisplayName("should track remaining count accurately")
        void shouldTrackRemainingAccurately() {
            String key = "test:count:" + System.nanoTime();
            int limit = 10;

            for (int i = 0; i < limit; i++) {
                RateLimitResult result = rateLimitService.checkRateLimit(key, limit, 60);
                assertThat(result.isAllowed()).isTrue();
                assertThat(result.getRemaining()).isLessThanOrEqualTo(limit - i);
            }
        }
    }

    @Nested
    @DisplayName("API rate limiting tests")
    class ApiRateLimitingTests {

        @Test
        @DisplayName("should apply API rate limits")
        void shouldApplyApiRateLimits() {
            String userId = "test-user-api-" + System.nanoTime();

            RateLimitResult result = rateLimitService.checkApiRateLimit(userId);

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(config.getApi().getRequestsPerMinute() - 1);
        }
    }

    @Nested
    @DisplayName("IP rate limiting tests")
    class IpRateLimitingTests {

        @Test
        @DisplayName("should apply IP rate limits")
        void shouldApplyIpRateLimits() {
            String ipAddress = "test.203.0.113." + (System.nanoTime() % 255);

            RateLimitResult result = rateLimitService.checkIpRateLimit(ipAddress);

            assertThat(result.isAllowed()).isTrue();
        }

        @Test
        @DisplayName("should rate limit different IPs independently")
        void shouldRateLimitIpsIndependently() {
            String ip1 = "test.192.168.1." + (System.nanoTime() % 255);
            String ip2 = "test.192.168.2." + (System.nanoTime() % 255);

            // Exhaust limit for IP1
            for (int i = 0; i < config.getIp().getRequestsPerMinute(); i++) {
                rateLimitService.checkIpRateLimit(ip1);
            }

            // IP1 should be denied
            RateLimitResult result1 = rateLimitService.checkIpRateLimit(ip1);
            assertThat(result1.isDenied()).isTrue();

            // IP2 should still be allowed
            RateLimitResult result2 = rateLimitService.checkIpRateLimit(ip2);
            assertThat(result2.isAllowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("Login rate limiting tests")
    class LoginRateLimitingTests {

        @Test
        @DisplayName("should allow login attempts under limit")
        void shouldAllowLoginUnderLimit() {
            String email = "test" + System.nanoTime() + "@example.com";
            String ip = "192.168.1.1";

            RateLimitResult result = rateLimitService.checkLoginRateLimit(email, ip);

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.isBlocked()).isFalse();
        }

        @Test
        @DisplayName("should block after max failed attempts")
        void shouldBlockAfterMaxAttempts() {
            String email = "test-block" + System.nanoTime() + "@example.com";
            String ip = "10.0.0.1";

            // Record max failed attempts
            for (int i = 0; i < config.getLogin().getMaxAttempts(); i++) {
                rateLimitService.recordFailedLogin(email, ip);
            }

            // Should now be blocked
            RateLimitResult result = rateLimitService.checkLoginRateLimit(email, ip);
            assertThat(result.isBlocked()).isTrue();
            assertThat(result.getRetryAfterSeconds()).isGreaterThan(0);
        }

        @Test
        @DisplayName("should check if login is blocked")
        void shouldCheckIfBlocked() {
            String email = "test-blocked" + System.nanoTime() + "@example.com";

            // Block the login
            rateLimitService.blockLogin(email);

            // Verify blocked
            assertThat(rateLimitService.isLoginBlocked(email)).isTrue();
            assertThat(rateLimitService.getBlockTimeRemaining(email))
                    .isGreaterThan(0)
                    .isLessThanOrEqualTo(config.getLogin().getBlockDurationSeconds());

            // Cleanup
            rateLimitService.unblockLogin(email);
        }

        @Test
        @DisplayName("should clear login attempts")
        void shouldClearLoginAttempts() {
            String email = "test-clear" + System.nanoTime() + "@example.com";
            String ip = "192.168.1.100";

            // Record some attempts
            rateLimitService.recordFailedLogin(email, ip);
            rateLimitService.recordFailedLogin(email, ip);

            // Clear attempts
            rateLimitService.clearLoginAttempts(email, ip);

            // Should have full quota again
            RateLimitResult result = rateLimitService.checkLoginRateLimit(email, ip);
            assertThat(result.isAllowed()).isTrue();
        }

        @Test
        @DisplayName("should unblock login")
        void shouldUnblockLogin() {
            String email = "test-unblock" + System.nanoTime() + "@example.com";

            // Block then unblock
            rateLimitService.blockLogin(email);
            assertThat(rateLimitService.isLoginBlocked(email)).isTrue();

            rateLimitService.unblockLogin(email);
            assertThat(rateLimitService.isLoginBlocked(email)).isFalse();
        }
    }

    @Nested
    @DisplayName("Concurrent request tests")
    class ConcurrentRequestTests {

        @Test
        @DisplayName("should handle concurrent requests correctly")
        void shouldHandleConcurrentRequests() throws InterruptedException {
            String key = "test:concurrent:" + System.nanoTime();
            int limit = 20;
            int threads = 50;

            AtomicInteger allowed = new AtomicInteger(0);
            AtomicInteger denied = new AtomicInteger(0);
            CountDownLatch latch = new CountDownLatch(threads);
            ExecutorService executor = Executors.newFixedThreadPool(10);

            for (int i = 0; i < threads; i++) {
                executor.submit(() -> {
                    try {
                        RateLimitResult result = rateLimitService.checkRateLimit(key, limit, 60);
                        if (result.isAllowed()) {
                            allowed.incrementAndGet();
                        } else {
                            denied.incrementAndGet();
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await(10, TimeUnit.SECONDS);
            executor.shutdown();

            // Should have exactly 'limit' allowed and rest denied
            assertThat(allowed.get()).isEqualTo(limit);
            assertThat(denied.get()).isEqualTo(threads - limit);
        }
    }

    @Nested
    @DisplayName("Administrative operations tests")
    class AdminOperationsTests {

        @Test
        @DisplayName("should reset rate limit")
        void shouldResetRateLimit() {
            String key = "test:reset:" + System.nanoTime();

            // Use up some of the limit
            for (int i = 0; i < 5; i++) {
                rateLimitService.checkRateLimit(key, 10, 60);
            }

            // Verify some requests were made
            assertThat(rateLimitService.getCurrentCount(key, 60)).isEqualTo(5);

            // Reset the limit
            rateLimitService.resetRateLimit(key);

            // Count should be zero after reset
            assertThat(rateLimitService.getCurrentCount(key, 60)).isEqualTo(0);
        }

        @Test
        @DisplayName("should get current count accurately")
        void shouldGetCurrentCount() {
            String key = "test:count:" + System.nanoTime();

            // Make some requests
            rateLimitService.checkRateLimit(key, 100, 60);
            rateLimitService.checkRateLimit(key, 100, 60);
            rateLimitService.checkRateLimit(key, 100, 60);

            long count = rateLimitService.getCurrentCount(key, 60);
            assertThat(count).isEqualTo(3);
        }
    }

    @Nested
    @DisplayName("Sliding window tests")
    class SlidingWindowTests {

        @Test
        @DisplayName("should use sliding window correctly")
        void shouldUseSlidingWindow() {
            String key = "test:sliding:" + System.nanoTime();
            int limit = 5;
            int windowSeconds = 2; // Short window for testing

            // Fill up the limit
            for (int i = 0; i < limit; i++) {
                RateLimitResult result = rateLimitService.checkRateLimit(key, limit, windowSeconds);
                assertThat(result.isAllowed()).isTrue();
            }

            // Should be denied
            RateLimitResult denied = rateLimitService.checkRateLimit(key, limit, windowSeconds);
            assertThat(denied.isDenied()).isTrue();

            // Wait for window to expire
            try {
                Thread.sleep((windowSeconds + 1) * 1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Should be allowed again
            RateLimitResult allowed = rateLimitService.checkRateLimit(key, limit, windowSeconds);
            assertThat(allowed.isAllowed()).isTrue();
        }
    }
}
