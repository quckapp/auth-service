package com.quckapp.auth.security.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for RateLimitResult
 */
class RateLimitResultTest {

    @Nested
    @DisplayName("Factory method tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("should create allowed result")
        void shouldCreateAllowedResult() {
            RateLimitResult result = RateLimitResult.allowed(10);

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.isDenied()).isFalse();
            assertThat(result.isBlocked()).isFalse();
            assertThat(result.getRemaining()).isEqualTo(10);
            assertThat(result.getRetryAfterSeconds()).isEqualTo(0);
        }

        @Test
        @DisplayName("should create exceeded result")
        void shouldCreateExceededResult() {
            RateLimitResult result = RateLimitResult.exceeded(60);

            assertThat(result.isAllowed()).isFalse();
            assertThat(result.isDenied()).isTrue();
            assertThat(result.isBlocked()).isFalse();
            assertThat(result.getRemaining()).isEqualTo(0);
            assertThat(result.getRetryAfterSeconds()).isEqualTo(60);
        }

        @Test
        @DisplayName("should create blocked result")
        void shouldCreateBlockedResult() {
            RateLimitResult result = RateLimitResult.blocked(900);

            assertThat(result.isAllowed()).isFalse();
            assertThat(result.isDenied()).isTrue();
            assertThat(result.isBlocked()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(0);
            assertThat(result.getRetryAfterSeconds()).isEqualTo(900);
        }
    }

    @Nested
    @DisplayName("isDenied tests")
    class IsDeniedTests {

        @Test
        @DisplayName("isDenied should be opposite of isAllowed")
        void shouldBeOppositeOfAllowed() {
            RateLimitResult allowed = RateLimitResult.allowed(5);
            assertThat(allowed.isDenied()).isEqualTo(!allowed.isAllowed());

            RateLimitResult exceeded = RateLimitResult.exceeded(30);
            assertThat(exceeded.isDenied()).isEqualTo(!exceeded.isAllowed());

            RateLimitResult blocked = RateLimitResult.blocked(600);
            assertThat(blocked.isDenied()).isEqualTo(!blocked.isAllowed());
        }
    }

    @Nested
    @DisplayName("getHeaders tests")
    class GetHeadersTests {

        @Test
        @DisplayName("should return correct headers for allowed result")
        void shouldReturnHeadersForAllowed() {
            RateLimitResult result = RateLimitResult.allowed(45);

            Map<String, String> headers = result.getHeaders(60);

            assertThat(headers).containsEntry("X-RateLimit-Limit", "60");
            assertThat(headers).containsEntry("X-RateLimit-Remaining", "45");
            assertThat(headers).doesNotContainKey("X-RateLimit-Reset");
            assertThat(headers).doesNotContainKey("Retry-After");
        }

        @Test
        @DisplayName("should return correct headers for exceeded result")
        void shouldReturnHeadersForExceeded() {
            RateLimitResult result = RateLimitResult.exceeded(30);

            Map<String, String> headers = result.getHeaders(100);

            assertThat(headers).containsEntry("X-RateLimit-Limit", "100");
            assertThat(headers).containsEntry("X-RateLimit-Remaining", "0");
            assertThat(headers).containsEntry("X-RateLimit-Reset", "30");
            assertThat(headers).containsEntry("Retry-After", "30");
        }

        @Test
        @DisplayName("should return correct headers for blocked result")
        void shouldReturnHeadersForBlocked() {
            RateLimitResult result = RateLimitResult.blocked(900);

            Map<String, String> headers = result.getHeaders(5);

            assertThat(headers).containsEntry("X-RateLimit-Limit", "5");
            assertThat(headers).containsEntry("X-RateLimit-Remaining", "0");
            assertThat(headers).containsEntry("X-RateLimit-Reset", "900");
            assertThat(headers).containsEntry("Retry-After", "900");
        }
    }

    @Nested
    @DisplayName("Edge case tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("should handle zero remaining")
        void shouldHandleZeroRemaining() {
            RateLimitResult result = RateLimitResult.allowed(0);

            assertThat(result.isAllowed()).isTrue();
            assertThat(result.getRemaining()).isEqualTo(0);
        }

        @Test
        @DisplayName("should handle zero retry after")
        void shouldHandleZeroRetryAfter() {
            RateLimitResult result = RateLimitResult.exceeded(0);

            assertThat(result.isDenied()).isTrue();
            assertThat(result.getRetryAfterSeconds()).isEqualTo(0);
        }

        @Test
        @DisplayName("should handle large retry after values")
        void shouldHandleLargeRetryAfter() {
            long largeValue = 86400L; // 24 hours
            RateLimitResult result = RateLimitResult.blocked(largeValue);

            assertThat(result.getRetryAfterSeconds()).isEqualTo(largeValue);
        }
    }
}
