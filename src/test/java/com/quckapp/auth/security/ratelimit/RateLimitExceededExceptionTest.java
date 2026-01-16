package com.quckapp.auth.security.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for RateLimitExceededException
 */
class RateLimitExceededExceptionTest {

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("should create exception with message and retry after")
        void shouldCreateWithMessageAndRetryAfter() {
            RateLimitExceededException exception =
                    new RateLimitExceededException("Custom message", 60);

            assertThat(exception.getMessage()).isEqualTo("Custom message");
            assertThat(exception.getRetryAfterSeconds()).isEqualTo(60);
            assertThat(exception.getLimitType()).isEqualTo("api");
            assertThat(exception.isBlocked()).isFalse();
        }

        @Test
        @DisplayName("should create exception with all parameters")
        void shouldCreateWithAllParameters() {
            RateLimitExceededException exception =
                    new RateLimitExceededException("Blocked message", 900, "login", true);

            assertThat(exception.getMessage()).isEqualTo("Blocked message");
            assertThat(exception.getRetryAfterSeconds()).isEqualTo(900);
            assertThat(exception.getLimitType()).isEqualTo("login");
            assertThat(exception.isBlocked()).isTrue();
        }
    }

    @Nested
    @DisplayName("Factory method tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("should create API limit exception")
        void shouldCreateApiLimitException() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(45);

            assertThat(exception.getMessage()).contains("API rate limit exceeded");
            assertThat(exception.getRetryAfterSeconds()).isEqualTo(45);
            assertThat(exception.getLimitType()).isEqualTo("api");
            assertThat(exception.isBlocked()).isFalse();
        }

        @Test
        @DisplayName("should create login limit exception")
        void shouldCreateLoginLimitException() {
            RateLimitExceededException exception = RateLimitExceededException.loginLimit(120);

            assertThat(exception.getMessage()).contains("Too many login attempts");
            assertThat(exception.getRetryAfterSeconds()).isEqualTo(120);
            assertThat(exception.getLimitType()).isEqualTo("login");
            assertThat(exception.isBlocked()).isFalse();
        }

        @Test
        @DisplayName("should create login blocked exception")
        void shouldCreateLoginBlockedException() {
            RateLimitExceededException exception = RateLimitExceededException.loginBlocked(900);

            assertThat(exception.getMessage()).contains("Account temporarily locked");
            assertThat(exception.getRetryAfterSeconds()).isEqualTo(900);
            assertThat(exception.getLimitType()).isEqualTo("login");
            assertThat(exception.isBlocked()).isTrue();
        }

        @Test
        @DisplayName("should create IP limit exception")
        void shouldCreateIpLimitException() {
            RateLimitExceededException exception = RateLimitExceededException.ipLimit(60);

            assertThat(exception.getMessage()).contains("Too many requests from this IP");
            assertThat(exception.getRetryAfterSeconds()).isEqualTo(60);
            assertThat(exception.getLimitType()).isEqualTo("ip");
            assertThat(exception.isBlocked()).isFalse();
        }
    }

    @Nested
    @DisplayName("Inheritance tests")
    class InheritanceTests {

        @Test
        @DisplayName("should be a RuntimeException")
        void shouldBeRuntimeException() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(30);

            assertThat(exception).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("should preserve stack trace")
        void shouldPreserveStackTrace() {
            RateLimitExceededException exception = RateLimitExceededException.loginLimit(60);

            assertThat(exception.getStackTrace()).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Edge cases tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("should handle zero retry after")
        void shouldHandleZeroRetryAfter() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(0);

            assertThat(exception.getRetryAfterSeconds()).isEqualTo(0);
        }

        @Test
        @DisplayName("should handle large retry after")
        void shouldHandleLargeRetryAfter() {
            long largeValue = 86400L; // 24 hours
            RateLimitExceededException exception = RateLimitExceededException.loginBlocked(largeValue);

            assertThat(exception.getRetryAfterSeconds()).isEqualTo(largeValue);
        }
    }
}
