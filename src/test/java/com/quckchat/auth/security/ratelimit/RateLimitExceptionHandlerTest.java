package com.quckapp.auth.security.ratelimit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for RateLimitExceptionHandler
 */
class RateLimitExceptionHandlerTest {

    private RateLimitExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new RateLimitExceptionHandler();
    }

    @Nested
    @DisplayName("handleRateLimitExceeded tests")
    class HandleRateLimitExceededTests {

        @Test
        @DisplayName("should return 429 status code")
        void shouldReturn429StatusCode() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(60);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        @Test
        @DisplayName("should include rate_limit_exceeded error for non-blocked")
        void shouldIncludeRateLimitExceededError() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(30);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("error")).isEqualTo("rate_limit_exceeded");
        }

        @Test
        @DisplayName("should include account_blocked error for blocked")
        void shouldIncludeAccountBlockedError() {
            RateLimitExceededException exception = RateLimitExceededException.loginBlocked(900);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("error")).isEqualTo("account_blocked");
        }

        @Test
        @DisplayName("should include message in response body")
        void shouldIncludeMessage() {
            RateLimitExceededException exception =
                    new RateLimitExceededException("Custom error message", 60);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("message")).isEqualTo("Custom error message");
        }

        @Test
        @DisplayName("should include retryAfter in response body")
        void shouldIncludeRetryAfter() {
            RateLimitExceededException exception = RateLimitExceededException.ipLimit(45);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("retryAfter")).isEqualTo(45L);
        }

        @Test
        @DisplayName("should include limitType in response body")
        void shouldIncludeLimitType() {
            RateLimitExceededException exception = RateLimitExceededException.loginLimit(120);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("limitType")).isEqualTo("login");
        }

        @Test
        @DisplayName("should include Retry-After header")
        void shouldIncludeRetryAfterHeader() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(60);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("60");
        }

        @Test
        @DisplayName("should include X-RateLimit-Reset header")
        void shouldIncludeRateLimitResetHeader() {
            RateLimitExceededException exception = RateLimitExceededException.ipLimit(90);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getHeaders().getFirst("X-RateLimit-Reset")).isEqualTo("90");
        }
    }

    @Nested
    @DisplayName("Different exception types tests")
    class DifferentExceptionTypesTests {

        @Test
        @DisplayName("should handle API limit exception")
        void shouldHandleApiLimitException() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(60);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("limitType")).isEqualTo("api");
            assertThat(response.getBody().get("error")).isEqualTo("rate_limit_exceeded");
        }

        @Test
        @DisplayName("should handle login limit exception")
        void shouldHandleLoginLimitException() {
            RateLimitExceededException exception = RateLimitExceededException.loginLimit(120);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("limitType")).isEqualTo("login");
            assertThat(response.getBody().get("error")).isEqualTo("rate_limit_exceeded");
        }

        @Test
        @DisplayName("should handle login blocked exception")
        void shouldHandleLoginBlockedException() {
            RateLimitExceededException exception = RateLimitExceededException.loginBlocked(900);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("limitType")).isEqualTo("login");
            assertThat(response.getBody().get("error")).isEqualTo("account_blocked");
        }

        @Test
        @DisplayName("should handle IP limit exception")
        void shouldHandleIpLimitException() {
            RateLimitExceededException exception = RateLimitExceededException.ipLimit(30);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("limitType")).isEqualTo("ip");
            assertThat(response.getBody().get("error")).isEqualTo("rate_limit_exceeded");
        }
    }

    @Nested
    @DisplayName("Response body structure tests")
    class ResponseBodyStructureTests {

        @Test
        @DisplayName("should contain all required fields")
        void shouldContainAllRequiredFields() {
            RateLimitExceededException exception = RateLimitExceededException.apiLimit(60);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsKeys("error", "message", "retryAfter", "limitType");
        }

        @Test
        @DisplayName("should return correct types for all fields")
        void shouldReturnCorrectTypes() {
            RateLimitExceededException exception = RateLimitExceededException.loginBlocked(900);

            ResponseEntity<Map<String, Object>> response = handler.handleRateLimitExceeded(exception);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("error")).isInstanceOf(String.class);
            assertThat(response.getBody().get("message")).isInstanceOf(String.class);
            assertThat(response.getBody().get("retryAfter")).isInstanceOf(Long.class);
            assertThat(response.getBody().get("limitType")).isInstanceOf(String.class);
        }
    }
}
