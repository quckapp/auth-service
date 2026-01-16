package com.quckapp.auth.security.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for RateLimitFilter using a fake RateLimitService
 */
class RateLimitFilterTest {

    private RateLimitConfig config;
    private ObjectMapper objectMapper;
    private RateLimitFilter filter;
    private FakeRateLimitService fakeRateLimitService;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        config = createDefaultConfig();
        objectMapper = new ObjectMapper();
        fakeRateLimitService = new FakeRateLimitService();
        filter = new RateLimitFilter(fakeRateLimitService, config, objectMapper);
        filterChain = new MockFilterChain();
    }

    private RateLimitConfig createDefaultConfig() {
        RateLimitConfig cfg = new RateLimitConfig();
        cfg.setEnabled(true);

        RateLimitConfig.IpRateLimit ip = new RateLimitConfig.IpRateLimit();
        ip.setEnabled(true);
        ip.setRequestsPerMinute(60);
        cfg.setIp(ip);

        return cfg;
    }

    /**
     * Simple mock FilterChain that tracks if doFilter was called
     */
    static class MockFilterChain implements FilterChain {
        boolean filterCalled = false;

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response)
                throws IOException, ServletException {
            filterCalled = true;
        }

        boolean wasFilterCalled() {
            return filterCalled;
        }

        void reset() {
            filterCalled = false;
        }
    }

    /**
     * Fake RateLimitOperations for testing
     */
    static class FakeRateLimitService implements RateLimitOperations {
        private RateLimitResult nextResult = RateLimitResult.allowed(60);
        private String lastCheckedIp = null;

        void setNextResult(RateLimitResult result) {
            this.nextResult = result;
        }

        String getLastCheckedIp() {
            return lastCheckedIp;
        }

        @Override
        public RateLimitResult checkIpRateLimit(String ipAddress) {
            this.lastCheckedIp = ipAddress;
            return nextResult;
        }

        @Override
        public RateLimitResult checkRateLimit(String key, int maxRequests, int windowSeconds) {
            return nextResult;
        }

        @Override
        public RateLimitResult checkApiRateLimit(String userId) {
            return nextResult;
        }

        @Override
        public RateLimitResult checkLoginRateLimit(String email, String ipAddress) {
            return nextResult;
        }

        @Override
        public void recordFailedLogin(String email, String ipAddress) {}

        @Override
        public void clearLoginAttempts(String email, String ipAddress) {}

        @Override
        public void blockLogin(String email) {}

        @Override
        public void unblockLogin(String email) {}

        @Override
        public boolean isLoginBlocked(String email) {
            return false;
        }

        @Override
        public long getBlockTimeRemaining(String email) {
            return 0;
        }

        @Override
        public void resetRateLimit(String key) {}

        @Override
        public long getCurrentCount(String key, int windowSeconds) {
            return 0;
        }
    }

    @Nested
    @DisplayName("Filter bypass tests")
    class FilterBypassTests {

        @Test
        @DisplayName("should skip when rate limiting is disabled globally")
        void shouldSkipWhenDisabledGlobally() throws ServletException, IOException {
            config.setEnabled(false);
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(filterChain.wasFilterCalled()).isTrue();
        }

        @Test
        @DisplayName("should skip when IP rate limiting is disabled")
        void shouldSkipWhenIpDisabled() throws ServletException, IOException {
            config.getIp().setEnabled(false);
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(filterChain.wasFilterCalled()).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "/actuator/health",
                "/actuator/info",
                "/health",
                "/v3/api-docs",
                "/v3/api-docs/swagger-config",
                "/swagger-ui",
                "/swagger-ui/index.html"
        })
        @DisplayName("should skip excluded paths")
        void shouldSkipExcludedPaths(String path) throws ServletException, IOException {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(filterChain.wasFilterCalled()).isTrue();
        }
    }

    @Nested
    @DisplayName("Rate limit checking tests")
    class RateLimitCheckingTests {

        @Test
        @DisplayName("should allow request when under limit")
        void shouldAllowWhenUnderLimit() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(55));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(filterChain.wasFilterCalled()).isTrue();
            assertThat(response.getHeader("X-RateLimit-Limit")).isEqualTo("60");
            assertThat(response.getHeader("X-RateLimit-Remaining")).isEqualTo("55");
        }

        @Test
        @DisplayName("should deny request when limit exceeded")
        void shouldDenyWhenLimitExceeded() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.exceeded(45));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(filterChain.wasFilterCalled()).isFalse();
            assertThat(response.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
            assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
            assertThat(response.getHeader("Retry-After")).isEqualTo("45");
            assertThat(response.getHeader("X-RateLimit-Reset")).isEqualTo("45");

            // Verify response body
            @SuppressWarnings("unchecked")
            Map<String, Object> body = objectMapper.readValue(
                    response.getContentAsString(), Map.class);
            assertThat(body.get("error")).isEqualTo("rate_limit_exceeded");
            assertThat(body.get("retryAfter")).isEqualTo(45);
        }

        @Test
        @DisplayName("should add rate limit headers on allowed request")
        void shouldAddHeadersOnAllowedRequest() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(30));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/data");
            request.setRemoteAddr("10.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getHeader("X-RateLimit-Limit")).isEqualTo("60");
            assertThat(response.getHeader("X-RateLimit-Remaining")).isEqualTo("30");
            assertThat(response.getHeader("Retry-After")).isNull();
        }
    }

    @Nested
    @DisplayName("IP extraction tests")
    class IpExtractionTests {

        @Test
        @DisplayName("should extract IP from X-Forwarded-For header")
        void shouldExtractFromXForwardedFor() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(50));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.addHeader("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 192.168.1.1");
            request.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(fakeRateLimitService.getLastCheckedIp()).isEqualTo("203.0.113.50");
        }

        @Test
        @DisplayName("should extract IP from X-Real-IP header when X-Forwarded-For absent")
        void shouldExtractFromXRealIp() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(50));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.addHeader("X-Real-IP", "198.51.100.25");
            request.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(fakeRateLimitService.getLastCheckedIp()).isEqualTo("198.51.100.25");
        }

        @Test
        @DisplayName("should use remote address when no proxy headers")
        void shouldUseRemoteAddr() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(50));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.setRemoteAddr("10.20.30.40");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(fakeRateLimitService.getLastCheckedIp()).isEqualTo("10.20.30.40");
        }

        @Test
        @DisplayName("should prefer X-Forwarded-For over X-Real-IP")
        void shouldPreferXForwardedFor() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(50));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.addHeader("X-Forwarded-For", "203.0.113.50");
            request.addHeader("X-Real-IP", "198.51.100.25");
            request.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(fakeRateLimitService.getLastCheckedIp()).isEqualTo("203.0.113.50");
        }

        @Test
        @DisplayName("should handle empty X-Forwarded-For gracefully")
        void shouldHandleEmptyXForwardedFor() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(50));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.addHeader("X-Forwarded-For", "");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(fakeRateLimitService.getLastCheckedIp()).isEqualTo("192.168.1.1");
        }
    }

    @Nested
    @DisplayName("Response body tests")
    class ResponseBodyTests {

        @Test
        @DisplayName("should return correct JSON structure on rate limit")
        void shouldReturnCorrectJsonStructure() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.exceeded(120));
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/data");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            @SuppressWarnings("unchecked")
            Map<String, Object> body = objectMapper.readValue(
                    response.getContentAsString(), Map.class);

            assertThat(body).containsKeys("error", "message", "retryAfter");
            assertThat(body.get("error")).isEqualTo("rate_limit_exceeded");
            assertThat(body.get("message")).isEqualTo("Too many requests. Please try again later.");
            assertThat(body.get("retryAfter")).isEqualTo(120);
        }
    }

    @Nested
    @DisplayName("Header tests")
    class HeaderTests {

        @Test
        @DisplayName("should set all required headers on rate limit")
        void shouldSetAllHeadersOnRateLimit() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.exceeded(60));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getHeader("X-RateLimit-Limit")).isEqualTo("60");
            assertThat(response.getHeader("X-RateLimit-Remaining")).isEqualTo("0");
            assertThat(response.getHeader("X-RateLimit-Reset")).isEqualTo("60");
            assertThat(response.getHeader("Retry-After")).isEqualTo("60");
        }

        @Test
        @DisplayName("should not set reset headers when allowed")
        void shouldNotSetResetHeadersWhenAllowed() throws ServletException, IOException {
            fakeRateLimitService.setNextResult(RateLimitResult.allowed(45));
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
            request.setRemoteAddr("192.168.1.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilterInternal(request, response, filterChain);

            assertThat(response.getHeader("X-RateLimit-Limit")).isEqualTo("60");
            assertThat(response.getHeader("X-RateLimit-Remaining")).isEqualTo("45");
            assertThat(response.getHeader("X-RateLimit-Reset")).isNull();
            assertThat(response.getHeader("Retry-After")).isNull();
        }
    }
}
