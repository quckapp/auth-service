package com.quckapp.auth.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RateLimitAspect
 */
@ExtendWith(MockitoExtension.class)
class RateLimitAspectTest {

    @Mock
    private RateLimitOperations rateLimitService;

    @Mock
    private ProceedingJoinPoint joinPoint;

    @Mock
    private MethodSignature methodSignature;


    private RateLimitConfig config;
    private RateLimitAspect aspect;

    @BeforeEach
    void setUp() {
        config = new RateLimitConfig();
        config.setEnabled(true);
        aspect = new RateLimitAspect(rateLimitService, config);
    }

    @Nested
    @DisplayName("Rate limit enforcement tests")
    class EnforcementTests {

        @Test
        @DisplayName("should skip rate limiting when disabled")
        void shouldSkipWhenDisabled() throws Throwable {
            config.setEnabled(false);
            when(joinPoint.proceed()).thenReturn("result");

            Object result = aspect.enforceRateLimit(joinPoint);

            assertThat(result).isEqualTo("result");
            verifyNoInteractions(rateLimitService);
        }

        @Test
        @DisplayName("should proceed when no @RateLimit annotation")
        void shouldProceedWhenNoAnnotation() throws Throwable {
            when(joinPoint.getSignature()).thenReturn(methodSignature);
            when(methodSignature.getMethod()).thenReturn(getMethodWithoutAnnotation());
            when(joinPoint.proceed()).thenReturn("result");

            Object result = aspect.enforceRateLimit(joinPoint);

            assertThat(result).isEqualTo("result");
            verifyNoInteractions(rateLimitService);
        }

        @Test
        @DisplayName("should allow request when under limit")
        void shouldAllowWhenUnderLimit() throws Throwable {
            setupMocksForRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            when(rateLimitService.checkRateLimit(anyString(), eq(10), eq(60)))
                    .thenReturn(RateLimitResult.allowed(9));
            when(joinPoint.proceed()).thenReturn("result");

            Object result = aspect.enforceRateLimit(joinPoint);

            assertThat(result).isEqualTo("result");
            verify(rateLimitService).checkRateLimit(contains("ip:192.168.1.1"), eq(10), eq(60));
        }

        @Test
        @DisplayName("should throw exception when limit exceeded")
        void shouldThrowWhenLimitExceeded() throws Throwable {
            setupMocksForRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            when(rateLimitService.checkRateLimit(anyString(), eq(10), eq(60)))
                    .thenReturn(RateLimitResult.exceeded(30));

            assertThatThrownBy(() -> aspect.enforceRateLimit(joinPoint))
                    .isInstanceOf(RateLimitExceededException.class)
                    .hasMessageContaining("Rate limit exceeded");
        }

        @Test
        @DisplayName("should skip for authenticated users when configured")
        void shouldSkipForAuthenticatedWhenConfigured() throws Throwable {
            setupMocksForSkipAuthenticatedMethod();
            setupAuthentication("user123");
            when(joinPoint.proceed()).thenReturn("result");

            Object result = aspect.enforceRateLimit(joinPoint);

            assertThat(result).isEqualTo("result");
            verifyNoInteractions(rateLimitService);
        }
    }

    @Nested
    @DisplayName("Key building tests")
    class KeyBuildingTests {

        @Test
        @DisplayName("should build IP-based key")
        void shouldBuildIpKey() throws Throwable {
            setupMocksForRateLimitedMethod();
            setupMockRequest("10.0.0.1");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:10.0.0.1"), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should build user-based key for authenticated requests")
        void shouldBuildUserKey() throws Throwable {
            setupMocksForUserRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            setupAuthentication("user456");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("user:user456"), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should fall back to IP for USER key type when not authenticated")
        void shouldFallbackToIpWhenNotAuthenticated() throws Throwable {
            setupMocksForUserRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            clearAuthentication();
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:192.168.1.1"), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should extract IP from X-Forwarded-For header")
        void shouldExtractIpFromXForwardedFor() throws Throwable {
            setupMocksForRateLimitedMethod();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("X-Forwarded-For", "203.0.113.50, 70.41.3.18");
            request.setRemoteAddr("192.168.1.1");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:203.0.113.50"), anyInt(), anyInt());

            RequestContextHolder.resetRequestAttributes();
        }

        @Test
        @DisplayName("should extract IP from X-Real-IP header")
        void shouldExtractIpFromXRealIp() throws Throwable {
            setupMocksForRateLimitedMethod();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("X-Real-IP", "198.51.100.25");
            request.setRemoteAddr("192.168.1.1");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:198.51.100.25"), anyInt(), anyInt());

            RequestContextHolder.resetRequestAttributes();
        }

        @Test
        @DisplayName("should build endpoint-specific key")
        void shouldBuildEndpointKey() throws Throwable {
            setupMocksForIpEndpointRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(
                    contains("ip:192.168.1.1:RateLimitAspectTest.ipEndpointLimitedMethod"),
                    anyInt(), anyInt());
        }

        @Test
        @DisplayName("should use custom key prefix when provided")
        void shouldUseCustomKeyPrefix() throws Throwable {
            setupMocksForPrefixedRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(startsWith("custom:"), anyInt(), anyInt());
        }
    }

    @Nested
    @DisplayName("API Key rate limiting tests")
    class ApiKeyTests {

        @Test
        @DisplayName("should build API key based key when header present")
        void shouldBuildApiKeyBasedKey() throws Throwable {
            setupMocksForApiKeyRateLimitedMethod();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("X-API-Key", "test-api-key-12345");
            request.setRemoteAddr("192.168.1.1");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(startsWith("apikey:"), anyInt(), anyInt());

            RequestContextHolder.resetRequestAttributes();
        }

        @Test
        @DisplayName("should fall back to IP when no API key")
        void shouldFallbackToIpWhenNoApiKey() throws Throwable {
            setupMocksForApiKeyRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:192.168.1.1"), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should fall back to IP when API key is empty")
        void shouldFallbackToIpWhenApiKeyEmpty() throws Throwable {
            setupMocksForApiKeyRateLimitedMethod();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("X-API-Key", "");
            request.setRemoteAddr("192.168.1.1");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:192.168.1.1"), anyInt(), anyInt());

            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Nested
    @DisplayName("User Endpoint key type tests")
    class UserEndpointKeyTests {

        @Test
        @DisplayName("should build user endpoint key for authenticated user")
        void shouldBuildUserEndpointKeyForAuthenticatedUser() throws Throwable {
            setupMocksForUserEndpointRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            setupAuthentication("user789");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(
                    eq("user:user789:RateLimitAspectTest.userEndpointLimitedMethod"),
                    anyInt(), anyInt());
        }

        @Test
        @DisplayName("should fall back to IP endpoint key when not authenticated")
        void shouldFallbackToIpEndpointWhenNotAuthenticated() throws Throwable {
            setupMocksForUserEndpointRateLimitedMethod();
            setupMockRequest("10.0.0.5");
            clearAuthentication();
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(
                    eq("ip:10.0.0.5:RateLimitAspectTest.userEndpointLimitedMethod"),
                    anyInt(), anyInt());
        }
    }

    @Nested
    @DisplayName("Global key type tests")
    class GlobalKeyTests {

        @Test
        @DisplayName("should build global key regardless of user or IP")
        void shouldBuildGlobalKey() throws Throwable {
            setupMocksForGlobalRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(
                    eq("global:RateLimitAspectTest.globalLimitedMethod"),
                    anyInt(), anyInt());
        }
    }

    @Nested
    @DisplayName("Edge cases and error handling")
    class EdgeCasesTests {

        @Test
        @DisplayName("should return unknown IP when no request context")
        void shouldReturnUnknownIpWhenNoRequestContext() throws Throwable {
            setupMocksForRateLimitedMethod();
            RequestContextHolder.resetRequestAttributes();
            clearAuthentication();
            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:unknown"), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should use remoteAddr when X-Forwarded-For is empty")
        void shouldUseRemoteAddrWhenXForwardedForEmpty() throws Throwable {
            setupMocksForRateLimitedMethod();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("X-Forwarded-For", "");
            request.setRemoteAddr("172.16.0.1");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:172.16.0.1"), anyInt(), anyInt());

            RequestContextHolder.resetRequestAttributes();
        }

        @Test
        @DisplayName("should use remoteAddr when X-Real-IP is empty")
        void shouldUseRemoteAddrWhenXRealIpEmpty() throws Throwable {
            setupMocksForRateLimitedMethod();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("X-Real-IP", "");
            request.setRemoteAddr("172.16.0.2");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            verify(rateLimitService).checkRateLimit(eq("ip:172.16.0.2"), anyInt(), anyInt());

            RequestContextHolder.resetRequestAttributes();
        }

        @Test
        @DisplayName("should not skip rate limit for anonymous user even with skipAuthenticated")
        void shouldNotSkipForAnonymousUser() throws Throwable {
            setupMocksForSkipAuthenticatedMethod();
            setupMockRequest("192.168.1.1");
            // Set up anonymous user authentication
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    "anonymousUser", null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            // Should NOT skip - rate limit should be checked for anonymous user
            verify(rateLimitService).checkRateLimit(anyString(), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should fall back to IP for USER key when user is anonymous")
        void shouldFallbackToIpForAnonymousUser() throws Throwable {
            setupMocksForUserRateLimitedMethod();
            setupMockRequest("192.168.1.1");
            // Set up anonymous user authentication
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    "anonymousUser", null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            // Should fall back to IP since anonymous user is not considered authenticated
            verify(rateLimitService).checkRateLimit(eq("ip:192.168.1.1"), anyInt(), anyInt());
        }

        @Test
        @DisplayName("should handle null authentication")
        void shouldHandleNullAuthentication() throws Throwable {
            setupMocksForSkipAuthenticatedMethod();
            setupMockRequest("192.168.1.1");
            SecurityContextHolder.getContext().setAuthentication(null);

            when(rateLimitService.checkRateLimit(anyString(), anyInt(), anyInt()))
                    .thenReturn(RateLimitResult.allowed(5));
            when(joinPoint.proceed()).thenReturn("result");

            aspect.enforceRateLimit(joinPoint);

            // Should NOT skip - rate limit should be checked when no authentication
            verify(rateLimitService).checkRateLimit(anyString(), anyInt(), anyInt());
        }
    }

    // Helper methods

    private void setupMocksForRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getIpRateLimitedMethod());
    }

    private void setupMocksForUserRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getUserRateLimitedMethod());
    }

    private void setupMocksForSkipAuthenticatedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getSkipAuthenticatedMethod());
    }

    private void setupMocksForIpEndpointRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getIpEndpointRateLimitedMethod());
    }

    private void setupMocksForPrefixedRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getPrefixedRateLimitedMethod());
    }

    private void setupMocksForApiKeyRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getApiKeyRateLimitedMethod());
    }

    private void setupMocksForUserEndpointRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getUserEndpointRateLimitedMethod());
    }

    private void setupMocksForGlobalRateLimitedMethod() throws NoSuchMethodException {
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(getGlobalRateLimitedMethod());
    }

    private void setupMockRequest(String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private void setupAuthentication(String username) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, null, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private void clearAuthentication() {
        SecurityContextHolder.clearContext();
    }

    // Test methods with annotations

    private Method getMethodWithoutAnnotation() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("unAnnotatedMethod");
    }

    private Method getIpRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("ipRateLimitedMethod");
    }

    private Method getUserRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("userRateLimitedMethod");
    }

    private Method getSkipAuthenticatedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("skipAuthenticatedMethod");
    }

    private Method getIpEndpointRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("ipEndpointLimitedMethod");
    }

    private Method getPrefixedRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("prefixedRateLimitedMethod");
    }

    private Method getApiKeyRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("apiKeyRateLimitedMethod");
    }

    private Method getUserEndpointRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("userEndpointLimitedMethod");
    }

    private Method getGlobalRateLimitedMethod() throws NoSuchMethodException {
        return this.getClass().getDeclaredMethod("globalLimitedMethod");
    }

    // Dummy methods for annotation testing

    void unAnnotatedMethod() {}

    @RateLimit(requests = 10, window = 60, key = RateLimit.KeyType.IP)
    void ipRateLimitedMethod() {}

    @RateLimit(requests = 100, window = 60, key = RateLimit.KeyType.USER)
    void userRateLimitedMethod() {}

    @RateLimit(requests = 10, window = 60, skipAuthenticated = true)
    void skipAuthenticatedMethod() {}

    @RateLimit(requests = 5, window = 60, key = RateLimit.KeyType.IP_ENDPOINT)
    void ipEndpointLimitedMethod() {}

    @RateLimit(requests = 10, window = 60, keyPrefix = "custom")
    void prefixedRateLimitedMethod() {}

    @RateLimit(requests = 50, window = 60, key = RateLimit.KeyType.API_KEY)
    void apiKeyRateLimitedMethod() {}

    @RateLimit(requests = 20, window = 60, key = RateLimit.KeyType.USER_ENDPOINT)
    void userEndpointLimitedMethod() {}

    @RateLimit(requests = 1000, window = 60, key = RateLimit.KeyType.GLOBAL)
    void globalLimitedMethod() {}
}
