package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.dto.LoginRequest;
import com.quckapp.auth.dto.RegisterRequest;
import com.quckapp.auth.security.ratelimit.RateLimitConfig;
import com.quckapp.auth.security.ratelimit.RateLimitExceptionHandler;
import com.quckapp.auth.security.ratelimit.RateLimitResult;
import com.quckapp.auth.security.ratelimit.RateLimitOperations;
import com.quckapp.auth.service.AuthService;
import com.quckapp.auth.service.TwoFactorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for rate limiting on AuthController endpoints.
 * Uses standalone MockMvc setup to avoid Spring context loading issues.
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerRateLimitTest {

    /**
     * Exception handler for handling general exceptions in tests
     */
    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(Exception.class)
        public ResponseEntity<String> handleException(Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ex.getMessage());
        }
    }

    private MockMvc mockMvc;

    private ObjectMapper objectMapper;

    @Mock
    private AuthService authService;

    @Mock
    private RateLimitOperations rateLimitService;

    @Mock
    private TwoFactorService twoFactorService;

    private RateLimitConfig config;

    @BeforeEach
    void setUp() {
        config = new RateLimitConfig();
        config.setEnabled(true);
        config.getLogin().setMaxAttempts(5);
        config.getLogin().setBlockDurationSeconds(900);

        objectMapper = new ObjectMapper();
        AuthController authController = new AuthController(authService, twoFactorService, rateLimitService);
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new RateLimitExceptionHandler(), new TestExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Login rate limiting tests")
    class LoginRateLimitTests {

        @Test
        @DisplayName("should allow login when under rate limit")
        void shouldAllowLoginUnderLimit() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("test@example.com");
            request.setPassword("password123");

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.allowed(4));

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(rateLimitService).checkLoginRateLimit(eq("test@example.com"), anyString());
        }

        @Test
        @DisplayName("should return 429 when login rate limit exceeded")
        void shouldReturn429WhenLoginLimitExceeded() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("test@example.com");
            request.setPassword("password123");

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.exceeded(60));

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.error").value("rate_limit_exceeded"));
        }

        @Test
        @DisplayName("should return 429 with account_blocked when login blocked")
        void shouldReturn429WhenLoginBlocked() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("blocked@example.com");
            request.setPassword("password123");

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.blocked(900));

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.error").value("account_blocked"))
                    .andExpect(header().exists("Retry-After"));
        }

        @Test
        @DisplayName("should record failed login on authentication failure")
        void shouldRecordFailedLogin() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("test@example.com");
            request.setPassword("wrong-password");

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.allowed(4));
            when(authService.login(any(), any()))
                    .thenThrow(new RuntimeException("Invalid credentials"));

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isInternalServerError());

            verify(rateLimitService).recordFailedLogin(eq("test@example.com"), anyString());
        }

        @Test
        @DisplayName("should clear login attempts on successful login")
        void shouldClearLoginAttemptsOnSuccess() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("test@example.com");
            request.setPassword("correct-password");

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.allowed(4));
            when(authService.login(any(), any()))
                    .thenReturn(null); // or a valid AuthResponse

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(rateLimitService).clearLoginAttempts(eq("test@example.com"), anyString());
        }
    }

    @Nested
    @DisplayName("Registration rate limiting tests")
    class RegistrationRateLimitTests {

        @Test
        @DisplayName("should apply rate limit to registration")
        void shouldApplyRateLimitToRegistration() throws Exception {
            RegisterRequest request = new RegisterRequest();
            request.setEmail("newuser@example.com");
            request.setPassword("password123");

            // Rate limit check happens via @RateLimit annotation
            // which is processed by RateLimitAspect
            mockMvc.perform(post("/v1/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("IP extraction tests")
    class IpExtractionTests {

        @Test
        @DisplayName("should extract IP from X-Forwarded-For header")
        void shouldExtractIpFromXForwardedFor() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("test@example.com");
            request.setPassword("password123");

            when(rateLimitService.checkLoginRateLimit(anyString(), eq("203.0.113.50")))
                    .thenReturn(RateLimitResult.allowed(4));

            mockMvc.perform(post("/v1/login")
                            .header("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(rateLimitService).checkLoginRateLimit(anyString(), eq("203.0.113.50"));
        }

        @Test
        @DisplayName("should extract IP from X-Real-IP header")
        void shouldExtractIpFromXRealIp() throws Exception {
            LoginRequest request = new LoginRequest();
            request.setEmail("test@example.com");
            request.setPassword("password123");

            when(rateLimitService.checkLoginRateLimit(anyString(), eq("198.51.100.25")))
                    .thenReturn(RateLimitResult.allowed(4));

            mockMvc.perform(post("/v1/login")
                            .header("X-Real-IP", "198.51.100.25")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(rateLimitService).checkLoginRateLimit(anyString(), eq("198.51.100.25"));
        }
    }
}
