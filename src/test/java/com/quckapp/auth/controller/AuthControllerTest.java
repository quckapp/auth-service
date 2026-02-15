package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.ratelimit.RateLimitOperations;
import com.quckapp.auth.security.ratelimit.RateLimitResult;
import com.quckapp.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for AuthController using standalone MockMvc setup
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }
    }

    @Mock
    private AuthService authService;

    @Mock
    private RateLimitOperations rateLimitService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        AuthController authController = new AuthController(authService, rateLimitService);
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Registration tests")
    class RegistrationTests {

        @Test
        @DisplayName("should register user successfully")
        void shouldRegisterUserSuccessfully() throws Exception {
            RegisterRequest request = RegisterRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            AuthResponse response = AuthResponse.builder()
                    .accessToken("access-token")
                    .refreshToken("refresh-token")
                    .tokenType("Bearer")
                    .expiresIn(3600)
                    .requiresTwoFactor(false)
                    .build();

            when(authService.register(any(RegisterRequest.class), any(ClientInfo.class))).thenReturn(response);

            mockMvc.perform(post("/v1/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                    .andExpect(jsonPath("$.tokenType").value("Bearer"));

            verify(authService).register(any(RegisterRequest.class), any(ClientInfo.class));
        }
    }

    @Nested
    @DisplayName("Login tests")
    class LoginTests {

        @Test
        @DisplayName("should login successfully")
        void shouldLoginSuccessfully() throws Exception {
            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            AuthResponse response = AuthResponse.builder()
                    .accessToken("access-token")
                    .refreshToken("refresh-token")
                    .tokenType("Bearer")
                    .expiresIn(3600)
                    .requiresTwoFactor(false)
                    .build();

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.allowed(10));
            when(authService.login(any(LoginRequest.class), any(ClientInfo.class))).thenReturn(response);

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("access-token"));

            verify(rateLimitService).clearLoginAttempts(anyString(), anyString());
        }

        @Test
        @DisplayName("should return 2FA required response")
        void shouldReturn2FARequiredResponse() throws Exception {
            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            AuthResponse response = AuthResponse.builder()
                    .requiresTwoFactor(true)
                    .tempToken("temp-token")
                    .build();

            when(rateLimitService.checkLoginRateLimit(anyString(), anyString()))
                    .thenReturn(RateLimitResult.allowed(10));
            when(authService.login(any(LoginRequest.class), any(ClientInfo.class))).thenReturn(response);

            mockMvc.perform(post("/v1/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.requiresTwoFactor").value(true))
                    .andExpect(jsonPath("$.tempToken").value("temp-token"));
        }

        @Test
        @DisplayName("should complete 2FA login")
        void shouldComplete2FALogin() throws Exception {
            TwoFactorLoginRequest request = TwoFactorLoginRequest.builder()
                    .tempToken("temp-token")
                    .code("123456")
                    .build();

            AuthResponse response = AuthResponse.builder()
                    .accessToken("access-token")
                    .refreshToken("refresh-token")
                    .tokenType("Bearer")
                    .expiresIn(3600)
                    .requiresTwoFactor(false)
                    .build();

            when(authService.loginWith2FA(any(TwoFactorLoginRequest.class), any(ClientInfo.class))).thenReturn(response);

            mockMvc.perform(post("/v1/login/2fa")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("access-token"));
        }
    }

    @Nested
    @DisplayName("Logout tests")
    class LogoutTests {

        @Test
        @DisplayName("should logout successfully")
        void shouldLogoutSuccessfully() throws Exception {
            mockMvc.perform(post("/v1/logout")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk());

            verify(authService).logout(eq("valid-token"), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should reject invalid authorization header")
        void shouldRejectInvalidAuthHeader() throws Exception {
            mockMvc.perform(post("/v1/logout")
                            .header("Authorization", "Invalid"))
                    .andExpect(status().isBadRequest());
        }
    }

    // Note: Token management tests moved to TokenControllerTest (endpoints at /v1/token)

    @Nested
    @DisplayName("Password management tests")
    class PasswordManagementTests {

        @Test
        @DisplayName("should handle forgot password")
        void shouldHandleForgotPassword() throws Exception {
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .email("test@example.com")
                    .build();

            mockMvc.perform(post("/v1/password/forgot")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).forgotPassword(any(ForgotPasswordRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should reset password")
        void shouldResetPassword() throws Exception {
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .token("reset-token")
                    .newPassword("newPassword123")
                    .build();

            mockMvc.perform(post("/v1/password/reset")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).resetPassword(any(ResetPasswordRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should change password")
        void shouldChangePassword() throws Exception {
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword("oldPassword")
                    .newPassword("newPassword123")
                    .build();

            mockMvc.perform(post("/v1/password/change")
                            .header("Authorization", "Bearer valid-token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).changePassword(eq("valid-token"), any(ChangePasswordRequest.class), any(ClientInfo.class));
        }
    }

    // Note: 2FA setup/enable/disable/backup-codes tests moved to TwoFactorControllerTest (endpoints at /v1/2fa)

    @Nested
    @DisplayName("OAuth tests")
    class OAuthTests {

        @Test
        @DisplayName("should login with OAuth")
        void shouldLoginWithOAuth() throws Exception {
            OAuthRequest request = OAuthRequest.builder()
                    .providerUserId("google-123")
                    .accessToken("oauth-token")
                    .email("test@gmail.com")
                    .build();

            AuthResponse response = AuthResponse.builder()
                    .accessToken("access-token")
                    .refreshToken("refresh-token")
                    .tokenType("Bearer")
                    .expiresIn(3600)
                    .build();

            when(authService.oauthLogin(eq("google"), any(OAuthRequest.class), any(ClientInfo.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/oauth/google")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("access-token"));
        }

        @Test
        @DisplayName("should link OAuth provider")
        void shouldLinkOAuthProvider() throws Exception {
            OAuthRequest request = OAuthRequest.builder()
                    .providerUserId("github-123")
                    .accessToken("oauth-token")
                    .build();

            mockMvc.perform(post("/v1/oauth/github/link")
                            .header("Authorization", "Bearer valid-token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).linkOAuthProvider(eq("valid-token"), eq("github"), any(OAuthRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should unlink OAuth provider")
        void shouldUnlinkOAuthProvider() throws Exception {
            mockMvc.perform(delete("/v1/oauth/google/unlink")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).unlinkOAuthProvider(eq("valid-token"), eq("google"), any(ClientInfo.class));
        }
    }

    // Note: Session tests moved to SessionControllerTest (endpoints at /v1/sessions)
}
