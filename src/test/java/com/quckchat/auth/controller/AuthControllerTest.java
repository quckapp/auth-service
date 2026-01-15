package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.ratelimit.RateLimitOperations;
import com.quckapp.auth.security.ratelimit.RateLimitResult;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.HashSet;
import java.util.Set;

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
    private TwoFactorService twoFactorService;

    @Mock
    private RateLimitOperations rateLimitService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        AuthController authController = new AuthController(authService, twoFactorService, rateLimitService);
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

    @Nested
    @DisplayName("Token management tests")
    class TokenManagementTests {

        @Test
        @DisplayName("should refresh token successfully")
        void shouldRefreshTokenSuccessfully() throws Exception {
            RefreshTokenRequest request = RefreshTokenRequest.builder()
                    .refreshToken("refresh-token")
                    .build();

            TokenResponse response = TokenResponse.builder()
                    .accessToken("new-access-token")
                    .refreshToken("new-refresh-token")
                    .tokenType("Bearer")
                    .expiresIn(3600)
                    .build();

            when(authService.refreshToken(any(RefreshTokenRequest.class), any(ClientInfo.class))).thenReturn(response);

            mockMvc.perform(post("/v1/token/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
        }

        @Test
        @DisplayName("should validate token")
        void shouldValidateToken() throws Exception {
            TokenValidationRequest request = TokenValidationRequest.builder()
                    .token("valid-token")
                    .build();

            TokenValidationResponse response = TokenValidationResponse.builder()
                    .valid(true)
                    .userId("user-123")
                    .email("test@example.com")
                    .build();

            when(authService.validateToken(any(TokenValidationRequest.class))).thenReturn(response);

            mockMvc.perform(post("/v1/token/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(true))
                    .andExpect(jsonPath("$.userId").value("user-123"));
        }

        @Test
        @DisplayName("should revoke token")
        void shouldRevokeToken() throws Exception {
            RevokeTokenRequest request = RevokeTokenRequest.builder()
                    .token("token-to-revoke")
                    .build();

            mockMvc.perform(post("/v1/token/revoke")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(authService).revokeToken(any(RevokeTokenRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should revoke all tokens")
        void shouldRevokeAllTokens() throws Exception {
            mockMvc.perform(post("/v1/token/revoke-all")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk());

            verify(authService).revokeAllTokens(eq("valid-token"), any(ClientInfo.class));
        }
    }

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

    @Nested
    @DisplayName("2FA tests")
    class TwoFactorTests {

        @Test
        @DisplayName("should setup 2FA")
        void shouldSetup2FA() throws Exception {
            TwoFactorSetupResponse response = TwoFactorSetupResponse.builder()
                    .secret("secret123")
                    .qrCodeUrl("https://qr.example.com")
                    .otpAuthUrl("otpauth://totp/...")
                    .build();

            when(twoFactorService.setupTwoFactor(anyString())).thenReturn(response);

            mockMvc.perform(post("/v1/2fa/setup")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.secret").value("secret123"))
                    .andExpect(jsonPath("$.qrCodeUrl").exists());
        }

        @Test
        @DisplayName("should enable 2FA")
        void shouldEnable2FA() throws Exception {
            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("123456")
                    .build();

            Set<String> backupCodes = new HashSet<>();
            backupCodes.add("1234-5678");
            backupCodes.add("8765-4321");

            TwoFactorEnableResponse response = TwoFactorEnableResponse.builder()
                    .enabled(true)
                    .backupCodes(backupCodes)
                    .build();

            when(twoFactorService.enableTwoFactor(anyString(), any(TwoFactorEnableRequest.class), any(ClientInfo.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/2fa/enable")
                            .header("Authorization", "Bearer valid-token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.enabled").value(true))
                    .andExpect(jsonPath("$.backupCodes").isArray());
        }

        @Test
        @DisplayName("should disable 2FA")
        void shouldDisable2FA() throws Exception {
            TwoFactorDisableRequest request = TwoFactorDisableRequest.builder()
                    .code("123456")
                    .password("password123")
                    .build();

            mockMvc.perform(post("/v1/2fa/disable")
                            .header("Authorization", "Bearer valid-token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(twoFactorService).disableTwoFactor(anyString(), any(TwoFactorDisableRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should generate backup codes")
        void shouldGenerateBackupCodes() throws Exception {
            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            Set<String> backupCodes = new HashSet<>();
            backupCodes.add("1111-2222");
            backupCodes.add("3333-4444");

            BackupCodesResponse response = BackupCodesResponse.builder()
                    .backupCodes(backupCodes)
                    .build();

            when(twoFactorService.generateBackupCodes(anyString(), any(TwoFactorVerifyRequest.class), any(ClientInfo.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/2fa/backup-codes")
                            .header("Authorization", "Bearer valid-token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.backupCodes").isArray());
        }
    }

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

    @Nested
    @DisplayName("Session tests")
    class SessionTests {

        @Test
        @DisplayName("should get active sessions")
        void shouldGetActiveSessions() throws Exception {
            SessionsResponse response = SessionsResponse.builder()
                    .currentSessionId("session-123")
                    .build();

            when(authService.getActiveSessions(anyString())).thenReturn(response);

            mockMvc.perform(get("/v1/sessions")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.currentSessionId").value("session-123"));
        }

        @Test
        @DisplayName("should terminate specific session")
        void shouldTerminateSpecificSession() throws Exception {
            mockMvc.perform(delete("/v1/sessions/session-123")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk());

            verify(authService).terminateSession(eq("valid-token"), eq("session-123"), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should terminate all other sessions")
        void shouldTerminateAllOtherSessions() throws Exception {
            mockMvc.perform(delete("/v1/sessions")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk());

            verify(authService).terminateAllOtherSessions(eq("valid-token"), any(ClientInfo.class));
        }
    }
}
