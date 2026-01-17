package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.OAuthConnection;
import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.OAuthConnectionRepository;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.dto.SessionDtos.ActiveSessionDto;
import com.quckapp.auth.kafka.UserEventOperations;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthServiceImpl
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private OAuthConnectionRepository oauthConnectionRepository;

    @Mock
    private JwtOperations jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private TokenBlacklistOperations tokenBlacklistService;

    @Mock
    private TwoFactorService twoFactorService;

    @Mock
    private SessionManagementOperations sessionManagementService;

    @Mock
    private LoginHistoryOperations loginHistoryService;

    @Mock
    private UserEventOperations userEventPublisher;

    private AuthServiceImpl authService;

    private ClientInfo testClientInfo;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(
                authUserRepository,
                refreshTokenRepository,
                oauthConnectionRepository,
                jwtService,
                passwordEncoder,
                tokenBlacklistService,
                twoFactorService,
                sessionManagementService,
                loginHistoryService,
                userEventPublisher
        );

        testClientInfo = ClientInfo.builder()
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .deviceId("device-123")
                .deviceName("Test Device")
                .deviceType("Desktop")
                .country("US")
                .city("New York")
                .build();

        testUser = AuthUser.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .twoFactorEnabled(false)
                .oauthConnections(new HashSet<>())
                .build();
    }

    @Nested
    @DisplayName("Registration tests")
    class RegistrationTests {

        @Test
        @DisplayName("should register new user successfully")
        void shouldRegisterNewUser() {
            RegisterRequest request = RegisterRequest.builder()
                    .email("newuser@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.existsByEmail("newuser@example.com")).thenReturn(false);
            when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            AuthResponse response = authService.register(request, testClientInfo);

            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
            assertThat(response.isRequiresTwoFactor()).isFalse();

            verify(authUserRepository).save(any(AuthUser.class));
            verify(refreshTokenRepository).save(any(RefreshToken.class));
            verify(userEventPublisher).publishUserRegistered(any(AuthUser.class));
        }

        @Test
        @DisplayName("should throw exception when email already exists")
        void shouldThrowWhenEmailExists() {
            RegisterRequest request = RegisterRequest.builder()
                    .email("existing@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.existsByEmail("existing@example.com")).thenReturn(true);

            assertThatThrownBy(() -> authService.register(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Email already registered");

            verify(authUserRepository, never()).save(any());
        }

        @Test
        @DisplayName("should use provided external ID if given")
        void shouldUseProvidedExternalId() {
            RegisterRequest request = RegisterRequest.builder()
                    .email("newuser@example.com")
                    .password("password123")
                    .externalId("custom-ext-id")
                    .build();

            when(authUserRepository.existsByEmail(anyString())).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            authService.register(request, testClientInfo);

            ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getExternalId()).isEqualTo("custom-ext-id");
        }
    }

    @Nested
    @DisplayName("Login tests")
    class LoginTests {

        @Test
        @DisplayName("should login successfully with correct credentials")
        void shouldLoginSuccessfully() {
            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(true);
            when(authUserRepository.save(any())).thenReturn(testUser);
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            AuthResponse response = authService.login(request, testClientInfo);

            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            assertThat(response.isRequiresTwoFactor()).isFalse();

            verify(loginHistoryService).recordLogin(any());
        }

        @Test
        @DisplayName("should throw exception for invalid email")
        void shouldThrowForInvalidEmail() {
            LoginRequest request = LoginRequest.builder()
                    .email("nonexistent@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.login(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid credentials");

            verify(loginHistoryService).recordLogin(any());
        }

        @Test
        @DisplayName("should throw exception for invalid password")
        void shouldThrowForInvalidPassword() {
            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("wrongpassword")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("wrongpassword", "hashedPassword")).thenReturn(false);
            when(authUserRepository.save(any())).thenReturn(testUser);

            assertThatThrownBy(() -> authService.login(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid credentials");

            verify(authUserRepository).save(any()); // Save to increment failed attempts
        }

        @Test
        @DisplayName("should throw exception for locked account")
        void shouldThrowForLockedAccount() {
            testUser.setLockedUntil(Instant.now().plus(1, ChronoUnit.HOURS));

            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.login(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Account is locked");
        }

        @Test
        @DisplayName("should lock account after max failed attempts")
        void shouldLockAfterMaxFailedAttempts() {
            testUser.setFailedLoginAttempts(4); // One more attempt will trigger lock

            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("wrongpassword")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("wrongpassword", "hashedPassword")).thenReturn(false);
            when(authUserRepository.save(any())).thenReturn(testUser);

            assertThatThrownBy(() -> authService.login(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class);

            ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getLockedUntil()).isNotNull();
        }

        @Test
        @DisplayName("should return 2FA response when 2FA is enabled")
        void shouldReturn2FAResponseWhenEnabled() {
            testUser.setTwoFactorEnabled(true);

            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(true);
            when(authUserRepository.save(any())).thenReturn(testUser);
            when(jwtService.generateTempToken(any())).thenReturn("temp-token");

            AuthResponse response = authService.login(request, testClientInfo);

            assertThat(response.isRequiresTwoFactor()).isTrue();
            assertThat(response.getTempToken()).isEqualTo("temp-token");
            assertThat(response.getAccessToken()).isNull();
        }

        @Test
        @DisplayName("should reset failed attempts on successful login")
        void shouldResetFailedAttemptsOnSuccess() {
            testUser.setFailedLoginAttempts(3);

            LoginRequest request = LoginRequest.builder()
                    .email("test@example.com")
                    .password("password123")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(true);
            when(authUserRepository.save(any())).thenReturn(testUser);
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            authService.login(request, testClientInfo);

            ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository, atLeastOnce()).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getFailedLoginAttempts()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("2FA login tests")
    class TwoFactorLoginTests {

        @Test
        @DisplayName("should complete 2FA login with valid code")
        void shouldComplete2FALogin() {
            testUser.setTwoFactorSecret("secret123");

            TwoFactorLoginRequest request = TwoFactorLoginRequest.builder()
                    .tempToken("temp-token")
                    .code("123456")
                    .build();

            when(jwtService.extractUserId("temp-token")).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            AuthResponse response = authService.loginWith2FA(request, testClientInfo);

            assertThat(response.getAccessToken()).isEqualTo("access-token");
            assertThat(response.isRequiresTwoFactor()).isFalse();
        }

        @Test
        @DisplayName("should throw exception for invalid 2FA code")
        void shouldThrowForInvalid2FACode() {
            testUser.setTwoFactorSecret("secret123");

            TwoFactorLoginRequest request = TwoFactorLoginRequest.builder()
                    .tempToken("temp-token")
                    .code("invalid")
                    .build();

            when(jwtService.extractUserId("temp-token")).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> authService.loginWith2FA(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid verification code");
        }

        @Test
        @DisplayName("should accept backup code for 2FA")
        void shouldAcceptBackupCode() {
            Set<String> backupCodes = new HashSet<>(Arrays.asList("backup-123", "backup-456"));
            testUser.setBackupCodes(backupCodes);
            testUser.setTwoFactorSecret(null); // No TOTP, only backup codes

            TwoFactorLoginRequest request = TwoFactorLoginRequest.builder()
                    .tempToken("temp-token")
                    .code("backup-123")
                    .build();

            when(jwtService.extractUserId("temp-token")).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any())).thenReturn(testUser);
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            AuthResponse response = authService.loginWith2FA(request, testClientInfo);

            assertThat(response.getAccessToken()).isEqualTo("access-token");
            // Backup code should be removed after use
            assertThat(testUser.getBackupCodes()).doesNotContain("backup-123");
        }
    }

    @Nested
    @DisplayName("Logout tests")
    class LogoutTests {

        @Test
        @DisplayName("should logout successfully")
        void shouldLogoutSuccessfully() {
            String token = "valid-token";
            Date expiration = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));

            when(jwtService.extractUserId(token)).thenReturn(testUser.getId().toString());
            when(jwtService.extractExpiration(token)).thenReturn(expiration);
            when(jwtService.extractSessionId(token)).thenReturn(UUID.randomUUID().toString());

            authService.logout(token, testClientInfo);

            verify(tokenBlacklistService).blacklistToken(eq(token), eq(expiration), anyString());
            verify(sessionManagementService).terminateSession(any(UUID.class), eq("User logout"));
        }

        @Test
        @DisplayName("should still blacklist token even if other operations fail")
        void shouldBlacklistTokenOnError() {
            String token = "valid-token";
            Date expiration = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));

            when(jwtService.extractUserId(token)).thenThrow(new RuntimeException("Error"));
            when(jwtService.extractExpiration(token)).thenReturn(expiration);

            authService.logout(token, testClientInfo);

            verify(tokenBlacklistService).blacklistToken(eq(token), eq(expiration), anyString());
        }
    }

    @Nested
    @DisplayName("Token refresh tests")
    class TokenRefreshTests {

        @Test
        @DisplayName("should refresh token successfully")
        void shouldRefreshTokenSuccessfully() {
            String refreshToken = "refresh-token";
            RefreshToken storedToken = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .token(refreshToken)
                    .user(testUser)
                    .expiresAt(Instant.now().plus(7, ChronoUnit.DAYS))
                    .build();

            RefreshTokenRequest request = RefreshTokenRequest.builder()
                    .refreshToken(refreshToken)
                    .build();

            when(jwtService.validateToken(refreshToken)).thenReturn(true);
            when(jwtService.extractTokenType(refreshToken)).thenReturn("refresh");
            when(tokenBlacklistService.isBlacklisted(refreshToken)).thenReturn(false);
            when(refreshTokenRepository.findByTokenAndRevokedFalse(refreshToken)).thenReturn(Optional.of(storedToken));
            when(jwtService.extractUserId(refreshToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(jwtService.generateAccessToken(any())).thenReturn("new-access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("new-refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            TokenResponse response = authService.refreshToken(request, testClientInfo);

            assertThat(response.getAccessToken()).isEqualTo("new-access-token");
            assertThat(response.getRefreshToken()).isEqualTo("new-refresh-token");

            // Verify old token is revoked
            verify(refreshTokenRepository).save(storedToken);
            assertThat(storedToken.isRevoked()).isTrue();

            // Verify new refresh token is saved
            verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("should throw exception for invalid refresh token")
        void shouldThrowForInvalidRefreshToken() {
            RefreshTokenRequest request = RefreshTokenRequest.builder()
                    .refreshToken("invalid-token")
                    .build();

            when(jwtService.validateToken("invalid-token")).thenReturn(false);

            assertThatThrownBy(() -> authService.refreshToken(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid refresh token");
        }

        @Test
        @DisplayName("should throw exception for blacklisted token")
        void shouldThrowForBlacklistedToken() {
            String refreshToken = "blacklisted-token";
            RefreshTokenRequest request = RefreshTokenRequest.builder()
                    .refreshToken(refreshToken)
                    .build();

            when(jwtService.validateToken(refreshToken)).thenReturn(true);
            when(jwtService.extractTokenType(refreshToken)).thenReturn("refresh");
            when(tokenBlacklistService.isBlacklisted(refreshToken)).thenReturn(true);

            assertThatThrownBy(() -> authService.refreshToken(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Token has been revoked");
        }

        @Test
        @DisplayName("should throw exception for expired refresh token")
        void shouldThrowForExpiredRefreshToken() {
            String refreshToken = "expired-token";
            RefreshToken storedToken = RefreshToken.builder()
                    .token(refreshToken)
                    .expiresAt(Instant.now().minus(1, ChronoUnit.DAYS))
                    .build();

            RefreshTokenRequest request = RefreshTokenRequest.builder()
                    .refreshToken(refreshToken)
                    .build();

            when(jwtService.validateToken(refreshToken)).thenReturn(true);
            when(jwtService.extractTokenType(refreshToken)).thenReturn("refresh");
            when(tokenBlacklistService.isBlacklisted(refreshToken)).thenReturn(false);
            when(refreshTokenRepository.findByTokenAndRevokedFalse(refreshToken)).thenReturn(Optional.of(storedToken));

            assertThatThrownBy(() -> authService.refreshToken(request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Refresh token has expired");
        }
    }

    @Nested
    @DisplayName("Token validation tests")
    class TokenValidationTests {

        @Test
        @DisplayName("should validate token successfully")
        void shouldValidateTokenSuccessfully() {
            String token = "valid-token";
            Date expiration = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));
            Date issuedAt = Date.from(Instant.now().minus(1, ChronoUnit.HOURS));

            TokenValidationRequest request = TokenValidationRequest.builder()
                    .token(token)
                    .build();

            when(jwtService.validateToken(token)).thenReturn(true);
            when(tokenBlacklistService.isBlacklisted(token)).thenReturn(false);
            when(jwtService.extractUserId(token)).thenReturn(testUser.getId().toString());
            when(jwtService.extractEmail(token)).thenReturn(testUser.getEmail());
            when(jwtService.extractExternalId(token)).thenReturn(testUser.getExternalId());
            when(jwtService.extractTokenType(token)).thenReturn("access");
            when(jwtService.extractIssuedAt(token)).thenReturn(issuedAt);
            when(tokenBlacklistService.isTokenIssuedBeforeBlacklist(anyString(), anyLong())).thenReturn(false);
            when(jwtService.extractExpiration(token)).thenReturn(expiration);

            TokenValidationResponse response = authService.validateToken(request);

            assertThat(response.isValid()).isTrue();
            assertThat(response.getUserId()).isEqualTo(testUser.getId().toString());
            assertThat(response.getEmail()).isEqualTo(testUser.getEmail());
        }

        @Test
        @DisplayName("should return invalid for blacklisted token")
        void shouldReturnInvalidForBlacklistedToken() {
            String token = "blacklisted-token";
            TokenValidationRequest request = TokenValidationRequest.builder()
                    .token(token)
                    .build();

            when(jwtService.validateToken(token)).thenReturn(true);
            when(tokenBlacklistService.isBlacklisted(token)).thenReturn(true);

            TokenValidationResponse response = authService.validateToken(request);

            assertThat(response.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return invalid for expired token")
        void shouldReturnInvalidForExpiredToken() {
            String token = "expired-token";
            TokenValidationRequest request = TokenValidationRequest.builder()
                    .token(token)
                    .build();

            when(jwtService.validateToken(token)).thenReturn(false);

            TokenValidationResponse response = authService.validateToken(request);

            assertThat(response.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("Token revocation tests")
    class TokenRevocationTests {

        @Test
        @DisplayName("should revoke single token")
        void shouldRevokeSingleToken() {
            String accessToken = "caller-access-token";
            String token = "token-to-revoke";
            Date expiration = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));

            RevokeTokenRequest request = RevokeTokenRequest.builder()
                    .token(token)
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(jwtService.extractExpiration(token)).thenReturn(expiration);
            when(jwtService.extractTokenType(token)).thenReturn("access");

            authService.revokeToken(accessToken, request, testClientInfo);

            verify(tokenBlacklistService).blacklistToken(eq(token), eq(expiration), anyString());
        }

        @Test
        @DisplayName("should revoke all user tokens")
        void shouldRevokeAllUserTokens() {
            String token = "current-token";

            when(jwtService.extractUserId(token)).thenReturn(testUser.getId().toString());

            authService.revokeAllTokens(token, testClientInfo);

            verify(tokenBlacklistService).blacklistAllUserTokens(testUser.getId().toString());
            verify(refreshTokenRepository).revokeAllUserTokens(eq(testUser.getId()), any(Instant.class), anyString());
            verify(sessionManagementService).terminateAllUserSessions(eq(testUser.getId()), anyString());
        }
    }

    @Nested
    @DisplayName("Password management tests")
    class PasswordManagementTests {

        @Test
        @DisplayName("should handle forgot password request")
        void shouldHandleForgotPassword() {
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .email("test@example.com")
                    .build();

            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(jwtService.generatePasswordResetToken(testUser)).thenReturn("reset-token");

            authService.forgotPassword(request, testClientInfo);

            verify(userEventPublisher).publishPasswordResetRequested(eq(testUser), eq("reset-token"));
        }

        @Test
        @DisplayName("should not fail for non-existent email in forgot password")
        void shouldNotFailForNonExistentEmail() {
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .email("nonexistent@example.com")
                    .build();

            when(authUserRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

            // Should not throw exception (prevent email enumeration)
            assertThatNoException().isThrownBy(() -> authService.forgotPassword(request, testClientInfo));
        }

        @Test
        @DisplayName("should reset password successfully")
        void shouldResetPasswordSuccessfully() {
            String resetToken = "valid-reset-token";
            ResetPasswordRequest request = ResetPasswordRequest.builder()
                    .token(resetToken)
                    .newPassword("newPassword123")
                    .build();

            when(jwtService.validateToken(resetToken)).thenReturn(true);
            when(jwtService.extractTokenType(resetToken)).thenReturn("password_reset");
            when(jwtService.extractUserId(resetToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(passwordEncoder.encode("newPassword123")).thenReturn("newEncodedPassword");

            authService.resetPassword(request, testClientInfo);

            verify(authUserRepository).save(testUser);
            assertThat(testUser.getPasswordHash()).isEqualTo("newEncodedPassword");
            verify(tokenBlacklistService).blacklistAllUserTokens(testUser.getId().toString());
            verify(sessionManagementService).terminateAllUserSessions(eq(testUser.getId()), anyString());
            verify(userEventPublisher).publishPasswordChanged(testUser);
        }

        @Test
        @DisplayName("should change password with correct current password")
        void shouldChangePasswordSuccessfully() {
            String accessToken = "access-token";
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword("currentPassword")
                    .newPassword("newPassword123")
                    .logoutOtherSessions(false)
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("currentPassword", "hashedPassword")).thenReturn(true);
            when(passwordEncoder.encode("newPassword123")).thenReturn("newEncodedPassword");

            authService.changePassword(accessToken, request, testClientInfo);

            verify(authUserRepository).save(testUser);
            assertThat(testUser.getPasswordHash()).isEqualTo("newEncodedPassword");
            verify(userEventPublisher).publishPasswordChanged(testUser);
        }

        @Test
        @DisplayName("should throw exception for incorrect current password")
        void shouldThrowForIncorrectCurrentPassword() {
            String accessToken = "access-token";
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword("wrongPassword")
                    .newPassword("newPassword123")
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("wrongPassword", "hashedPassword")).thenReturn(false);

            assertThatThrownBy(() -> authService.changePassword(accessToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Current password is incorrect");
        }

        @Test
        @DisplayName("should logout other sessions when requested during password change")
        void shouldLogoutOtherSessionsWhenRequested() {
            String accessToken = "access-token";
            String sessionId = UUID.randomUUID().toString();
            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .currentPassword("currentPassword")
                    .newPassword("newPassword123")
                    .logoutOtherSessions(true)
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(jwtService.extractSessionId(accessToken)).thenReturn(sessionId);
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("currentPassword", "hashedPassword")).thenReturn(true);
            when(passwordEncoder.encode("newPassword123")).thenReturn("newEncodedPassword");

            authService.changePassword(accessToken, request, testClientInfo);

            verify(sessionManagementService).terminateOtherSessions(
                    eq(testUser.getId()),
                    eq(UUID.fromString(sessionId)),
                    anyString()
            );
        }
    }

    @Nested
    @DisplayName("OAuth tests")
    class OAuthTests {

        @Test
        @DisplayName("should login with OAuth for existing user")
        void shouldLoginWithOAuthExistingUser() {
            OAuthConnection existingConnection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthConnection.OAuthProvider.GOOGLE)
                    .providerUserId("google-123")
                    .build();

            OAuthRequest request = OAuthRequest.builder()
                    .providerUserId("google-123")
                    .accessToken("oauth-access-token")
                    .email(testUser.getEmail())
                    .build();

            when(oauthConnectionRepository.findByProviderAndProviderUserId(
                    OAuthConnection.OAuthProvider.GOOGLE, "google-123"))
                    .thenReturn(Optional.of(existingConnection));
            when(authUserRepository.save(any())).thenReturn(testUser);
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            AuthResponse response = authService.oauthLogin("google", request, testClientInfo);

            assertThat(response.getAccessToken()).isEqualTo("access-token");
            verify(oauthConnectionRepository).save(existingConnection);
        }

        @Test
        @DisplayName("should create new user for OAuth login with new email")
        void shouldCreateNewUserForOAuth() {
            OAuthRequest request = OAuthRequest.builder()
                    .providerUserId("google-456")
                    .accessToken("oauth-access-token")
                    .email("newuser@gmail.com")
                    .build();

            when(oauthConnectionRepository.findByProviderAndProviderUserId(
                    OAuthConnection.OAuthProvider.GOOGLE, "google-456"))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail("newuser@gmail.com")).thenReturn(Optional.empty());
            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                user.setOauthConnections(new HashSet<>());
                return user;
            });
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);

            AuthResponse response = authService.oauthLogin("google", request, testClientInfo);

            assertThat(response.getAccessToken()).isEqualTo("access-token");
            verify(authUserRepository, times(2)).save(any(AuthUser.class));
            verify(oauthConnectionRepository).save(any(OAuthConnection.class));
        }

        @Test
        @DisplayName("should link OAuth provider to existing account")
        void shouldLinkOAuthProvider() {
            String accessToken = "access-token";
            OAuthRequest request = OAuthRequest.builder()
                    .providerUserId("github-123")
                    .accessToken("oauth-access-token")
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.existsByUserIdAndProvider(testUser.getId(), OAuthConnection.OAuthProvider.GITHUB))
                    .thenReturn(false);
            when(oauthConnectionRepository.existsByProviderAndProviderUserId(OAuthConnection.OAuthProvider.GITHUB, "github-123"))
                    .thenReturn(false);

            authService.linkOAuthProvider(accessToken, "github", request, testClientInfo);

            verify(oauthConnectionRepository).save(any(OAuthConnection.class));
        }

        @Test
        @DisplayName("should throw exception when provider already linked")
        void shouldThrowWhenProviderAlreadyLinked() {
            String accessToken = "access-token";
            OAuthRequest request = OAuthRequest.builder()
                    .providerUserId("github-123")
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.existsByUserIdAndProvider(testUser.getId(), OAuthConnection.OAuthProvider.GITHUB))
                    .thenReturn(true);

            assertThatThrownBy(() -> authService.linkOAuthProvider(accessToken, "github", request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Provider already linked");
        }

        @Test
        @DisplayName("should unlink OAuth provider when user has password")
        void shouldUnlinkOAuthProviderWithPassword() {
            String accessToken = "access-token";

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.countByUserId(testUser.getId())).thenReturn(1);
            when(oauthConnectionRepository.deleteByUserIdAndProvider(testUser.getId(), OAuthConnection.OAuthProvider.GOOGLE))
                    .thenReturn(1);

            authService.unlinkOAuthProvider(accessToken, "google", testClientInfo);

            verify(oauthConnectionRepository).deleteByUserIdAndProvider(testUser.getId(), OAuthConnection.OAuthProvider.GOOGLE);
        }

        @Test
        @DisplayName("should not allow unlinking last auth method")
        void shouldNotAllowUnlinkingLastAuthMethod() {
            testUser.setPasswordHash(null); // No password
            String accessToken = "access-token";

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.countByUserId(testUser.getId())).thenReturn(1);

            assertThatThrownBy(() -> authService.unlinkOAuthProvider(accessToken, "google", testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot unlink the only authentication method");
        }
    }

    @Nested
    @DisplayName("Session management tests")
    class SessionManagementTests {

        @Test
        @DisplayName("should get active sessions")
        void shouldGetActiveSessions() {
            String accessToken = "access-token";
            String sessionId = UUID.randomUUID().toString();

            ActiveSessionDto session1 = ActiveSessionDto.builder()
                    .id(UUID.fromString(sessionId))
                    .userId(testUser.getId())
                    .deviceName("Device 1")
                    .deviceType("Desktop")
                    .ipAddress("192.168.1.1")
                    .city("New York")
                    .country("US")
                    .lastActivityAt(Instant.now())
                    .createdAt(Instant.now().minus(1, ChronoUnit.DAYS))
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(jwtService.extractSessionId(accessToken)).thenReturn(sessionId);
            when(sessionManagementService.getActiveSessions(testUser.getId()))
                    .thenReturn(Collections.singletonList(session1));

            SessionsResponse response = authService.getActiveSessions(accessToken);

            assertThat(response.getSessions()).hasSize(1);
            assertThat(response.getCurrentSessionId()).isEqualTo(sessionId);
            assertThat(response.getSessions().get(0).isCurrent()).isTrue();
        }

        @Test
        @DisplayName("should terminate specific session")
        void shouldTerminateSession() {
            String accessToken = "access-token";
            UUID sessionToTerminate = UUID.randomUUID();

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(sessionToTerminate)
                    .userId(testUser.getId())
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(sessionManagementService.getSession(sessionToTerminate)).thenReturn(session);

            authService.terminateSession(accessToken, sessionToTerminate.toString(), testClientInfo);

            verify(sessionManagementService).terminateSession(sessionToTerminate, "User requested");
        }

        @Test
        @DisplayName("should not allow terminating other user's session")
        void shouldNotAllowTerminatingOtherUserSession() {
            String accessToken = "access-token";
            UUID sessionToTerminate = UUID.randomUUID();
            UUID otherUserId = UUID.randomUUID();

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(sessionToTerminate)
                    .userId(otherUserId) // Different user
                    .build();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(sessionManagementService.getSession(sessionToTerminate)).thenReturn(session);

            assertThatThrownBy(() -> authService.terminateSession(accessToken, sessionToTerminate.toString(), testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Session does not belong to this user");
        }

        @Test
        @DisplayName("should terminate all other sessions")
        void shouldTerminateAllOtherSessions() {
            String accessToken = "access-token";
            String currentSessionId = UUID.randomUUID().toString();

            when(jwtService.extractUserId(accessToken)).thenReturn(testUser.getId().toString());
            when(jwtService.extractSessionId(accessToken)).thenReturn(currentSessionId);

            authService.terminateAllOtherSessions(accessToken, testClientInfo);

            verify(sessionManagementService).terminateOtherSessions(
                    testUser.getId(),
                    UUID.fromString(currentSessionId),
                    "User requested"
            );
        }
    }
}
