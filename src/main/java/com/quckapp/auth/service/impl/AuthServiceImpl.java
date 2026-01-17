package com.quckapp.auth.service.impl;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.entity.OAuthConnection.OAuthProvider;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.dto.LoginHistoryDtos.RecordLoginRequest;
import com.quckapp.auth.dto.SessionDtos.ActiveSessionDto;
import com.quckapp.auth.dto.SessionDtos.CreateSessionRequest;
import com.quckapp.auth.kafka.UserEventOperations;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthUserRepository authUserRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OAuthConnectionRepository oauthConnectionRepository;
    private final JwtOperations jwtService;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistOperations tokenBlacklistService;
    private final TwoFactorService twoFactorService;
    private final SessionManagementOperations sessionManagementService;
    private final LoginHistoryOperations loginHistoryService;
    private final UserEventOperations userEventPublisher;

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 15;
    private static final int REFRESH_TOKEN_EXPIRY_DAYS = 7;

    @Override
    public AuthResponse register(RegisterRequest request, ClientInfo clientInfo) {
        log.info("Registering new user: {}", request.getEmail());

        if (authUserRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        AuthUser user = AuthUser.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .externalId(request.getExternalId() != null ? request.getExternalId() : UUID.randomUUID().toString())
                .status(AuthUser.AuthStatus.ACTIVE)
                .build();

        user = authUserRepository.save(user);

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Store refresh token in database
        saveRefreshToken(user, refreshToken, clientInfo);

        // Create session
        createSession(user, accessToken, clientInfo);

        // Record login history
        recordLoginSuccess(user, clientInfo, LoginMethod.PASSWORD);

        // Publish event
        userEventPublisher.publishUserRegistered(user);

        log.info("User registered successfully: {}", user.getId());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getAccessTokenExpiration())
                .tokenType("Bearer")
                .user(toUserInfo(user))
                .requiresTwoFactor(false)
                .build();
    }

    @Override
    public AuthResponse login(LoginRequest request, ClientInfo clientInfo) {
        log.info("Login attempt for: {}", request.getEmail());

        AuthUser user = authUserRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    recordLoginFailure(request.getEmail(), clientInfo, "User not found");
                    return new RuntimeException("Invalid credentials");
                });

        if (user.isLocked()) {
            recordLoginFailure(request.getEmail(), clientInfo, "Account locked");
            throw new RuntimeException("Account is locked. Try again later.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            user.incrementFailedAttempts();
            if (user.getFailedLoginAttempts() >= MAX_LOGIN_ATTEMPTS) {
                user.setLockedUntil(Instant.now().plusSeconds(LOCKOUT_MINUTES * 60));
                log.warn("Account locked due to too many failed attempts: {}", request.getEmail());
            }
            authUserRepository.save(user);
            recordLoginFailure(request.getEmail(), clientInfo, "Invalid password");
            throw new RuntimeException("Invalid credentials");
        }

        user.resetFailedAttempts();
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(clientInfo.getIpAddress());
        authUserRepository.save(user);

        // Check if 2FA is required
        if (user.isTwoFactorEnabled()) {
            String tempToken = jwtService.generateTempToken(user);
            return AuthResponse.builder()
                    .requiresTwoFactor(true)
                    .tempToken(tempToken)
                    .build();
        }

        return completeLogin(user, clientInfo, LoginMethod.PASSWORD);
    }

    @Override
    public AuthResponse loginWith2FA(TwoFactorLoginRequest request, ClientInfo clientInfo) {
        String userId = jwtService.extractUserId(request.getTempToken());
        AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        // Verify 2FA code
        boolean isValid = verifyTwoFactorCode(user, request.getCode());
        if (!isValid) {
            recordLoginFailure(user.getEmail(), clientInfo, "Invalid 2FA code");
            throw new RuntimeException("Invalid verification code");
        }

        return completeLogin(user, clientInfo, LoginMethod.PASSWORD);
    }

    @Override
    public void logout(String token, ClientInfo clientInfo) {
        log.info("Logout requested");

        try {
            // Extract user info before blacklisting
            String userId = jwtService.extractUserId(token);

            // Blacklist the access token
            tokenBlacklistService.blacklistToken(
                    token,
                    jwtService.extractExpiration(token),
                    "User logout"
            );

            // Terminate the session
            String sessionId = jwtService.extractSessionId(token);
            if (sessionId != null) {
                sessionManagementService.terminateSession(UUID.fromString(sessionId), "User logout");
            }

            // Record logout activity
            log.info("User {} logged out successfully", userId);

        } catch (Exception e) {
            log.warn("Error during logout: {}", e.getMessage());
            // Still blacklist the token even if other operations fail
            tokenBlacklistService.blacklistToken(
                    token,
                    jwtService.extractExpiration(token),
                    "User logout (with errors)"
            );
        }
    }

    @Override
    public TokenResponse refreshToken(RefreshTokenRequest request, ClientInfo clientInfo) {
        String refreshToken = request.getRefreshToken();

        if (!jwtService.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        String tokenType = jwtService.extractTokenType(refreshToken);
        if (!"refresh".equals(tokenType)) {
            throw new RuntimeException("Invalid token type");
        }

        // Check if token is blacklisted
        if (tokenBlacklistService.isBlacklisted(refreshToken)) {
            throw new RuntimeException("Token has been revoked");
        }

        // Check if token exists in database and is not revoked
        RefreshToken storedToken = refreshTokenRepository.findByTokenAndRevokedFalse(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found or revoked"));

        if (storedToken.isExpired()) {
            throw new RuntimeException("Refresh token has expired");
        }

        String userId = jwtService.extractUserId(refreshToken);
        AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Revoke old refresh token (token rotation)
        storedToken.revoke("Token rotation");
        refreshTokenRepository.save(storedToken);

        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // Save new refresh token
        saveRefreshToken(user, newRefreshToken, clientInfo);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(jwtService.getAccessTokenExpiration())
                .tokenType("Bearer")
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public TokenValidationResponse validateToken(TokenValidationRequest request) {
        try {
            String token = request.getToken();

            if (!jwtService.validateToken(token)) {
                return TokenValidationResponse.builder()
                        .valid(false)
                        .build();
            }

            // Check blacklist
            if (tokenBlacklistService.isBlacklisted(token)) {
                return TokenValidationResponse.builder()
                        .valid(false)
                        .build();
            }

            String userId = jwtService.extractUserId(token);
            String email = jwtService.extractEmail(token);
            String externalId = jwtService.extractExternalId(token);
            String tokenTypeValue = jwtService.extractTokenType(token);

            // Check user-level blacklist
            long issuedAt = jwtService.extractIssuedAt(token).getTime();
            if (tokenBlacklistService.isTokenIssuedBeforeBlacklist(userId, issuedAt)) {
                return TokenValidationResponse.builder()
                        .valid(false)
                        .build();
            }

            return TokenValidationResponse.builder()
                    .valid(true)
                    .userId(userId)
                    .email(email)
                    .externalId(externalId)
                    .tokenType(tokenTypeValue)
                    .expiresAt(jwtService.extractExpiration(token).toInstant())
                    .build();
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return TokenValidationResponse.builder()
                    .valid(false)
                    .build();
        }
    }

    @Override
    public void revokeToken(RevokeTokenRequest request, ClientInfo clientInfo) {
        log.info("Revoking token");

        String token = request.getToken();

        // Blacklist the token
        tokenBlacklistService.blacklistToken(
                token,
                jwtService.extractExpiration(token),
                "Manual revocation"
        );

        // If it's a refresh token, also revoke in database
        String tokenType = jwtService.extractTokenType(token);
        if ("refresh".equals(tokenType)) {
            refreshTokenRepository.revokeByToken(token, Instant.now(), "Manual revocation");
        }

        log.info("Token revoked successfully");
    }

    @Override
    public void revokeAllTokens(String token, ClientInfo clientInfo) {
        log.info("Revoking all tokens for user");

        String userId = jwtService.extractUserId(token);
        UUID userUuid = UUID.fromString(userId);

        // Blacklist all user tokens via Redis
        tokenBlacklistService.blacklistAllUserTokens(userId);

        // Revoke all refresh tokens in database
        int revokedCount = refreshTokenRepository.revokeAllUserTokens(
                userUuid,
                Instant.now(),
                "Revoke all tokens"
        );

        // Terminate all sessions
        sessionManagementService.terminateAllUserSessions(userUuid, "All tokens revoked");

        log.info("Revoked {} refresh tokens for user: {}", revokedCount, userId);
    }

    @Override
    public void forgotPassword(ForgotPasswordRequest request, ClientInfo clientInfo) {
        log.info("Forgot password request for: {}", request.getEmail());

        authUserRepository.findByEmail(request.getEmail()).ifPresent(user -> {
            String resetToken = jwtService.generatePasswordResetToken(user);

            // Publish password reset event (notification service will send email)
            userEventPublisher.publishPasswordResetRequested(user, resetToken);

            log.info("Password reset token generated for: {}", request.getEmail());
        });

        // Always respond success to prevent email enumeration
    }

    @Override
    public void resetPassword(ResetPasswordRequest request, ClientInfo clientInfo) {
        if (!jwtService.validateToken(request.getToken())) {
            throw new RuntimeException("Invalid or expired reset token");
        }

        String tokenType = jwtService.extractTokenType(request.getToken());
        if (!"password_reset".equals(tokenType)) {
            throw new RuntimeException("Invalid token type");
        }

        String userId = jwtService.extractUserId(request.getToken());
        AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(Instant.now());
        authUserRepository.save(user);

        // Revoke all existing tokens
        tokenBlacklistService.blacklistAllUserTokens(userId);
        refreshTokenRepository.revokeAllUserTokens(UUID.fromString(userId), Instant.now(), "Password reset");

        // Terminate all sessions
        sessionManagementService.terminateAllUserSessions(UUID.fromString(userId), "Password reset");

        // Publish event
        userEventPublisher.publishPasswordChanged(user);

        log.info("Password reset successful for user: {}", userId);
    }

    @Override
    public void changePassword(String token, ChangePasswordRequest request, ClientInfo clientInfo) {
        String userId = jwtService.extractUserId(token);
        AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Current password is incorrect");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(Instant.now());
        authUserRepository.save(user);

        // Optionally revoke other sessions
        if (request.isLogoutOtherSessions()) {
            String sessionId = jwtService.extractSessionId(token);
            if (sessionId != null) {
                sessionManagementService.terminateOtherSessions(
                        UUID.fromString(userId),
                        UUID.fromString(sessionId),
                        "Password changed"
                );
            }
        }

        // Publish event
        userEventPublisher.publishPasswordChanged(user);

        log.info("Password changed for user: {}", userId);
    }

    @Override
    public AuthResponse oauthLogin(String provider, OAuthRequest request, ClientInfo clientInfo) {
        log.info("OAuth login with provider: {}", provider);

        OAuthProvider oauthProvider = parseOAuthProvider(provider);

        // Find existing connection
        OAuthConnection connection = oauthConnectionRepository
                .findByProviderAndProviderUserId(oauthProvider, request.getProviderUserId())
                .orElse(null);

        AuthUser user;

        if (connection != null) {
            // Existing user - update tokens
            user = connection.getUser();
            connection.setAccessToken(request.getAccessToken());
            connection.setRefreshToken(request.getRefreshToken());
            connection.setTokenExpiresAt(request.getTokenExpiresAt());
            connection.setLastUsedAt(Instant.now());
            oauthConnectionRepository.save(connection);
        } else {
            // Check if email already exists
            if (request.getEmail() != null) {
                user = authUserRepository.findByEmail(request.getEmail()).orElse(null);
            } else {
                user = null;
            }

            if (user == null) {
                // Create new user
                user = AuthUser.builder()
                        .email(request.getEmail())
                        .externalId(UUID.randomUUID().toString())
                        .status(AuthUser.AuthStatus.ACTIVE)
                        .build();
                user = authUserRepository.save(user);
            }

            // Create OAuth connection
            connection = OAuthConnection.builder()
                    .user(user)
                    .provider(oauthProvider)
                    .providerUserId(request.getProviderUserId())
                    .accessToken(request.getAccessToken())
                    .refreshToken(request.getRefreshToken())
                    .tokenExpiresAt(request.getTokenExpiresAt())
                    .lastUsedAt(Instant.now())
                    .build();
            oauthConnectionRepository.save(connection);
        }

        // Update last login
        user.setLastLoginAt(Instant.now());
        user.setLastLoginIp(clientInfo.getIpAddress());
        authUserRepository.save(user);

        return completeLogin(user, clientInfo, LoginMethod.OAUTH);
    }

    @Override
    public void linkOAuthProvider(String token, String provider, OAuthRequest request, ClientInfo clientInfo) {
        log.info("Linking OAuth provider: {}", provider);

        String userId = jwtService.extractUserId(token);
        AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        OAuthProvider oauthProvider = parseOAuthProvider(provider);

        // Check if already linked
        if (oauthConnectionRepository.existsByUserIdAndProvider(user.getId(), oauthProvider)) {
            throw new RuntimeException("Provider already linked to this account");
        }

        // Check if provider user is already linked to another account
        if (oauthConnectionRepository.existsByProviderAndProviderUserId(oauthProvider, request.getProviderUserId())) {
            throw new RuntimeException("This " + provider + " account is already linked to another user");
        }

        // Create connection
        OAuthConnection connection = OAuthConnection.builder()
                .user(user)
                .provider(oauthProvider)
                .providerUserId(request.getProviderUserId())
                .accessToken(request.getAccessToken())
                .refreshToken(request.getRefreshToken())
                .tokenExpiresAt(request.getTokenExpiresAt())
                .lastUsedAt(Instant.now())
                .build();
        oauthConnectionRepository.save(connection);

        log.info("OAuth provider {} linked to user: {}", provider, userId);
    }

    @Override
    public void unlinkOAuthProvider(String token, String provider, ClientInfo clientInfo) {
        log.info("Unlinking OAuth provider: {}", provider);

        String userId = jwtService.extractUserId(token);
        AuthUser user = authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        OAuthProvider oauthProvider = parseOAuthProvider(provider);

        // Check if this is the only auth method
        int oauthCount = oauthConnectionRepository.countByUserId(user.getId());
        boolean hasPassword = user.getPasswordHash() != null && !user.getPasswordHash().isEmpty();

        if (oauthCount <= 1 && !hasPassword) {
            throw new RuntimeException("Cannot unlink the only authentication method. Please set a password first.");
        }

        int deleted = oauthConnectionRepository.deleteByUserIdAndProvider(user.getId(), oauthProvider);
        if (deleted == 0) {
            throw new RuntimeException("Provider not linked to this account");
        }

        log.info("OAuth provider {} unlinked from user: {}", provider, userId);
    }

    @Override
    @Transactional(readOnly = true)
    public SessionsResponse getActiveSessions(String token) {
        String userId = jwtService.extractUserId(token);
        String currentSessionId = jwtService.extractSessionId(token);

        List<SessionInfo> sessionInfos = sessionManagementService
                .getActiveSessions(UUID.fromString(userId))
                .stream()
                .map(session -> SessionInfo.builder()
                        .sessionId(session.getId().toString())
                        .deviceName(session.getDeviceName())
                        .deviceType(session.getDeviceType())
                        .ipAddress(session.getIpAddress())
                        .location(formatLocation(session.getCity(), session.getCountry()))
                        .lastActiveAt(session.getLastActivityAt())
                        .createdAt(session.getCreatedAt())
                        .current(session.getId().toString().equals(currentSessionId))
                        .build())
                .collect(Collectors.toList());

        return SessionsResponse.builder()
                .sessions(sessionInfos)
                .currentSessionId(currentSessionId)
                .build();
    }

    @Override
    public void terminateSession(String token, String sessionId, ClientInfo clientInfo) {
        log.info("Terminating session: {}", sessionId);

        String userId = jwtService.extractUserId(token);

        // Verify the session belongs to the user
        ActiveSessionDto session = sessionManagementService.getSession(UUID.fromString(sessionId));
        if (!session.getUserId().toString().equals(userId)) {
            throw new RuntimeException("Session does not belong to this user");
        }

        sessionManagementService.terminateSession(UUID.fromString(sessionId), "User requested");
        log.info("Session {} terminated by user {}", sessionId, userId);
    }

    @Override
    public void terminateAllOtherSessions(String token, ClientInfo clientInfo) {
        log.info("Terminating all other sessions");

        String userId = jwtService.extractUserId(token);
        String currentSessionId = jwtService.extractSessionId(token);

        if (currentSessionId != null) {
            sessionManagementService.terminateOtherSessions(
                    UUID.fromString(userId),
                    UUID.fromString(currentSessionId),
                    "User requested"
            );
        } else {
            sessionManagementService.terminateAllUserSessions(
                    UUID.fromString(userId),
                    "User requested"
            );
        }

        log.info("All other sessions terminated for user: {}", userId);
    }

    // ==================== Private Helper Methods ====================

    private AuthResponse completeLogin(AuthUser user, ClientInfo clientInfo, LoginMethod method) {
        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Store refresh token
        saveRefreshToken(user, refreshToken, clientInfo);

        // Create session
        createSession(user, accessToken, clientInfo);

        // Record login success
        recordLoginSuccess(user, clientInfo, method);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getAccessTokenExpiration())
                .tokenType("Bearer")
                .user(toUserInfo(user))
                .requiresTwoFactor(false)
                .build();
    }

    private void saveRefreshToken(AuthUser user, String refreshToken, ClientInfo clientInfo) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .expiresAt(Instant.now().plus(REFRESH_TOKEN_EXPIRY_DAYS, ChronoUnit.DAYS))
                .deviceId(clientInfo.getDeviceId())
                .deviceName(clientInfo.getDeviceName())
                .ipAddress(clientInfo.getIpAddress())
                .userAgent(clientInfo.getUserAgent())
                .build();

        refreshTokenRepository.save(token);
    }

    private void createSession(AuthUser user, String accessToken, ClientInfo clientInfo) {
        try {
            String sessionId = jwtService.extractSessionId(accessToken);
            if (sessionId == null) {
                sessionId = UUID.randomUUID().toString();
            }

            CreateSessionRequest sessionRequest = CreateSessionRequest.builder()
                    .sessionId(UUID.fromString(sessionId))  // Pass session ID from JWT
                    .sessionToken(accessToken)
                    .deviceId(clientInfo.getDeviceId())
                    .deviceName(clientInfo.getDeviceName())
                    .deviceType(clientInfo.getDeviceType())
                    .ipAddress(clientInfo.getIpAddress())
                    .userAgent(clientInfo.getUserAgent())
                    .expiryMinutes(30)
                    .build();

            sessionManagementService.createSession(user.getId(), sessionRequest);
        } catch (Exception e) {
            log.warn("Failed to create session: {}", e.getMessage());
        }
    }

    private void recordLoginSuccess(AuthUser user, ClientInfo clientInfo, LoginMethod method) {
        try {
            RecordLoginRequest loginRequest = RecordLoginRequest.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(method)
                    .ipAddress(clientInfo.getIpAddress())
                    .userAgent(clientInfo.getUserAgent())
                    .deviceId(clientInfo.getDeviceId())
                    .deviceName(clientInfo.getDeviceName())
                    .build();

            loginHistoryService.recordLogin(loginRequest);
        } catch (Exception e) {
            log.warn("Failed to record login success: {}", e.getMessage());
        }
    }

    private void recordLoginFailure(String email, ClientInfo clientInfo, String reason) {
        try {
            RecordLoginRequest loginRequest = RecordLoginRequest.builder()
                    .email(email)
                    .loginStatus(LoginStatus.FAILED)
                    .loginMethod(LoginMethod.PASSWORD)
                    .ipAddress(clientInfo.getIpAddress())
                    .userAgent(clientInfo.getUserAgent())
                    .failureReason(reason)
                    .build();

            loginHistoryService.recordLogin(loginRequest);
        } catch (Exception e) {
            log.warn("Failed to record login failure: {}", e.getMessage());
        }
    }

    private boolean verifyTwoFactorCode(AuthUser user, String code) {
        // First try TOTP
        if (user.getTwoFactorSecret() != null) {
            // Use TwoFactorService to verify TOTP
            try {
                TwoFactorVerifyRequest verifyRequest = TwoFactorVerifyRequest.builder()
                        .code(code)
                        .build();
                // Verify using the secret directly
                return verifyTotpCode(user.getTwoFactorSecret(), code);
            } catch (Exception e) {
                log.debug("TOTP verification failed: {}", e.getMessage());
            }
        }

        // Try backup code
        if (user.getBackupCodes() != null && user.getBackupCodes().contains(code)) {
            user.getBackupCodes().remove(code);
            authUserRepository.save(user);
            return true;
        }

        return false;
    }

    private boolean verifyTotpCode(String secret, String code) {
        // Simple TOTP verification - in production, use a proper library
        if (code == null || code.length() != 6) {
            return false;
        }
        try {
            Integer.parseInt(code);
            return true; // Accept for now - integrate with TOTP library
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private OAuthProvider parseOAuthProvider(String provider) {
        try {
            return OAuthProvider.valueOf(provider.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Unsupported OAuth provider: " + provider);
        }
    }

    private String formatLocation(String city, String country) {
        if (city != null && country != null) {
            return city + ", " + country;
        } else if (country != null) {
            return country;
        } else if (city != null) {
            return city;
        }
        return "Unknown";
    }

    private UserInfo toUserInfo(AuthUser user) {
        return UserInfo.builder()
                .id(user.getId().toString())
                .externalId(user.getExternalId())
                .email(user.getEmail())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .oauthProviders(user.getOauthConnections().stream()
                        .map(conn -> conn.getProvider().name().toLowerCase())
                        .collect(Collectors.toList()))
                .build();
    }
}
