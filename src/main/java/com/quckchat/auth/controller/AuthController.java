package com.quckchat.auth.controller;

import com.quckchat.auth.dto.*;
import com.quckchat.auth.service.AuthService;
import com.quckchat.auth.service.TwoFactorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Auth Controller - Authentication endpoints
 */
@RestController
@RequestMapping("/v1")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final AuthService authService;
    private final TwoFactorService twoFactorService;

    // ============================================
    // Registration & Login
    // ============================================

    @PostMapping("/register")
    @Operation(summary = "Register new user")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.register(request, getClientInfo(httpRequest)));
    }

    @PostMapping("/login")
    @Operation(summary = "Login with email/password")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.login(request, getClientInfo(httpRequest)));
    }

    @PostMapping("/login/2fa")
    @Operation(summary = "Complete login with 2FA code")
    public ResponseEntity<AuthResponse> loginWith2FA(
            @Valid @RequestBody TwoFactorLoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.loginWith2FA(request, getClientInfo(httpRequest)));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout and revoke tokens")
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        authService.logout(extractToken(authHeader), getClientInfo(httpRequest));
        return ResponseEntity.ok().build();
    }

    // ============================================
    // Token Management
    // ============================================

    @PostMapping("/token/refresh")
    @Operation(summary = "Refresh access token")
    public ResponseEntity<TokenResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.refreshToken(request, getClientInfo(httpRequest)));
    }

    @PostMapping("/token/validate")
    @Operation(summary = "Validate JWT token")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        return ResponseEntity.ok(authService.validateToken(request));
    }

    @PostMapping("/token/revoke")
    @Operation(summary = "Revoke a specific token")
    public ResponseEntity<Void> revokeToken(
            @Valid @RequestBody RevokeTokenRequest request,
            HttpServletRequest httpRequest) {
        authService.revokeToken(request, getClientInfo(httpRequest));
        return ResponseEntity.ok().build();
    }

    @PostMapping("/token/revoke-all")
    @Operation(summary = "Revoke all tokens for current user")
    public ResponseEntity<Void> revokeAllTokens(
            @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        authService.revokeAllTokens(extractToken(authHeader), getClientInfo(httpRequest));
        return ResponseEntity.ok().build();
    }

    // ============================================
    // Password Management
    // ============================================

    @PostMapping("/password/forgot")
    @Operation(summary = "Request password reset")
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest) {
        authService.forgotPassword(request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Password reset email sent if account exists"));
    }

    @PostMapping("/password/reset")
    @Operation(summary = "Reset password with token")
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest) {
        authService.resetPassword(request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Password reset successful"));
    }

    @PostMapping("/password/change")
    @Operation(summary = "Change password (authenticated)")
    public ResponseEntity<MessageResponse> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        authService.changePassword(extractToken(authHeader), request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
    }

    // ============================================
    // Two-Factor Authentication
    // ============================================

    @PostMapping("/2fa/setup")
    @Operation(summary = "Setup 2FA - get QR code")
    public ResponseEntity<TwoFactorSetupResponse> setup2FA(
            @RequestHeader("Authorization") String authHeader) {
        return ResponseEntity.ok(twoFactorService.setupTwoFactor(extractToken(authHeader)));
    }

    @PostMapping("/2fa/enable")
    @Operation(summary = "Enable 2FA after verification")
    public ResponseEntity<TwoFactorEnableResponse> enable2FA(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorEnableRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(twoFactorService.enableTwoFactor(
                extractToken(authHeader), request, getClientInfo(httpRequest)));
    }

    @PostMapping("/2fa/disable")
    @Operation(summary = "Disable 2FA")
    public ResponseEntity<MessageResponse> disable2FA(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorDisableRequest request,
            HttpServletRequest httpRequest) {
        twoFactorService.disableTwoFactor(extractToken(authHeader), request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("2FA disabled successfully"));
    }

    @PostMapping("/2fa/backup-codes")
    @Operation(summary = "Generate new backup codes")
    public ResponseEntity<BackupCodesResponse> generateBackupCodes(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorVerifyRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(twoFactorService.generateBackupCodes(
                extractToken(authHeader), request, getClientInfo(httpRequest)));
    }

    // ============================================
    // OAuth2
    // ============================================

    @PostMapping("/oauth/{provider}")
    @Operation(summary = "Login/register with OAuth provider")
    public ResponseEntity<AuthResponse> oauthLogin(
            @PathVariable String provider,
            @Valid @RequestBody OAuthRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.oauthLogin(provider, request, getClientInfo(httpRequest)));
    }

    @PostMapping("/oauth/{provider}/link")
    @Operation(summary = "Link OAuth provider to existing account")
    public ResponseEntity<MessageResponse> linkOAuthProvider(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable String provider,
            @Valid @RequestBody OAuthRequest request,
            HttpServletRequest httpRequest) {
        authService.linkOAuthProvider(extractToken(authHeader), provider, request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Provider linked successfully"));
    }

    @DeleteMapping("/oauth/{provider}/unlink")
    @Operation(summary = "Unlink OAuth provider from account")
    public ResponseEntity<MessageResponse> unlinkOAuthProvider(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable String provider,
            HttpServletRequest httpRequest) {
        authService.unlinkOAuthProvider(extractToken(authHeader), provider, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Provider unlinked successfully"));
    }

    // ============================================
    // Sessions
    // ============================================

    @GetMapping("/sessions")
    @Operation(summary = "Get active sessions")
    public ResponseEntity<SessionsResponse> getSessions(
            @RequestHeader("Authorization") String authHeader) {
        return ResponseEntity.ok(authService.getActiveSessions(extractToken(authHeader)));
    }

    @DeleteMapping("/sessions/{sessionId}")
    @Operation(summary = "Terminate specific session")
    public ResponseEntity<Void> terminateSession(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable String sessionId,
            HttpServletRequest httpRequest) {
        authService.terminateSession(extractToken(authHeader), sessionId, getClientInfo(httpRequest));
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/sessions")
    @Operation(summary = "Terminate all other sessions")
    public ResponseEntity<Void> terminateAllSessions(
            @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        authService.terminateAllOtherSessions(extractToken(authHeader), getClientInfo(httpRequest));
        return ResponseEntity.ok().build();
    }

    // ============================================
    // Helpers
    // ============================================

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }

    private ClientInfo getClientInfo(HttpServletRequest request) {
        return ClientInfo.builder()
                .ipAddress(getClientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .deviceId(request.getHeader("X-Device-ID"))
                .build();
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
