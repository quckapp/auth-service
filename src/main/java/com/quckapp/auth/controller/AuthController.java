package com.quckapp.auth.controller;

import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.security.ratelimit.RateLimitExceededException;
import com.quckapp.auth.security.ratelimit.RateLimitResult;
import com.quckapp.auth.security.ratelimit.RateLimitOperations;
import com.quckapp.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Auth Controller - Authentication endpoints
 */
@RestController
@RequestMapping("/v1")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final AuthService authService;
    private final RateLimitOperations rateLimitService;

    // ============================================
    // Registration & Login
    // ============================================

    @PostMapping("/register")
    @Operation(summary = "Register new user")
    @RateLimit(requests = 5, window = 3600, key = KeyType.IP, message = "Too many registration attempts. Please try again later.")
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

        String email = request.getEmail();
        String clientIp = getClientIp(httpRequest);

        // Check login rate limit (email + IP combination)
        RateLimitResult rateLimitResult = rateLimitService.checkLoginRateLimit(email, clientIp);
        if (rateLimitResult.isBlocked()) {
            throw RateLimitExceededException.loginBlocked(rateLimitResult.getRetryAfterSeconds());
        }
        if (rateLimitResult.isDenied()) {
            throw RateLimitExceededException.loginLimit(rateLimitResult.getRetryAfterSeconds());
        }

        try {
            AuthResponse response = authService.login(request, getClientInfo(httpRequest));

            // Clear failed attempts on successful login
            rateLimitService.clearLoginAttempts(email, clientIp);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // Record failed login attempt
            rateLimitService.recordFailedLogin(email, clientIp);
            throw e;
        }
    }

    @PostMapping("/login/2fa")
    @Operation(summary = "Complete login with 2FA code")
    @RateLimit(requests = 5, window = 300, key = KeyType.IP, message = "Too many 2FA attempts. Please try again later.")
    public ResponseEntity<AuthResponse> loginWith2FA(
            @Valid @RequestBody TwoFactorLoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.loginWith2FA(request, getClientInfo(httpRequest)));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout and revoke tokens")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Void> logout(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        authService.logout(extractToken(authHeader), getClientInfo(httpRequest));
        return ResponseEntity.ok().build();
    }

    // ============================================
    // Token Management — handled by TokenController at /v1/token
    // ============================================

    // ============================================
    // Password Management
    // ============================================

    @PostMapping("/password/forgot")
    @Operation(summary = "Request password reset")
    @RateLimit(requests = 3, window = 3600, key = KeyType.IP, message = "Too many password reset requests. Please try again later.")
    public ResponseEntity<MessageResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest httpRequest) {
        authService.forgotPassword(request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Password reset email sent if account exists"));
    }

    @PostMapping("/password/reset")
    @Operation(summary = "Reset password with token")
    @RateLimit(requests = 5, window = 3600, key = KeyType.IP)
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest) {
        authService.resetPassword(request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Password reset successful"));
    }

    @PostMapping("/password/change")
    @Operation(summary = "Change password (authenticated)")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 5, window = 3600, key = KeyType.USER)
    public ResponseEntity<MessageResponse> changePassword(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        authService.changePassword(extractToken(authHeader), request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
    }

    // ============================================
    // Two-Factor Authentication — handled by TwoFactorController at /v1/2fa
    // ============================================

    // ============================================
    // OAuth2
    // ============================================

    @PostMapping("/oauth/{provider}")
    @Operation(summary = "Login/register with OAuth provider")
    @RateLimit(requests = 10, window = 60, key = KeyType.IP)
    public ResponseEntity<AuthResponse> oauthLogin(
            @PathVariable String provider,
            @Valid @RequestBody OAuthRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.oauthLogin(provider, request, getClientInfo(httpRequest)));
    }

    @PostMapping("/oauth/{provider}/link")
    @Operation(summary = "Link OAuth provider to existing account")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 5, window = 3600, key = KeyType.USER)
    public ResponseEntity<MessageResponse> linkOAuthProvider(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String provider,
            @Valid @RequestBody OAuthRequest request,
            HttpServletRequest httpRequest) {
        authService.linkOAuthProvider(extractToken(authHeader), provider, request, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Provider linked successfully"));
    }

    @DeleteMapping("/oauth/{provider}/unlink")
    @Operation(summary = "Unlink OAuth provider from account")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 5, window = 3600, key = KeyType.USER)
    public ResponseEntity<MessageResponse> unlinkOAuthProvider(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String provider,
            HttpServletRequest httpRequest) {
        authService.unlinkOAuthProvider(extractToken(authHeader), provider, getClientInfo(httpRequest));
        return ResponseEntity.ok(new MessageResponse("Provider unlinked successfully"));
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
