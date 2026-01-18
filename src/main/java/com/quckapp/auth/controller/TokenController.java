package com.quckapp.auth.controller;

import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST Controller for JWT Token management
 * Provides endpoints for refreshing, validating, and revoking tokens
 */
@RestController
@RequestMapping("/v1/token")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Token Management", description = "JWT token operations - refresh, validate, and revoke tokens")
public class TokenController {

    private final AuthService authService;
    private final JwtOperations jwtOperations;
    private final RefreshTokenRepository refreshTokenRepository;

    // ==================== Token Refresh ====================

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token",
               description = "Exchange a valid refresh token for a new access token and refresh token pair")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Tokens refreshed successfully"),
        @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token")
    })
    @RateLimit(requests = 30, window = 60, key = KeyType.IP)
    public ResponseEntity<TokenResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        log.debug("Token refresh request from IP: {}", getClientIp(httpRequest));
        return ResponseEntity.ok(authService.refreshToken(request, getClientInfo(httpRequest)));
    }

    // ==================== Token Validation ====================

    @PostMapping("/validate")
    @Operation(summary = "Validate JWT token",
               description = "Check if a token is valid and return its claims if so")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Validation result returned"),
        @ApiResponse(responseCode = "400", description = "Invalid request")
    })
    @RateLimit(requests = 100, window = 60, key = KeyType.IP)
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        log.debug("Token validation request");
        return ResponseEntity.ok(authService.validateToken(request));
    }

    @GetMapping("/info")
    @Operation(summary = "Get current token info",
               description = "Get information about the current access token")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<TokenInfoResponse> getTokenInfo(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);

        try {
            String userId = jwtOperations.extractUserId(token);
            String email = jwtOperations.extractEmail(token);
            String sessionId = jwtOperations.extractSessionId(token);
            String tokenType = jwtOperations.extractTokenType(token);
            Instant expiration = jwtOperations.extractExpiration(token).toInstant();
            Instant issuedAt = jwtOperations.extractIssuedAt(token).toInstant();

            TokenInfoResponse response = TokenInfoResponse.builder()
                    .userId(userId)
                    .email(email)
                    .sessionId(sessionId)
                    .tokenType(tokenType)
                    .issuedAt(issuedAt)
                    .expiresAt(expiration)
                    .valid(!jwtOperations.isTokenExpired(token))
                    .remainingSeconds(Math.max(0, expiration.getEpochSecond() - Instant.now().getEpochSecond()))
                    .build();

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.warn("Failed to extract token info: {}", e.getMessage());
            return ResponseEntity.ok(TokenInfoResponse.builder()
                    .valid(false)
                    .build());
        }
    }

    // ==================== Token Revocation ====================

    @PostMapping("/revoke")
    @Operation(summary = "Revoke a specific token",
               description = "Revoke a specific refresh token, preventing it from being used again")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Token revoked successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> revokeToken(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody RevokeTokenRequest request,
            HttpServletRequest httpRequest) {
        String token = extractToken(authHeader);
        log.info("Token revocation request");

        authService.revokeToken(token, request, getClientInfo(httpRequest));

        return ResponseEntity.ok(Map.of("message", "Token revoked successfully"));
    }

    @PostMapping("/revoke-all")
    @Operation(summary = "Revoke all refresh tokens",
               description = "Revoke all refresh tokens for the current user, logging out all devices")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 5, window = 300, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> revokeAllTokens(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            HttpServletRequest httpRequest) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        log.info("Revoking all tokens for user: {}", userId);
        authService.revokeAllTokens(token, getClientInfo(httpRequest));

        return ResponseEntity.ok(Map.of("message", "All tokens revoked successfully"));
    }

    // ==================== Active Tokens ====================

    @GetMapping("/active")
    @Operation(summary = "List active refresh tokens",
               description = "Get a list of all active (non-revoked, non-expired) refresh tokens for the current user")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<ActiveTokensResponse> getActiveTokens(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        List<RefreshToken> tokens = refreshTokenRepository.findValidTokensByUserId(
                UUID.fromString(userId), Instant.now());

        List<TokenSummary> tokenSummaries = tokens.stream()
                .map(t -> TokenSummary.builder()
                        .id(t.getId().toString())
                        .deviceId(t.getDeviceId())
                        .deviceName(t.getDeviceName())
                        .ipAddress(t.getIpAddress())
                        .createdAt(t.getCreatedAt())
                        .expiresAt(t.getExpiresAt())
                        .oauthProvider(t.getOauthProvider())
                        .build())
                .collect(Collectors.toList());

        return ResponseEntity.ok(ActiveTokensResponse.builder()
                .userId(userId)
                .activeTokenCount(tokenSummaries.size())
                .tokens(tokenSummaries)
                .build());
    }

    @GetMapping("/count")
    @Operation(summary = "Get active token count",
               description = "Returns the number of active refresh tokens for the current user")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Integer>> getTokenCount(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        int count = refreshTokenRepository.countActiveTokensByUserId(
                UUID.fromString(userId), Instant.now());

        return ResponseEntity.ok(Map.of("activeTokens", count));
    }

    // ==================== Token History ====================

    @GetMapping("/history")
    @Operation(summary = "Get token history",
               description = "Get history of all refresh tokens (including revoked) for the current user")
    @SecurityRequirement(name = "bearerAuth")
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<TokenHistoryResponse> getTokenHistory(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @RequestParam(defaultValue = "20") int limit) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        List<RefreshToken> tokens = refreshTokenRepository.findByUserId(UUID.fromString(userId));

        // Limit results
        List<TokenHistoryEntry> history = tokens.stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                .limit(Math.min(limit, 100))
                .map(t -> TokenHistoryEntry.builder()
                        .id(t.getId().toString())
                        .deviceId(t.getDeviceId())
                        .deviceName(t.getDeviceName())
                        .ipAddress(t.getIpAddress())
                        .createdAt(t.getCreatedAt())
                        .expiresAt(t.getExpiresAt())
                        .revoked(t.isRevoked())
                        .revokedAt(t.getRevokedAt())
                        .revokedReason(t.getRevokedReason())
                        .oauthProvider(t.getOauthProvider())
                        .build())
                .collect(Collectors.toList());

        return ResponseEntity.ok(TokenHistoryResponse.builder()
                .userId(userId)
                .totalTokens(tokens.size())
                .entries(history)
                .build());
    }

    // ==================== Internal DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenInfoResponse {
        private String userId;
        private String email;
        private String sessionId;
        private String tokenType;
        private Instant issuedAt;
        private Instant expiresAt;
        private boolean valid;
        private long remainingSeconds;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class ActiveTokensResponse {
        private String userId;
        private int activeTokenCount;
        private List<TokenSummary> tokens;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenSummary {
        private String id;
        private String deviceId;
        private String deviceName;
        private String ipAddress;
        private Instant createdAt;
        private Instant expiresAt;
        private String oauthProvider;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenHistoryResponse {
        private String userId;
        private int totalTokens;
        private List<TokenHistoryEntry> entries;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenHistoryEntry {
        private String id;
        private String deviceId;
        private String deviceName;
        private String ipAddress;
        private Instant createdAt;
        private Instant expiresAt;
        private boolean revoked;
        private Instant revokedAt;
        private String revokedReason;
        private String oauthProvider;
    }

    // ==================== Helpers ====================

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
