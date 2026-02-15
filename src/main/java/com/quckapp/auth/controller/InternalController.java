package com.quckapp.auth.controller;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.AuthUser.AuthStatus;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.dto.UserProfileDtos.UserProfileDto;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.AuthService;
import com.quckapp.auth.service.SessionManagementService;
import com.quckapp.auth.service.UserProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Internal API Controller for service-to-service communication
 * All endpoints require API Key authentication via X-API-Key header
 */
@RestController
@RequestMapping("/v1/internal")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Internal", description = "Internal service-to-service endpoints")
@SecurityRequirement(name = "apiKey")
public class InternalController {

    private final AuthUserRepository authUserRepository;
    private final JwtOperations jwtOperations;
    private final AuthService authService;
    private final SessionManagementService sessionManagementService;
    private final UserProfileService userProfileService;

    // ==================== Token Introspection ====================

    @PostMapping("/token/introspect")
    @Operation(summary = "Introspect JWT token",
               description = "Validate and decode a JWT token, returning user info and claims. Used by other services to validate incoming requests.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Token introspection result"),
        @ApiResponse(responseCode = "401", description = "Invalid API key")
    })
    public ResponseEntity<TokenIntrospectionResponse> introspectToken(
            @RequestHeader("X-API-Key") String apiKey,
            @Valid @RequestBody TokenIntrospectionRequest request) {
        log.debug("Token introspection request");

        try {
            String token = request.getToken();

            if (jwtOperations.isTokenExpired(token)) {
                return ResponseEntity.ok(TokenIntrospectionResponse.builder()
                        .active(false)
                        .reason("Token expired")
                        .build());
            }

            String userId = jwtOperations.extractUserId(token);
            String email = jwtOperations.extractEmail(token);
            String externalId = jwtOperations.extractExternalId(token);
            String sessionId = jwtOperations.extractSessionId(token);
            String tokenType = jwtOperations.extractTokenType(token);
            Date expiration = jwtOperations.extractExpiration(token);
            Date issuedAt = jwtOperations.extractIssuedAt(token);

            // Check if user still exists and is active
            Optional<AuthUser> userOpt = authUserRepository.findById(UUID.fromString(userId));
            if (userOpt.isEmpty()) {
                return ResponseEntity.ok(TokenIntrospectionResponse.builder()
                        .active(false)
                        .reason("User not found")
                        .build());
            }

            AuthUser user = userOpt.get();
            if (!user.isActive()) {
                return ResponseEntity.ok(TokenIntrospectionResponse.builder()
                        .active(false)
                        .reason("User account is " + user.getStatus().name().toLowerCase())
                        .build());
            }

            return ResponseEntity.ok(TokenIntrospectionResponse.builder()
                    .active(true)
                    .userId(userId)
                    .email(email)
                    .externalId(externalId)
                    .sessionId(sessionId)
                    .tokenType(tokenType)
                    .issuedAt(issuedAt.toInstant())
                    .expiresAt(expiration.toInstant())
                    .twoFactorEnabled(user.isTwoFactorEnabled())
                    .emailVerified(user.isEmailVerified())
                    .build());

        } catch (Exception e) {
            log.warn("Token introspection failed: {}", e.getMessage());
            return ResponseEntity.ok(TokenIntrospectionResponse.builder()
                    .active(false)
                    .reason("Invalid token: " + e.getMessage())
                    .build());
        }
    }

    // ==================== User Validation ====================

    @GetMapping("/users/{userId}/validate")
    @Operation(summary = "Validate user exists and is active",
               description = "Quick check if a user ID is valid and the account is active")
    public ResponseEntity<UserValidationResponse> validateUser(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable UUID userId) {
        log.debug("User validation request for: {}", userId);

        Optional<AuthUser> userOpt = authUserRepository.findById(userId);

        if (userOpt.isEmpty()) {
            return ResponseEntity.ok(UserValidationResponse.builder()
                    .valid(false)
                    .reason("User not found")
                    .build());
        }

        AuthUser user = userOpt.get();
        boolean isValid = user.isActive();

        return ResponseEntity.ok(UserValidationResponse.builder()
                .valid(isValid)
                .userId(userId.toString())
                .email(user.getEmail())
                .externalId(user.getExternalId())
                .status(user.getStatus().name())
                .reason(isValid ? null : "User account is " + user.getStatus().name().toLowerCase())
                .build());
    }

    @PostMapping("/users/validate/batch")
    @Operation(summary = "Batch validate multiple users",
               description = "Validate multiple user IDs in a single request")
    public ResponseEntity<BatchUserValidationResponse> validateUsersBatch(
            @RequestHeader("X-API-Key") String apiKey,
            @Valid @RequestBody BatchUserValidationRequest request) {
        log.debug("Batch user validation for {} users", request.getUserIds().size());

        Map<String, UserValidationResponse> results = new HashMap<>();

        for (UUID userId : request.getUserIds()) {
            Optional<AuthUser> userOpt = authUserRepository.findById(userId);

            if (userOpt.isEmpty()) {
                results.put(userId.toString(), UserValidationResponse.builder()
                        .valid(false)
                        .userId(userId.toString())
                        .reason("User not found")
                        .build());
            } else {
                AuthUser user = userOpt.get();
                boolean isValid = user.isActive();
                results.put(userId.toString(), UserValidationResponse.builder()
                        .valid(isValid)
                        .userId(userId.toString())
                        .email(user.getEmail())
                        .externalId(user.getExternalId())
                        .status(user.getStatus().name())
                        .reason(isValid ? null : "User account is " + user.getStatus().name().toLowerCase())
                        .build());
            }
        }

        long validCount = results.values().stream().filter(UserValidationResponse::isValid).count();

        return ResponseEntity.ok(BatchUserValidationResponse.builder()
                .totalRequested(request.getUserIds().size())
                .validCount((int) validCount)
                .invalidCount(request.getUserIds().size() - (int) validCount)
                .results(results)
                .build());
    }

    // ==================== User Lookup ====================

    @GetMapping("/users/by-email/{email}")
    @Operation(summary = "Get user by email",
               description = "Look up user ID and basic info by email address")
    public ResponseEntity<InternalUserResponse> getUserByEmail(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable String email) {
        log.debug("User lookup by email: {}", email);

        return authUserRepository.findByEmail(email)
                .map(user -> ResponseEntity.ok(mapToInternalUserResponse(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/users/by-external-id/{externalId}")
    @Operation(summary = "Get user by external ID",
               description = "Look up user by their external ID (from user service)")
    public ResponseEntity<InternalUserResponse> getUserByExternalId(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable String externalId) {
        log.debug("User lookup by external ID: {}", externalId);

        return authUserRepository.findByExternalId(externalId)
                .map(user -> ResponseEntity.ok(mapToInternalUserResponse(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/lookup/batch")
    @Operation(summary = "Batch lookup users",
               description = "Look up multiple users by their IDs")
    public ResponseEntity<Map<String, InternalUserResponse>> lookupUsersBatch(
            @RequestHeader("X-API-Key") String apiKey,
            @Valid @RequestBody BatchUserLookupRequest request) {
        log.debug("Batch user lookup for {} users", request.getUserIds().size());

        Map<String, InternalUserResponse> results = new HashMap<>();

        List<AuthUser> users = authUserRepository.findAllById(request.getUserIds());

        for (AuthUser user : users) {
            results.put(user.getId().toString(), mapToInternalUserResponse(user));
        }

        return ResponseEntity.ok(results);
    }

    // ==================== User Profile Lookup (with phone numbers) ====================

    @GetMapping("/users/profiles/batch")
    @Operation(summary = "Get user profiles by IDs",
               description = "Fetch full user profiles (including phone numbers) by IDs. Used for enriching conversation data.")
    public ResponseEntity<List<UserProfileDto>> getProfilesByIds(
            @RequestHeader("X-API-Key") String apiKey,
            @RequestParam List<UUID> ids) {
        log.debug("Internal batch profile lookup for {} users", ids.size());
        return ResponseEntity.ok(userProfileService.getUsersByIds(ids));
    }

    @GetMapping("/users/profiles/batch/external")
    @Operation(summary = "Get user profiles by external IDs",
               description = "Fetch full user profiles (including phone numbers) by external IDs.")
    public ResponseEntity<List<UserProfileDto>> getProfilesByExternalIds(
            @RequestHeader("X-API-Key") String apiKey,
            @RequestParam List<String> externalIds) {
        log.debug("Internal batch profile lookup by external IDs for {} users", externalIds.size());
        return ResponseEntity.ok(userProfileService.getUsersByExternalIds(externalIds));
    }

    // ==================== Session Management ====================

    @GetMapping("/users/{userId}/sessions/count")
    @Operation(summary = "Get user's active session count",
               description = "Returns the number of active sessions for a user")
    public ResponseEntity<Map<String, Object>> getUserSessionCount(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable UUID userId) {
        int count = sessionManagementService.countActiveSessions(userId);
        return ResponseEntity.ok(Map.of(
                "userId", userId.toString(),
                "activeSessions", count
        ));
    }

    @PostMapping("/users/{userId}/sessions/terminate-all")
    @Operation(summary = "Terminate all user sessions",
               description = "Force logout a user from all devices. Use for security incidents or account compromise.")
    public ResponseEntity<Map<String, String>> terminateAllUserSessions(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable UUID userId,
            @RequestBody(required = false) TerminateSessionsRequest request) {
        String reason = request != null && request.getReason() != null
                ? request.getReason()
                : "Terminated by internal service";

        log.info("Terminating all sessions for user {} - Reason: {}", userId, reason);
        sessionManagementService.terminateAllUserSessions(userId, reason);

        return ResponseEntity.ok(Map.of(
                "message", "All sessions terminated",
                "userId", userId.toString()
        ));
    }

    // ==================== Account Status ====================

    @PostMapping("/users/{userId}/lock")
    @Operation(summary = "Lock user account",
               description = "Temporarily lock a user account for a specified duration")
    public ResponseEntity<Map<String, Object>> lockUserAccount(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable UUID userId,
            @Valid @RequestBody LockAccountRequest request) {
        log.info("Locking account for user {} - Duration: {} minutes, Reason: {}",
                userId, request.getDurationMinutes(), request.getReason());

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        Instant lockUntil = Instant.now().plusSeconds(request.getDurationMinutes() * 60L);
        user.setLockedUntil(lockUntil);
        authUserRepository.save(user);

        // Terminate all sessions
        sessionManagementService.terminateAllUserSessions(userId, "Account locked: " + request.getReason());

        return ResponseEntity.ok(Map.of(
                "message", "Account locked",
                "userId", userId.toString(),
                "lockedUntil", lockUntil.toString()
        ));
    }

    @PostMapping("/users/{userId}/unlock")
    @Operation(summary = "Unlock user account",
               description = "Remove lock from a user account")
    public ResponseEntity<Map<String, String>> unlockUserAccount(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable UUID userId) {
        log.info("Unlocking account for user {}", userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        user.setLockedUntil(null);
        user.resetFailedAttempts();
        authUserRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "Account unlocked",
                "userId", userId.toString()
        ));
    }

    @PostMapping("/users/{userId}/status")
    @Operation(summary = "Update user status",
               description = "Change user account status (ACTIVE, INACTIVE, SUSPENDED)")
    public ResponseEntity<Map<String, String>> updateUserStatus(
            @RequestHeader("X-API-Key") String apiKey,
            @PathVariable UUID userId,
            @Valid @RequestBody UpdateStatusInternalRequest request) {
        log.info("Updating status for user {} to {}", userId, request.getStatus());

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        AuthStatus newStatus = AuthStatus.valueOf(request.getStatus().toUpperCase());
        user.setStatus(newStatus);
        authUserRepository.save(user);

        // If suspending, terminate sessions
        if (newStatus == AuthStatus.SUSPENDED || newStatus == AuthStatus.INACTIVE) {
            sessionManagementService.terminateAllUserSessions(userId, "Account status changed to " + newStatus);
        }

        return ResponseEntity.ok(Map.of(
                "message", "Status updated",
                "userId", userId.toString(),
                "status", newStatus.name()
        ));
    }

    // ==================== Security Events ====================

    @PostMapping("/security/report-suspicious")
    @Operation(summary = "Report suspicious activity",
               description = "Report suspicious activity for a user account. May trigger security measures.")
    public ResponseEntity<Map<String, String>> reportSuspiciousActivity(
            @RequestHeader("X-API-Key") String apiKey,
            @Valid @RequestBody SuspiciousActivityRequest request) {
        log.warn("Suspicious activity reported for user {} - Type: {}, Source: {}",
                request.getUserId(), request.getActivityType(), request.getSourceService());

        // In a real implementation, this would:
        // 1. Log to security audit
        // 2. Potentially lock account
        // 3. Send notifications
        // 4. Trigger fraud detection

        return ResponseEntity.ok(Map.of(
                "message", "Suspicious activity reported",
                "userId", request.getUserId().toString(),
                "activityType", request.getActivityType()
        ));
    }

    // ==================== Health Check ====================

    @GetMapping("/health")
    @Operation(summary = "Internal health check",
               description = "Check if auth service is healthy and responsive")
    public ResponseEntity<Map<String, Object>> healthCheck(
            @RequestHeader("X-API-Key") String apiKey) {
        return ResponseEntity.ok(Map.of(
                "status", "healthy",
                "service", "auth-service",
                "timestamp", Instant.now().toString()
        ));
    }

    // ==================== Helper Methods ====================

    private InternalUserResponse mapToInternalUserResponse(AuthUser user) {
        return InternalUserResponse.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .externalId(user.getExternalId())
                .status(user.getStatus().name())
                .emailVerified(user.isEmailVerified())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .locked(user.isLocked())
                .lockedUntil(user.getLockedUntil())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .build();
    }

    // ==================== Request/Response DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenIntrospectionRequest {
        @NotBlank
        private String token;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenIntrospectionResponse {
        private boolean active;
        private String userId;
        private String email;
        private String externalId;
        private String sessionId;
        private String tokenType;
        private Instant issuedAt;
        private Instant expiresAt;
        private boolean twoFactorEnabled;
        private boolean emailVerified;
        private String reason;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class UserValidationResponse {
        private boolean valid;
        private String userId;
        private String email;
        private String externalId;
        private String status;
        private String reason;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BatchUserValidationRequest {
        @NotEmpty
        private List<UUID> userIds;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BatchUserValidationResponse {
        private int totalRequested;
        private int validCount;
        private int invalidCount;
        private Map<String, UserValidationResponse> results;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BatchUserLookupRequest {
        @NotEmpty
        private List<UUID> userIds;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class InternalUserResponse {
        private String id;
        private String email;
        private String externalId;
        private String status;
        private boolean emailVerified;
        private boolean twoFactorEnabled;
        private boolean locked;
        private Instant lockedUntil;
        private Instant lastLoginAt;
        private Instant createdAt;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TerminateSessionsRequest {
        private String reason;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class LockAccountRequest {
        @jakarta.validation.constraints.Min(1)
        @jakarta.validation.constraints.Max(43200) // Max 30 days
        private int durationMinutes;

        @NotBlank
        private String reason;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class UpdateStatusInternalRequest {
        @NotBlank
        @jakarta.validation.constraints.Pattern(regexp = "ACTIVE|INACTIVE|SUSPENDED|PENDING_VERIFICATION")
        private String status;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class SuspiciousActivityRequest {
        @jakarta.validation.constraints.NotNull
        private UUID userId;

        @NotBlank
        private String activityType;

        @NotBlank
        private String sourceService;

        private String details;

        private String ipAddress;
    }
}
