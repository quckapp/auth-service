package com.quckapp.auth.controller;

import com.quckapp.auth.dto.SessionDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.service.SessionManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REST Controller for Session management
 * Provides endpoints for viewing, managing, and terminating user sessions
 */
@RestController
@RequestMapping("/v1/sessions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Sessions", description = "Active session management and device tracking")
@SecurityRequirement(name = "bearerAuth")
public class SessionController {

    private final SessionManagementService sessionManagementService;
    private final JwtOperations jwtOperations;

    // ==================== Session Retrieval ====================

    @GetMapping
    @Operation(summary = "Get all sessions for current user",
               description = "Returns all active and inactive sessions for the authenticated user")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Sessions retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<UserSessionsResponse> getUserSessions(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);
        String sessionId = jwtOperations.extractSessionId(token);

        log.debug("Getting sessions for user: {}", userId);

        UserSessionsResponse response = sessionManagementService.getUserSessions(
                UUID.fromString(userId),
                sessionId != null ? UUID.fromString(sessionId) : null
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/active")
    @Operation(summary = "Get active sessions only",
               description = "Returns only currently active sessions for the authenticated user")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<List<ActiveSessionDto>> getActiveSessions(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        log.debug("Getting active sessions for user: {}", userId);

        List<ActiveSessionDto> sessions = sessionManagementService.getActiveSessions(UUID.fromString(userId));
        return ResponseEntity.ok(sessions);
    }

    @GetMapping("/{sessionId}")
    @Operation(summary = "Get specific session details",
               description = "Returns detailed information about a specific session")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Session found"),
        @ApiResponse(responseCode = "404", description = "Session not found")
    })
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<ActiveSessionDto> getSession(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID sessionId) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        log.debug("Getting session {} for user: {}", sessionId, userId);

        ActiveSessionDto session = sessionManagementService.getSession(sessionId);

        // Verify the session belongs to the requesting user
        if (!session.getUserId().toString().equals(userId)) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(session);
    }

    @GetMapping("/count")
    @Operation(summary = "Get active session count",
               description = "Returns the number of active sessions for the current user")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Integer>> getSessionCount(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        int count = sessionManagementService.countActiveSessions(UUID.fromString(userId));
        return ResponseEntity.ok(Map.of("activeSessions", count));
    }

    // ==================== Session Activities ====================

    @GetMapping("/{sessionId}/activities")
    @Operation(summary = "Get session activity history",
               description = "Returns the activity log for a specific session")
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<List<SessionActivityDto>> getSessionActivities(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID sessionId) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        // Verify session belongs to user
        ActiveSessionDto session = sessionManagementService.getSession(sessionId);
        if (!session.getUserId().toString().equals(userId)) {
            return ResponseEntity.notFound().build();
        }

        List<SessionActivityDto> activities = sessionManagementService.getSessionActivities(sessionId);
        return ResponseEntity.ok(activities);
    }

    @GetMapping("/activities")
    @Operation(summary = "Get all session activities for current user",
               description = "Returns paginated activity log across all sessions")
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<Page<SessionActivityDto>> getUserActivities(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        Pageable pageable = PageRequest.of(page, Math.min(size, 100));
        Page<SessionActivityDto> activities = sessionManagementService.getUserActivities(
                UUID.fromString(userId), pageable);

        return ResponseEntity.ok(activities);
    }

    // ==================== Session Management ====================

    @PutMapping("/{sessionId}/trust")
    @Operation(summary = "Mark session as trusted",
               description = "Marks a session as trusted device, which may affect security checks")
    @RateLimit(requests = 10, window = 3600, key = KeyType.USER)
    public ResponseEntity<Void> trustSession(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID sessionId) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        // Verify session belongs to user
        ActiveSessionDto session = sessionManagementService.getSession(sessionId);
        if (!session.getUserId().toString().equals(userId)) {
            return ResponseEntity.notFound().build();
        }

        log.info("Marking session {} as trusted for user: {}", sessionId, userId);
        sessionManagementService.markSessionAsTrusted(sessionId);

        return ResponseEntity.ok().build();
    }

    // ==================== Session Termination ====================

    @DeleteMapping("/{sessionId}")
    @Operation(summary = "Terminate a specific session",
               description = "Terminates (logs out) a specific session. Cannot terminate current session using this endpoint.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Session terminated"),
        @ApiResponse(responseCode = "400", description = "Cannot terminate current session"),
        @ApiResponse(responseCode = "404", description = "Session not found")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Void> terminateSession(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID sessionId) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);
        String currentSessionId = jwtOperations.extractSessionId(token);

        // Verify session belongs to user
        ActiveSessionDto session = sessionManagementService.getSession(sessionId);
        if (!session.getUserId().toString().equals(userId)) {
            return ResponseEntity.notFound().build();
        }

        // Prevent terminating current session (use logout instead)
        if (currentSessionId != null && sessionId.toString().equals(currentSessionId)) {
            return ResponseEntity.badRequest().build();
        }

        log.info("User {} terminating session: {}", userId, sessionId);
        sessionManagementService.terminateSession(sessionId, "User requested termination");

        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    @Operation(summary = "Terminate all other sessions",
               description = "Terminates all sessions except the current one (logout everywhere else)")
    @RateLimit(requests = 5, window = 300, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> terminateAllOtherSessions(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);
        String currentSessionId = jwtOperations.extractSessionId(token);

        log.info("User {} terminating all other sessions", userId);

        if (currentSessionId != null) {
            sessionManagementService.terminateOtherSessions(
                    UUID.fromString(userId),
                    UUID.fromString(currentSessionId),
                    "User requested termination of all other sessions"
            );
        } else {
            sessionManagementService.terminateAllUserSessions(
                    UUID.fromString(userId),
                    "User requested termination of all sessions"
            );
        }

        return ResponseEntity.ok(Map.of("message", "All other sessions terminated"));
    }

    @DeleteMapping("/all")
    @Operation(summary = "Terminate all sessions including current",
               description = "Terminates ALL sessions for the user, including the current one. User will be logged out.")
    @RateLimit(requests = 3, window = 3600, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> terminateAllSessions(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);

        log.info("User {} terminating ALL sessions", userId);
        sessionManagementService.terminateAllUserSessions(
                UUID.fromString(userId),
                "User requested termination of all sessions"
        );

        return ResponseEntity.ok(Map.of("message", "All sessions terminated. You have been logged out."));
    }

    // ==================== Helpers ====================

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }
}
