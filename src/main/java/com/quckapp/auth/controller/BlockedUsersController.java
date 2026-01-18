package com.quckapp.auth.controller;

import com.quckapp.auth.dto.UserProfileDtos.UserProfileSummaryDto;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.service.UserSettingsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * REST Controller for Blocked Users management
 * Provides endpoints for blocking, unblocking, and querying blocked users
 */
@RestController
@RequestMapping("/v1/blocked-users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Blocked Users", description = "Block and unblock users, manage blocked user list")
@SecurityRequirement(name = "bearerAuth")
public class BlockedUsersController {

    private final UserSettingsService userSettingsService;
    private final JwtOperations jwtOperations;

    // ==================== Block/Unblock Operations ====================

    @PostMapping
    @Operation(summary = "Block a user",
               description = "Block a user. Blocked users cannot send messages or interact with you.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User blocked successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request or cannot block yourself"),
        @ApiResponse(responseCode = "404", description = "User to block not found")
    })
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> blockUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BlockUserRequest request) {
        UUID userId = getUserId(authHeader);
        log.info("User {} blocking user {}", userId, request.getUserId());

        userSettingsService.blockUser(userId, request.getUserId());

        return ResponseEntity.ok(Map.of(
                "message", "User blocked successfully",
                "blockedUserId", request.getUserId().toString()
        ));
    }

    @DeleteMapping("/{blockedUserId}")
    @Operation(summary = "Unblock a user",
               description = "Remove a user from your blocked list")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User unblocked successfully"),
        @ApiResponse(responseCode = "404", description = "User not in blocked list")
    })
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> unblockUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID blockedUserId) {
        UUID userId = getUserId(authHeader);
        log.info("User {} unblocking user {}", userId, blockedUserId);

        userSettingsService.unblockUser(userId, blockedUserId);

        return ResponseEntity.ok(Map.of(
                "message", "User unblocked successfully",
                "unblockedUserId", blockedUserId.toString()
        ));
    }

    // ==================== List Blocked Users ====================

    @GetMapping
    @Operation(summary = "Get blocked users list",
               description = "Get a list of all users you have blocked with their profile information")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<BlockedUsersResponse> getBlockedUsers(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);

        List<UserProfileSummaryDto> blockedUsers = userSettingsService.getBlockedUsers(userId);

        return ResponseEntity.ok(BlockedUsersResponse.builder()
                .userId(userId)
                .blockedCount(blockedUsers.size())
                .blockedUsers(blockedUsers)
                .build());
    }

    @GetMapping("/ids")
    @Operation(summary = "Get blocked user IDs",
               description = "Get a list of user IDs you have blocked (lightweight endpoint)")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<BlockedUserIdsResponse> getBlockedUserIds(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);

        Set<UUID> blockedIds = userSettingsService.getBlockedUserIds(userId);

        return ResponseEntity.ok(BlockedUserIdsResponse.builder()
                .userId(userId)
                .blockedCount(blockedIds != null ? blockedIds.size() : 0)
                .blockedUserIds(blockedIds != null ? blockedIds : Set.of())
                .build());
    }

    @GetMapping("/count")
    @Operation(summary = "Get blocked users count",
               description = "Get the count of users you have blocked")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> getBlockedUsersCount(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);

        Set<UUID> blockedIds = userSettingsService.getBlockedUserIds(userId);
        int count = blockedIds != null ? blockedIds.size() : 0;

        return ResponseEntity.ok(Map.of(
                "userId", userId.toString(),
                "blockedCount", count
        ));
    }

    // ==================== Check Block Status ====================

    @GetMapping("/check/{targetUserId}")
    @Operation(summary = "Check if user is blocked",
               description = "Check if a specific user is in your blocked list")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<BlockStatusResponse> checkBlocked(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID targetUserId) {
        UUID userId = getUserId(authHeader);

        boolean isBlocked = userSettingsService.isBlocked(userId, targetUserId);

        return ResponseEntity.ok(BlockStatusResponse.builder()
                .userId(userId)
                .targetUserId(targetUserId)
                .isBlocked(isBlocked)
                .build());
    }

    @GetMapping("/check-mutual/{targetUserId}")
    @Operation(summary = "Check mutual block status",
               description = "Check if either you or the target user has blocked the other")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<MutualBlockStatusResponse> checkMutualBlocked(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID targetUserId) {
        UUID userId = getUserId(authHeader);

        boolean iBlockedThem = userSettingsService.isBlocked(userId, targetUserId);
        boolean theyBlockedMe = userSettingsService.isBlocked(targetUserId, userId);
        boolean anyBlocked = iBlockedThem || theyBlockedMe;

        return ResponseEntity.ok(MutualBlockStatusResponse.builder()
                .userId(userId)
                .targetUserId(targetUserId)
                .youBlockedThem(iBlockedThem)
                .theyBlockedYou(theyBlockedMe)
                .anyBlocked(anyBlocked)
                .build());
    }

    @PostMapping("/check-batch")
    @Operation(summary = "Check block status for multiple users",
               description = "Check block status for a batch of user IDs")
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<BatchBlockStatusResponse> checkBatchBlocked(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BatchBlockCheckRequest request) {
        UUID userId = getUserId(authHeader);

        Set<UUID> blockedIds = userSettingsService.getBlockedUserIds(userId);
        Set<UUID> requestedIds = request.getUserIds();

        // Filter to only include IDs that are actually blocked
        Set<UUID> blockedFromRequest = requestedIds.stream()
                .filter(id -> blockedIds != null && blockedIds.contains(id))
                .collect(java.util.stream.Collectors.toSet());

        return ResponseEntity.ok(BatchBlockStatusResponse.builder()
                .userId(userId)
                .checkedCount(requestedIds.size())
                .blockedUserIds(blockedFromRequest)
                .blockedCount(blockedFromRequest.size())
                .build());
    }

    // ==================== Bulk Operations ====================

    @PostMapping("/block-multiple")
    @Operation(summary = "Block multiple users",
               description = "Block multiple users at once")
    @RateLimit(requests = 5, window = 60, key = KeyType.USER)
    public ResponseEntity<BulkBlockResponse> blockMultipleUsers(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BulkBlockRequest request) {
        UUID userId = getUserId(authHeader);
        log.info("User {} blocking {} users", userId, request.getUserIds().size());

        int successCount = 0;
        int failedCount = 0;

        for (UUID userToBlock : request.getUserIds()) {
            try {
                userSettingsService.blockUser(userId, userToBlock);
                successCount++;
            } catch (Exception e) {
                log.warn("Failed to block user {}: {}", userToBlock, e.getMessage());
                failedCount++;
            }
        }

        return ResponseEntity.ok(BulkBlockResponse.builder()
                .message("Bulk block operation completed")
                .successCount(successCount)
                .failedCount(failedCount)
                .build());
    }

    @PostMapping("/unblock-multiple")
    @Operation(summary = "Unblock multiple users",
               description = "Unblock multiple users at once")
    @RateLimit(requests = 5, window = 60, key = KeyType.USER)
    public ResponseEntity<BulkBlockResponse> unblockMultipleUsers(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BulkBlockRequest request) {
        UUID userId = getUserId(authHeader);
        log.info("User {} unblocking {} users", userId, request.getUserIds().size());

        int successCount = 0;
        int failedCount = 0;

        for (UUID userToUnblock : request.getUserIds()) {
            try {
                userSettingsService.unblockUser(userId, userToUnblock);
                successCount++;
            } catch (Exception e) {
                log.warn("Failed to unblock user {}: {}", userToUnblock, e.getMessage());
                failedCount++;
            }
        }

        return ResponseEntity.ok(BulkBlockResponse.builder()
                .message("Bulk unblock operation completed")
                .successCount(successCount)
                .failedCount(failedCount)
                .build());
    }

    @DeleteMapping
    @Operation(summary = "Unblock all users",
               description = "Remove all users from your blocked list")
    @RateLimit(requests = 3, window = 3600, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> unblockAllUsers(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);
        log.info("User {} unblocking all users", userId);

        Set<UUID> blockedIds = userSettingsService.getBlockedUserIds(userId);
        int count = blockedIds != null ? blockedIds.size() : 0;

        if (blockedIds != null) {
            for (UUID blockedId : blockedIds) {
                try {
                    userSettingsService.unblockUser(userId, blockedId);
                } catch (Exception e) {
                    log.warn("Failed to unblock user {}: {}", blockedId, e.getMessage());
                }
            }
        }

        return ResponseEntity.ok(Map.of(
                "message", "All users unblocked",
                "unblockedCount", count
        ));
    }

    // ==================== Helper Methods ====================

    private UUID getUserId(String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);
        return UUID.fromString(userId);
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }

    // ==================== Request/Response DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BlockUserRequest {
        @NotNull
        private UUID userId;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BlockedUsersResponse {
        private UUID userId;
        private int blockedCount;
        private List<UserProfileSummaryDto> blockedUsers;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BlockedUserIdsResponse {
        private UUID userId;
        private int blockedCount;
        private Set<UUID> blockedUserIds;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BlockStatusResponse {
        private UUID userId;
        private UUID targetUserId;
        private boolean isBlocked;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class MutualBlockStatusResponse {
        private UUID userId;
        private UUID targetUserId;
        private boolean youBlockedThem;
        private boolean theyBlockedYou;
        private boolean anyBlocked;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BatchBlockCheckRequest {
        @NotNull
        private Set<UUID> userIds;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BatchBlockStatusResponse {
        private UUID userId;
        private int checkedCount;
        private Set<UUID> blockedUserIds;
        private int blockedCount;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BulkBlockRequest {
        @NotNull
        private Set<UUID> userIds;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BulkBlockResponse {
        private String message;
        private int successCount;
        private int failedCount;
    }
}
