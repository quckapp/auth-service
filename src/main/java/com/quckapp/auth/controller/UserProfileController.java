package com.quckapp.auth.controller;

import com.quckapp.auth.dto.UserProfileDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.LinkedDeviceService;
import com.quckapp.auth.service.UserProfileService;
import com.quckapp.auth.service.UserSettingsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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
 * REST Controller for user profile management
 */
@RestController
@RequestMapping("/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Profiles", description = "User profile management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class UserProfileController {

    private final UserProfileService profileService;
    private final UserSettingsService settingsService;
    private final LinkedDeviceService deviceService;
    private final JwtOperations jwtOperations;

    // ==================== Profile Endpoints ====================

    @GetMapping("/me")
    @Operation(summary = "Get current user's profile")
    public ResponseEntity<UserProfileDto> getMyProfile(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);
        log.debug("Getting profile for user: {}", userId);
        return ResponseEntity.ok(profileService.getProfile(userId));
    }

    @PutMapping("/me")
    @Operation(summary = "Update current user's profile")
    public ResponseEntity<UserProfileDto> updateMyProfile(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody UpdateProfileRequest request) {
        UUID userId = getUserId(authHeader);
        log.debug("Updating profile for user: {}", userId);
        return ResponseEntity.ok(profileService.updateProfile(userId, request));
    }

    @PatchMapping("/profile")
    @Operation(summary = "Partially update current user's profile (mobile-friendly)")
    public ResponseEntity<ProfileUpdateResponse> patchProfile(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @RequestBody PatchProfileRequest request) {
        UUID userId = getUserId(authHeader);
        log.debug("Patching profile for user: {}", userId);

        // Build display name from firstName/lastName if provided
        String displayName = request.getDisplayName();
        if (displayName == null || displayName.isEmpty()) {
            StringBuilder nameBuilder = new StringBuilder();
            if (request.getFirstName() != null && !request.getFirstName().isEmpty()) {
                nameBuilder.append(request.getFirstName());
            }
            if (request.getLastName() != null && !request.getLastName().isEmpty()) {
                if (nameBuilder.length() > 0) nameBuilder.append(" ");
                nameBuilder.append(request.getLastName());
            }
            if (nameBuilder.length() > 0) {
                displayName = nameBuilder.toString();
            }
        }

        UpdateProfileRequest updateRequest = UpdateProfileRequest.builder()
                .displayName(displayName)
                .username(request.getUsername())
                .email(request.getEmail())
                .build();

        UserProfileDto updatedProfile = profileService.updateProfile(userId, updateRequest);

        return ResponseEntity.ok(ProfileUpdateResponse.builder()
                .success(true)
                .message("Profile updated successfully")
                .user(updatedProfile)
                .build());
    }

    @PostMapping("/email/connect")
    @Operation(summary = "Connect email to user account")
    public ResponseEntity<EmailConnectResponse> connectEmail(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody EmailConnectRequest request) {
        UUID userId = getUserId(authHeader);
        log.debug("Connecting email for user: {}", userId);

        // Update profile with email
        UpdateProfileRequest updateRequest = UpdateProfileRequest.builder()
                .email(request.getEmail())
                .build();

        profileService.updateProfile(userId, updateRequest);

        // TODO: Send verification email via notification service

        return ResponseEntity.ok(EmailConnectResponse.builder()
                .success(true)
                .message("Verification email sent")
                .build());
    }

    @GetMapping("/{userId}")
    @Operation(summary = "Get profile by user ID")
    public ResponseEntity<UserProfileDto> getProfile(
            @PathVariable UUID userId) {
        return ResponseEntity.ok(profileService.getProfile(userId));
    }

    @GetMapping("/by-external-id/{externalId}")
    @Operation(summary = "Get profile by external ID (MongoDB ID)")
    public ResponseEntity<UserProfileDto> getProfileByExternalId(
            @PathVariable String externalId) {
        return ResponseEntity.ok(profileService.getProfileByExternalId(externalId));
    }

    @GetMapping("/by-phone/{phoneNumber}")
    @Operation(summary = "Get profile by phone number")
    public ResponseEntity<UserProfileDto> getProfileByPhone(
            @PathVariable String phoneNumber) {
        return profileService.findByPhoneNumber(phoneNumber)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/by-username/{username}")
    @Operation(summary = "Get profile by username")
    public ResponseEntity<UserProfileDto> getProfileByUsername(
            @PathVariable String username) {
        return profileService.findByUsername(username)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/batch")
    @Operation(summary = "Get multiple profiles by IDs")
    public ResponseEntity<List<UserProfileDto>> getProfilesByIds(
            @RequestParam List<UUID> ids) {
        return ResponseEntity.ok(profileService.getUsersByIds(ids));
    }

    @GetMapping("/batch/external")
    @Operation(summary = "Get multiple profiles by external IDs")
    public ResponseEntity<List<UserProfileDto>> getProfilesByExternalIds(
            @RequestParam List<String> externalIds) {
        return ResponseEntity.ok(profileService.getUsersByExternalIds(externalIds));
    }

    @GetMapping("/search")
    @Operation(summary = "Search users")
    public ResponseEntity<Page<UserProfileSummaryDto>> searchUsers(
            @RequestParam String query,
            @RequestParam(required = false) UUID excludeUserId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, Math.min(size, 100));
        return ResponseEntity.ok(profileService.searchUsers(query, excludeUserId, pageable));
    }

    // ==================== Status Endpoints ====================

    @PutMapping("/me/status")
    @Operation(summary = "Update user status (online/offline/away)")
    public ResponseEntity<Void> updateStatus(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody UpdateStatusRequest request) {
        UUID userId = getUserId(authHeader);
        profileService.updateStatus(userId, request.getStatus());
        return ResponseEntity.ok().build();
    }

    // ==================== Settings Endpoints ====================

    @GetMapping("/me/settings")
    @Operation(summary = "Get user settings")
    public ResponseEntity<UserSettingsDto> getSettings(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);
        return ResponseEntity.ok(settingsService.getSettings(userId));
    }

    @PutMapping("/me/settings")
    @Operation(summary = "Update user settings")
    public ResponseEntity<UserSettingsDto> updateSettings(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody UpdateSettingsRequest request) {
        UUID userId = getUserId(authHeader);
        return ResponseEntity.ok(settingsService.updateSettings(userId, request));
    }

    // ==================== Blocked Users Endpoints ====================

    @PostMapping("/me/blocked-users")
    @Operation(summary = "Block a user", tags = {"Blocked Users"})
    public ResponseEntity<Void> blockUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BlockUserRequest request) {
        UUID userId = getUserId(authHeader);
        settingsService.blockUser(userId, request.getUserId());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/me/blocked-users/{blockedUserId}")
    @Operation(summary = "Unblock a user", tags = {"Blocked Users"})
    public ResponseEntity<Void> unblockUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID blockedUserId) {
        UUID userId = getUserId(authHeader);
        settingsService.unblockUser(userId, blockedUserId);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me/blocked-users")
    @Operation(summary = "Get list of blocked users", tags = {"Blocked Users"})
    public ResponseEntity<List<UserProfileSummaryDto>> getBlockedUsers(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);
        return ResponseEntity.ok(settingsService.getBlockedUsers(userId));
    }

    // ==================== Linked Devices Endpoints ====================

    @PostMapping("/me/devices")
    @Operation(summary = "Link a device", tags = {"Devices"})
    public ResponseEntity<LinkedDeviceDto> linkDevice(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody LinkDeviceRequest request) {
        UUID userId = getUserId(authHeader);
        return ResponseEntity.ok(deviceService.linkDevice(userId, request));
    }

    @GetMapping("/me/devices")
    @Operation(summary = "Get linked devices", tags = {"Devices"})
    public ResponseEntity<List<LinkedDeviceDto>> getLinkedDevices(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);
        return ResponseEntity.ok(deviceService.getLinkedDevices(userId));
    }

    @DeleteMapping("/me/devices/{deviceId}")
    @Operation(summary = "Unlink a device", tags = {"Devices"})
    public ResponseEntity<Void> unlinkDevice(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId) {
        UUID userId = getUserId(authHeader);
        deviceService.unlinkDevice(userId, deviceId);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/me/devices/{deviceId}/activity")
    @Operation(summary = "Update device activity timestamp", tags = {"Devices"})
    public ResponseEntity<Void> updateDeviceActivity(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId) {
        UUID userId = getUserId(authHeader);
        deviceService.updateDeviceActivity(userId, deviceId);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/me/devices/{deviceId}/fcm-token")
    @Operation(summary = "Update device FCM token", tags = {"Devices"})
    public ResponseEntity<Void> updateFcmToken(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId,
            @RequestBody UpdateFcmTokenRequest request) {
        UUID userId = getUserId(authHeader);
        deviceService.updateFcmToken(userId, deviceId, request.getFcmToken());
        return ResponseEntity.ok().build();
    }

    // ==================== Internal Endpoints (Service-to-Service) ====================

    @GetMapping("/internal/fcm-tokens/{userId}")
    @Operation(summary = "Get FCM tokens for a user (internal use)", tags = {"Internal"})
    public ResponseEntity<FcmTokensResponse> getFcmTokens(
            @PathVariable UUID userId,
            @RequestHeader("X-API-Key") String apiKey) {
        // API key validation should be done by security filter
        List<String> tokens = deviceService.getFcmTokens(userId);
        return ResponseEntity.ok(FcmTokensResponse.builder()
                .userId(userId)
                .fcmTokens(tokens)
                .build());
    }

    @PostMapping("/internal/fcm-tokens/batch")
    @Operation(summary = "Get FCM tokens for multiple users (internal use)", tags = {"Internal"})
    public ResponseEntity<Map<UUID, List<String>>> getFcmTokensBatch(
            @RequestBody BatchFcmTokensRequest request,
            @RequestHeader("X-API-Key") String apiKey) {
        // API key validation should be done by security filter
        return ResponseEntity.ok(deviceService.getFcmTokensGroupedByUsers(request.getUserIds()));
    }

    @GetMapping("/internal/check-blocked")
    @Operation(summary = "Check if users are blocked (internal use)", tags = {"Internal"})
    public ResponseEntity<Boolean> checkBlocked(
            @RequestParam UUID userId1,
            @RequestParam UUID userId2,
            @RequestHeader("X-API-Key") String apiKey) {
        return ResponseEntity.ok(settingsService.areUsersBlocked(userId1, userId2));
    }

    // ==================== Admin Endpoints ====================

    @PostMapping("/admin/ban")
    @Operation(summary = "Ban a user (admin only)", tags = {"Admin"})
    public ResponseEntity<Void> banUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BanUserRequest request) {
        UUID adminUserId = getUserId(authHeader);
        // Admin check should be done by security filter
        profileService.banUser(request.getUserId(), adminUserId, request.getReason());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/unban/{userId}")
    @Operation(summary = "Unban a user (admin only)", tags = {"Admin"})
    public ResponseEntity<Void> unbanUser(
            @PathVariable UUID userId) {
        profileService.unbanUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/role")
    @Operation(summary = "Update user role (admin only)", tags = {"Admin"})
    public ResponseEntity<Void> updateRole(
            @Valid @RequestBody UpdateRoleRequest request) {
        profileService.updateRole(request.getUserId(), request.getRole());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/permissions")
    @Operation(summary = "Update user permissions (admin only)", tags = {"Admin"})
    public ResponseEntity<Void> updatePermissions(
            @Valid @RequestBody UpdatePermissionsRequest request) {
        profileService.updatePermissions(request.getUserId(), request.getPermissions());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/admin/statistics")
    @Operation(summary = "Get user statistics (admin only)", tags = {"Admin"})
    public ResponseEntity<UserStatisticsDto> getStatistics() {
        return ResponseEntity.ok(profileService.getStatistics());
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
}
