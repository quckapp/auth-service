package com.quckchat.auth.controller;

import com.quckchat.auth.dto.UserProfileDtos.*;
import com.quckchat.auth.service.LinkedDeviceService;
import com.quckchat.auth.service.UserProfileService;
import com.quckchat.auth.service.UserSettingsService;
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

    // ==================== Profile Endpoints ====================

    @GetMapping("/me")
    @Operation(summary = "Get current user's profile")
    public ResponseEntity<UserProfileDto> getMyProfile(
            @RequestHeader("X-User-ID") UUID userId) {
        log.debug("Getting profile for user: {}", userId);
        return ResponseEntity.ok(profileService.getProfile(userId));
    }

    @PutMapping("/me")
    @Operation(summary = "Update current user's profile")
    public ResponseEntity<UserProfileDto> updateMyProfile(
            @RequestHeader("X-User-ID") UUID userId,
            @Valid @RequestBody UpdateProfileRequest request) {
        log.debug("Updating profile for user: {}", userId);
        return ResponseEntity.ok(profileService.updateProfile(userId, request));
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
            @RequestHeader("X-User-ID") UUID userId,
            @Valid @RequestBody UpdateStatusRequest request) {
        profileService.updateStatus(userId, request.getStatus());
        return ResponseEntity.ok().build();
    }

    // ==================== Settings Endpoints ====================

    @GetMapping("/me/settings")
    @Operation(summary = "Get user settings")
    public ResponseEntity<UserSettingsDto> getSettings(
            @RequestHeader("X-User-ID") UUID userId) {
        return ResponseEntity.ok(settingsService.getSettings(userId));
    }

    @PutMapping("/me/settings")
    @Operation(summary = "Update user settings")
    public ResponseEntity<UserSettingsDto> updateSettings(
            @RequestHeader("X-User-ID") UUID userId,
            @Valid @RequestBody UpdateSettingsRequest request) {
        return ResponseEntity.ok(settingsService.updateSettings(userId, request));
    }

    // ==================== Blocked Users Endpoints ====================

    @PostMapping("/me/blocked-users")
    @Operation(summary = "Block a user")
    public ResponseEntity<Void> blockUser(
            @RequestHeader("X-User-ID") UUID userId,
            @Valid @RequestBody BlockUserRequest request) {
        settingsService.blockUser(userId, request.getUserId());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/me/blocked-users/{blockedUserId}")
    @Operation(summary = "Unblock a user")
    public ResponseEntity<Void> unblockUser(
            @RequestHeader("X-User-ID") UUID userId,
            @PathVariable UUID blockedUserId) {
        settingsService.unblockUser(userId, blockedUserId);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me/blocked-users")
    @Operation(summary = "Get list of blocked users")
    public ResponseEntity<List<UserProfileSummaryDto>> getBlockedUsers(
            @RequestHeader("X-User-ID") UUID userId) {
        return ResponseEntity.ok(settingsService.getBlockedUsers(userId));
    }

    // ==================== Linked Devices Endpoints ====================

    @PostMapping("/me/devices")
    @Operation(summary = "Link a device")
    public ResponseEntity<LinkedDeviceDto> linkDevice(
            @RequestHeader("X-User-ID") UUID userId,
            @Valid @RequestBody LinkDeviceRequest request) {
        return ResponseEntity.ok(deviceService.linkDevice(userId, request));
    }

    @GetMapping("/me/devices")
    @Operation(summary = "Get linked devices")
    public ResponseEntity<List<LinkedDeviceDto>> getLinkedDevices(
            @RequestHeader("X-User-ID") UUID userId) {
        return ResponseEntity.ok(deviceService.getLinkedDevices(userId));
    }

    @DeleteMapping("/me/devices/{deviceId}")
    @Operation(summary = "Unlink a device")
    public ResponseEntity<Void> unlinkDevice(
            @RequestHeader("X-User-ID") UUID userId,
            @PathVariable String deviceId) {
        deviceService.unlinkDevice(userId, deviceId);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/me/devices/{deviceId}/activity")
    @Operation(summary = "Update device activity timestamp")
    public ResponseEntity<Void> updateDeviceActivity(
            @RequestHeader("X-User-ID") UUID userId,
            @PathVariable String deviceId) {
        deviceService.updateDeviceActivity(userId, deviceId);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/me/devices/{deviceId}/fcm-token")
    @Operation(summary = "Update device FCM token")
    public ResponseEntity<Void> updateFcmToken(
            @RequestHeader("X-User-ID") UUID userId,
            @PathVariable String deviceId,
            @RequestBody UpdateFcmTokenRequest request) {
        deviceService.updateFcmToken(userId, deviceId, request.getFcmToken());
        return ResponseEntity.ok().build();
    }

    // ==================== Internal Endpoints (Service-to-Service) ====================

    @GetMapping("/internal/fcm-tokens/{userId}")
    @Operation(summary = "Get FCM tokens for a user (internal use)")
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
    @Operation(summary = "Get FCM tokens for multiple users (internal use)")
    public ResponseEntity<Map<UUID, List<String>>> getFcmTokensBatch(
            @RequestBody BatchFcmTokensRequest request,
            @RequestHeader("X-API-Key") String apiKey) {
        // API key validation should be done by security filter
        return ResponseEntity.ok(deviceService.getFcmTokensGroupedByUsers(request.getUserIds()));
    }

    @GetMapping("/internal/check-blocked")
    @Operation(summary = "Check if users are blocked (internal use)")
    public ResponseEntity<Boolean> checkBlocked(
            @RequestParam UUID userId1,
            @RequestParam UUID userId2,
            @RequestHeader("X-API-Key") String apiKey) {
        return ResponseEntity.ok(settingsService.areUsersBlocked(userId1, userId2));
    }

    // ==================== Admin Endpoints ====================

    @PostMapping("/admin/ban")
    @Operation(summary = "Ban a user (admin only)")
    public ResponseEntity<Void> banUser(
            @RequestHeader("X-User-ID") UUID adminUserId,
            @Valid @RequestBody BanUserRequest request) {
        // Admin check should be done by security filter
        profileService.banUser(request.getUserId(), adminUserId, request.getReason());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/unban/{userId}")
    @Operation(summary = "Unban a user (admin only)")
    public ResponseEntity<Void> unbanUser(
            @PathVariable UUID userId) {
        profileService.unbanUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/role")
    @Operation(summary = "Update user role (admin only)")
    public ResponseEntity<Void> updateRole(
            @Valid @RequestBody UpdateRoleRequest request) {
        profileService.updateRole(request.getUserId(), request.getRole());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/admin/permissions")
    @Operation(summary = "Update user permissions (admin only)")
    public ResponseEntity<Void> updatePermissions(
            @Valid @RequestBody UpdatePermissionsRequest request) {
        profileService.updatePermissions(request.getUserId(), request.getPermissions());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/admin/statistics")
    @Operation(summary = "Get user statistics (admin only)")
    public ResponseEntity<UserStatisticsDto> getStatistics() {
        return ResponseEntity.ok(profileService.getStatistics());
    }
}
