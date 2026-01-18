package com.quckapp.auth.controller;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.DeviceType;
import com.quckapp.auth.domain.entity.TrustedDevice;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.TrustedDeviceRepository;
import com.quckapp.auth.dto.UserProfileDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.service.LinkedDeviceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST Controller for Device management
 * Handles linked devices (FCM tokens) and trusted devices (2FA bypass)
 */
@RestController
@RequestMapping("/v1/devices")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Devices", description = "Device linking, FCM tokens, and push notification management")
@SecurityRequirement(name = "bearerAuth")
public class DevicesController {

    private final LinkedDeviceService linkedDeviceService;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final AuthUserRepository authUserRepository;
    private final JwtOperations jwtOperations;

    // ==================== Linked Devices ====================

    @PostMapping("/link")
    @Operation(summary = "Link a device",
               description = "Register a new device or update existing device info. Used for push notifications via FCM.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Device linked successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request")
    })
    @RateLimit(requests = 20, window = 60, key = KeyType.USER)
    public ResponseEntity<LinkedDeviceDto> linkDevice(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody LinkDeviceRequest request) {
        UUID userId = getUserId(authHeader);
        log.info("Linking device {} for user {}", request.getDeviceId(), userId);

        LinkedDeviceDto device = linkedDeviceService.linkDevice(userId, request);
        return ResponseEntity.ok(device);
    }

    @GetMapping
    @Operation(summary = "Get linked devices",
               description = "Get all devices linked to the current user's account")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<DevicesListResponse> getLinkedDevices(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);

        List<LinkedDeviceDto> devices = linkedDeviceService.getLinkedDevices(userId);

        return ResponseEntity.ok(DevicesListResponse.builder()
                .userId(userId.toString())
                .deviceCount(devices.size())
                .devices(devices)
                .build());
    }

    @GetMapping("/{deviceId}")
    @Operation(summary = "Get device details",
               description = "Get details of a specific linked device")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<LinkedDeviceDto> getDevice(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId) {
        UUID userId = getUserId(authHeader);

        List<LinkedDeviceDto> devices = linkedDeviceService.getLinkedDevices(userId);
        return devices.stream()
                .filter(d -> d.getDeviceId().equals(deviceId))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{deviceId}")
    @Operation(summary = "Unlink a device",
               description = "Remove a device from the account. This will stop push notifications to this device.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Device unlinked"),
        @ApiResponse(responseCode = "404", description = "Device not found")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> unlinkDevice(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId) {
        UUID userId = getUserId(authHeader);
        log.info("Unlinking device {} for user {}", deviceId, userId);

        linkedDeviceService.unlinkDevice(userId, deviceId);

        return ResponseEntity.ok(Map.of(
                "message", "Device unlinked successfully",
                "deviceId", deviceId
        ));
    }

    @PutMapping("/{deviceId}/activity")
    @Operation(summary = "Update device activity",
               description = "Update the last activity timestamp for a device")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<Void> updateDeviceActivity(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId) {
        UUID userId = getUserId(authHeader);

        linkedDeviceService.updateDeviceActivity(userId, deviceId);
        return ResponseEntity.ok().build();
    }

    // ==================== FCM Token Management ====================

    @PutMapping("/{deviceId}/fcm-token")
    @Operation(summary = "Update FCM token",
               description = "Update the Firebase Cloud Messaging token for push notifications")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> updateFcmToken(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId,
            @RequestBody UpdateFcmTokenRequest request) {
        UUID userId = getUserId(authHeader);
        log.info("Updating FCM token for user {} device {}", userId, deviceId);

        linkedDeviceService.updateFcmToken(userId, deviceId, request.getFcmToken());

        return ResponseEntity.ok(Map.of(
                "message", "FCM token updated",
                "deviceId", deviceId
        ));
    }

    @DeleteMapping("/{deviceId}/fcm-token")
    @Operation(summary = "Remove FCM token",
               description = "Remove the FCM token from a device (disable push notifications)")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> removeFcmToken(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable String deviceId) {
        UUID userId = getUserId(authHeader);
        log.info("Removing FCM token for user {} device {}", userId, deviceId);

        linkedDeviceService.updateFcmToken(userId, deviceId, null);

        return ResponseEntity.ok(Map.of(
                "message", "FCM token removed",
                "deviceId", deviceId
        ));
    }

    // ==================== Trusted Devices ====================

    @GetMapping("/trusted")
    @Operation(summary = "Get trusted devices",
               description = "Get all devices marked as trusted (can bypass 2FA)")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<TrustedDevicesResponse> getTrustedDevices(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);

        List<TrustedDevice> devices = trustedDeviceRepository.findActiveTrustedDevicesByUserId(userId);
        List<TrustedDeviceDto> deviceDtos = devices.stream()
                .map(this::mapToTrustedDeviceDto)
                .collect(Collectors.toList());

        return ResponseEntity.ok(TrustedDevicesResponse.builder()
                .userId(userId.toString())
                .trustedDeviceCount(deviceDtos.size())
                .devices(deviceDtos)
                .build());
    }

    @PostMapping("/trusted")
    @Operation(summary = "Trust current device",
               description = "Mark the current device as trusted. Trusted devices may bypass 2FA for a period.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Device trusted"),
        @ApiResponse(responseCode = "400", description = "Invalid request")
    })
    @RateLimit(requests = 5, window = 3600, key = KeyType.USER)
    public ResponseEntity<TrustedDeviceDto> trustDevice(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TrustDeviceRequest request) {
        UUID userId = getUserId(authHeader);
        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        log.info("Trusting device for user {}: {}", userId, request.getDeviceFingerprint());

        // Check if already trusted
        var existing = trustedDeviceRepository.findByUserIdAndDeviceFingerprint(
                userId, request.getDeviceFingerprint());

        TrustedDevice device;
        if (existing.isPresent()) {
            device = existing.get();
            device.setTrusted(true);
            device.setTrustedAt(Instant.now());
            device.setExpiresAt(calculateTrustExpiry(request.getTrustDurationDays()));
            device.updateLastUsed();
        } else {
            device = TrustedDevice.builder()
                    .user(user)
                    .deviceFingerprint(request.getDeviceFingerprint())
                    .deviceName(request.getDeviceName())
                    .deviceType(request.getDeviceType())
                    .osName(request.getOsName())
                    .browserName(request.getBrowserName())
                    .isTrusted(true)
                    .trustedAt(Instant.now())
                    .lastUsedAt(Instant.now())
                    .expiresAt(calculateTrustExpiry(request.getTrustDurationDays()))
                    .build();
        }

        device = trustedDeviceRepository.save(device);
        log.info("Device trusted: {}", device.getId());

        return ResponseEntity.ok(mapToTrustedDeviceDto(device));
    }

    @DeleteMapping("/trusted/{deviceId}")
    @Operation(summary = "Revoke device trust",
               description = "Remove trusted status from a device")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> revokeTrust(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID deviceId) {
        UUID userId = getUserId(authHeader);
        log.info("Revoking trust for device {} user {}", deviceId, userId);

        TrustedDevice device = trustedDeviceRepository.findById(deviceId)
                .filter(d -> d.getUser().getId().equals(userId))
                .orElseThrow(() -> new RuntimeException("Device not found"));

        device.revokeTrust();
        trustedDeviceRepository.save(device);

        return ResponseEntity.ok(Map.of(
                "message", "Device trust revoked",
                "deviceId", deviceId.toString()
        ));
    }

    @DeleteMapping("/trusted")
    @Operation(summary = "Revoke all trusted devices",
               description = "Remove trusted status from all devices")
    @RateLimit(requests = 3, window = 3600, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> revokeAllTrustedDevices(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);
        log.info("Revoking all trusted devices for user {}", userId);

        int revoked = trustedDeviceRepository.revokeAllTrustedDevices(userId);

        return ResponseEntity.ok(Map.of(
                "message", "All trusted devices revoked",
                "revokedCount", revoked
        ));
    }

    @GetMapping("/trusted/check")
    @Operation(summary = "Check if device is trusted",
               description = "Check if a specific device fingerprint is trusted")
    @RateLimit(requests = 60, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> checkDeviceTrusted(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @RequestParam String fingerprint) {
        UUID userId = getUserId(authHeader);

        boolean isTrusted = trustedDeviceRepository.isDeviceTrusted(userId, fingerprint);

        return ResponseEntity.ok(Map.of(
                "fingerprint", fingerprint,
                "trusted", isTrusted
        ));
    }

    // ==================== Statistics ====================

    @GetMapping("/stats")
    @Operation(summary = "Get device statistics",
               description = "Get statistics about linked and trusted devices")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<DeviceStatsResponse> getDeviceStats(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        UUID userId = getUserId(authHeader);

        int linkedCount = linkedDeviceService.getDeviceCount(userId);
        int trustedCount = trustedDeviceRepository.countActiveTrustedDevices(userId);
        List<LinkedDeviceDto> linkedDevices = linkedDeviceService.getLinkedDevices(userId);

        Map<String, Long> byType = linkedDevices.stream()
                .collect(Collectors.groupingBy(
                        d -> d.getDeviceType() != null ? d.getDeviceType().name() : "UNKNOWN",
                        Collectors.counting()
                ));

        long withFcmToken = linkedDevices.stream().filter(LinkedDeviceDto::isHasFcmToken).count();

        return ResponseEntity.ok(DeviceStatsResponse.builder()
                .linkedDeviceCount(linkedCount)
                .trustedDeviceCount(trustedCount)
                .devicesWithFcmToken((int) withFcmToken)
                .devicesByType(byType)
                .build());
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

    private Instant calculateTrustExpiry(Integer durationDays) {
        int days = durationDays != null ? Math.min(durationDays, 90) : 30; // Default 30 days, max 90
        return Instant.now().plus(days, ChronoUnit.DAYS);
    }

    private TrustedDeviceDto mapToTrustedDeviceDto(TrustedDevice device) {
        return TrustedDeviceDto.builder()
                .id(device.getId())
                .deviceFingerprint(device.getDeviceFingerprint())
                .deviceName(device.getDeviceName())
                .deviceType(device.getDeviceType())
                .osName(device.getOsName())
                .browserName(device.getBrowserName())
                .trusted(device.isTrusted())
                .trustedAt(device.getTrustedAt())
                .lastUsedAt(device.getLastUsedAt())
                .expiresAt(device.getExpiresAt())
                .expired(device.isExpired())
                .build();
    }

    // ==================== Request/Response DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class DevicesListResponse {
        private String userId;
        private int deviceCount;
        private List<LinkedDeviceDto> devices;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TrustedDevicesResponse {
        private String userId;
        private int trustedDeviceCount;
        private List<TrustedDeviceDto> devices;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TrustedDeviceDto {
        private UUID id;
        private String deviceFingerprint;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String browserName;
        private boolean trusted;
        private Instant trustedAt;
        private Instant lastUsedAt;
        private Instant expiresAt;
        private boolean expired;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TrustDeviceRequest {
        @NotBlank
        private String deviceFingerprint;

        private String deviceName;
        private String deviceType;
        private String osName;
        private String browserName;

        @jakarta.validation.constraints.Min(1)
        @jakarta.validation.constraints.Max(90)
        private Integer trustDurationDays; // Default 30, max 90
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class DeviceStatsResponse {
        private int linkedDeviceCount;
        private int trustedDeviceCount;
        private int devicesWithFcmToken;
        private Map<String, Long> devicesByType;
    }
}
