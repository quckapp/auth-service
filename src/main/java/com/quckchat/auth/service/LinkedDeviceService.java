package com.quckchat.auth.service;

import com.quckchat.auth.domain.entity.DeviceType;
import com.quckchat.auth.domain.entity.LinkedDevice;
import com.quckchat.auth.domain.entity.UserProfile;
import com.quckchat.auth.domain.repository.LinkedDeviceRepository;
import com.quckchat.auth.domain.repository.UserProfileRepository;
import com.quckchat.auth.dto.UserProfileDtos.*;
import com.quckchat.auth.kafka.UserEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for linked device and FCM token management
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class LinkedDeviceService {

    private final LinkedDeviceRepository deviceRepository;
    private final UserProfileRepository profileRepository;
    private final UserEventPublisher eventPublisher;

    // ==================== Device Management ====================

    public LinkedDeviceDto linkDevice(UUID userId, LinkDeviceRequest request) {
        log.info("Linking device for user {}: {}", userId, request.getDeviceId());

        UserProfile profile = profileRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found: " + userId));

        // Check if device already exists
        Optional<LinkedDevice> existing = deviceRepository.findByUserProfileIdAndDeviceId(userId, request.getDeviceId());

        LinkedDevice device;
        if (existing.isPresent()) {
            // Update existing device
            device = existing.get();
            device.setDeviceName(request.getDeviceName() != null ? request.getDeviceName() : device.getDeviceName());
            device.setDeviceType(request.getDeviceType() != null ? request.getDeviceType() : device.getDeviceType());
            device.setFcmToken(request.getFcmToken());
            device.updateActivity();
            log.info("Updated existing device: {}", device.getId());
        } else {
            // Create new device
            device = LinkedDevice.create(
                    profile,
                    request.getDeviceId(),
                    request.getDeviceName(),
                    request.getDeviceType() != null ? request.getDeviceType() : DeviceType.MOBILE,
                    request.getFcmToken()
            );
            log.info("Created new device for user: {}", userId);
        }

        device = deviceRepository.save(device);

        // Publish event
        eventPublisher.publishDeviceLinked(userId, device);

        return LinkedDeviceDto.from(device);
    }

    @Transactional(readOnly = true)
    public List<LinkedDeviceDto> getLinkedDevices(UUID userId) {
        return deviceRepository.findByUserProfileId(userId).stream()
                .map(LinkedDeviceDto::from)
                .collect(Collectors.toList());
    }

    public void unlinkDevice(UUID userId, String deviceId) {
        log.info("Unlinking device {} for user {}", deviceId, userId);

        LinkedDevice device = deviceRepository.findByUserProfileIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new RuntimeException("Device not found: " + deviceId));

        deviceRepository.delete(device);

        // Publish event
        eventPublisher.publishDeviceUnlinked(userId, deviceId);

        log.info("Device unlinked successfully: {}", deviceId);
    }

    public void updateDeviceActivity(UUID userId, String deviceId) {
        int updated = deviceRepository.updateDeviceActivity(userId, deviceId, Instant.now());
        if (updated == 0) {
            log.warn("Device not found for activity update: userId={}, deviceId={}", userId, deviceId);
        }
    }

    // ==================== FCM Token Management ====================

    public void updateFcmToken(UUID userId, String deviceId, String fcmToken) {
        log.info("Updating FCM token for user {} device {}", userId, deviceId);

        // Clear old token if it exists on another device
        if (fcmToken != null && !fcmToken.isBlank()) {
            deviceRepository.clearFcmToken(fcmToken);
        }

        int updated = deviceRepository.updateFcmToken(userId, deviceId, fcmToken);
        if (updated == 0) {
            // Device doesn't exist, create it with the token
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId(deviceId)
                    .fcmToken(fcmToken)
                    .build();
            linkDevice(userId, request);
        }

        log.info("FCM token updated for user {} device {}", userId, deviceId);
    }

    @Transactional(readOnly = true)
    public List<String> getFcmTokens(UUID userId) {
        return deviceRepository.findFcmTokensByUserId(userId);
    }

    @Transactional(readOnly = true)
    public List<String> getFcmTokensForUsers(List<UUID> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return List.of();
        }
        return deviceRepository.findFcmTokensByUserIds(userIds);
    }

    @Transactional(readOnly = true)
    public Map<UUID, List<String>> getFcmTokensGroupedByUsers(List<UUID> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return Map.of();
        }

        List<Object[]> results = deviceRepository.findFcmTokensGroupedByUserIds(userIds);

        Map<UUID, List<String>> grouped = new HashMap<>();
        for (Object[] row : results) {
            UUID userId = (UUID) row[0];
            String token = (String) row[1];
            grouped.computeIfAbsent(userId, k -> new ArrayList<>()).add(token);
        }

        return grouped;
    }

    // ==================== Cleanup ====================

    public int cleanupInactiveDevices(int daysInactive) {
        Instant threshold = Instant.now().minusSeconds(daysInactive * 24 * 60 * 60L);
        int deleted = deviceRepository.deleteInactiveDevices(threshold);
        log.info("Cleaned up {} inactive devices (inactive > {} days)", deleted, daysInactive);
        return deleted;
    }

    // ==================== Statistics ====================

    @Transactional(readOnly = true)
    public int getDeviceCount(UUID userId) {
        return deviceRepository.countDevicesByUserId(userId);
    }

    @Transactional(readOnly = true)
    public Map<String, Long> getDeviceTypeStatistics() {
        return deviceRepository.countByDeviceType().stream()
                .collect(Collectors.toMap(
                        arr -> ((DeviceType) arr[0]).name(),
                        arr -> (Long) arr[1]
                ));
    }
}
