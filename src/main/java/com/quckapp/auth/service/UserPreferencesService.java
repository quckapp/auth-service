package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.UserPreferencesDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for User Preferences management
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserPreferencesService {

    private final UserNotificationPreferencesRepository notificationRepository;
    private final UserSecurityPreferencesRepository securityRepository;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final AuthUserRepository authUserRepository;

    // ==================== Combined Preferences ====================

    @Transactional(readOnly = true)
    public UserPreferencesDto getUserPreferences(UUID userId) {
        NotificationPreferencesDto notifications = getNotificationPreferences(userId);
        SecurityPreferencesDto security = getSecurityPreferences(userId);
        List<TrustedDeviceDto> trustedDevices = getTrustedDevices(userId);

        return UserPreferencesDto.builder()
                .userId(userId)
                .notificationPreferences(notifications)
                .securityPreferences(security)
                .trustedDevices(trustedDevices)
                .build();
    }

    // ==================== Notification Preferences ====================

    @Transactional(readOnly = true)
    public NotificationPreferencesDto getNotificationPreferences(UUID userId) {
        return notificationRepository.findByUserId(userId)
                .map(NotificationPreferencesDto::from)
                .orElseGet(() -> createDefaultNotificationPreferences(userId));
    }

    public NotificationPreferencesDto createDefaultNotificationPreferences(UUID userId) {
        log.info("Creating default notification preferences for user: {}", userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        UserNotificationPreferences prefs = UserNotificationPreferences.builder()
                .user(user)
                .build();

        prefs = notificationRepository.save(prefs);
        log.info("Default notification preferences created for user: {}", userId);
        return NotificationPreferencesDto.from(prefs);
    }

    public NotificationPreferencesDto updateNotificationPreferences(UUID userId, UpdateNotificationPreferencesRequest request) {
        log.info("Updating notification preferences for user: {}", userId);

        UserNotificationPreferences prefs = notificationRepository.findByUserId(userId)
                .orElseGet(() -> {
                    AuthUser user = authUserRepository.findById(userId)
                            .orElseThrow(() -> new RuntimeException("User not found: " + userId));
                    return UserNotificationPreferences.builder().user(user).build();
                });

        // Update email preferences
        if (request.getEmailMarketing() != null) prefs.setEmailMarketing(request.getEmailMarketing());
        if (request.getEmailSecurityAlerts() != null) prefs.setEmailSecurityAlerts(request.getEmailSecurityAlerts());
        if (request.getEmailLoginAlerts() != null) prefs.setEmailLoginAlerts(request.getEmailLoginAlerts());
        if (request.getEmailWeeklyDigest() != null) prefs.setEmailWeeklyDigest(request.getEmailWeeklyDigest());
        if (request.getEmailProductUpdates() != null) prefs.setEmailProductUpdates(request.getEmailProductUpdates());

        // Update push preferences
        if (request.getPushDirectMessages() != null) prefs.setPushDirectMessages(request.getPushDirectMessages());
        if (request.getPushMentions() != null) prefs.setPushMentions(request.getPushMentions());
        if (request.getPushReplies() != null) prefs.setPushReplies(request.getPushReplies());
        if (request.getPushLikes() != null) prefs.setPushLikes(request.getPushLikes());
        if (request.getPushFollows() != null) prefs.setPushFollows(request.getPushFollows());
        if (request.getPushSystemAlerts() != null) prefs.setPushSystemAlerts(request.getPushSystemAlerts());

        // Update quiet hours
        if (request.getQuietHoursEnabled() != null) prefs.setQuietHoursEnabled(request.getQuietHoursEnabled());
        if (request.getQuietHoursStart() != null) prefs.setQuietHoursStart(request.getQuietHoursStart());
        if (request.getQuietHoursEnd() != null) prefs.setQuietHoursEnd(request.getQuietHoursEnd());
        if (request.getQuietHoursTimezone() != null) prefs.setQuietHoursTimezone(request.getQuietHoursTimezone());

        // Update SMS preferences
        if (request.getSmsEnabled() != null) prefs.setSmsEnabled(request.getSmsEnabled());
        if (request.getSmsSecurityOnly() != null) prefs.setSmsSecurityOnly(request.getSmsSecurityOnly());

        prefs = notificationRepository.save(prefs);
        log.info("Notification preferences updated for user: {}", userId);
        return NotificationPreferencesDto.from(prefs);
    }

    // ==================== Security Preferences ====================

    @Transactional(readOnly = true)
    public SecurityPreferencesDto getSecurityPreferences(UUID userId) {
        return securityRepository.findByUserId(userId)
                .map(SecurityPreferencesDto::from)
                .orElseGet(() -> createDefaultSecurityPreferences(userId));
    }

    public SecurityPreferencesDto createDefaultSecurityPreferences(UUID userId) {
        log.info("Creating default security preferences for user: {}", userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        UserSecurityPreferences prefs = UserSecurityPreferences.builder()
                .user(user)
                .build();

        prefs = securityRepository.save(prefs);
        log.info("Default security preferences created for user: {}", userId);
        return SecurityPreferencesDto.from(prefs);
    }

    public SecurityPreferencesDto updateSecurityPreferences(UUID userId, UpdateSecurityPreferencesRequest request) {
        log.info("Updating security preferences for user: {}", userId);

        UserSecurityPreferences prefs = securityRepository.findByUserId(userId)
                .orElseGet(() -> {
                    AuthUser user = authUserRepository.findById(userId)
                            .orElseThrow(() -> new RuntimeException("User not found: " + userId));
                    return UserSecurityPreferences.builder().user(user).build();
                });

        // Update login security
        if (request.getRequire2faForSensitiveActions() != null) {
            prefs.setRequire2faForSensitiveActions(request.getRequire2faForSensitiveActions());
        }
        if (request.getLoginNotificationEnabled() != null) {
            prefs.setLoginNotificationEnabled(request.getLoginNotificationEnabled());
        }
        if (request.getNewDeviceNotification() != null) {
            prefs.setNewDeviceNotification(request.getNewDeviceNotification());
        }
        if (request.getSuspiciousActivityNotification() != null) {
            prefs.setSuspiciousActivityNotification(request.getSuspiciousActivityNotification());
        }

        // Update session preferences
        if (request.getSessionTimeoutMinutes() != null) {
            prefs.setSessionTimeoutMinutes(request.getSessionTimeoutMinutes());
        }
        if (request.getMaxConcurrentSessions() != null) {
            prefs.setMaxConcurrentSessions(request.getMaxConcurrentSessions());
        }
        if (request.getRememberTrustedDevices() != null) {
            prefs.setRememberTrustedDevices(request.getRememberTrustedDevices());
        }
        if (request.getTrustedDeviceExpiryDays() != null) {
            prefs.setTrustedDeviceExpiryDays(request.getTrustedDeviceExpiryDays());
        }

        // Update password preferences
        if (request.getPasswordExpiryDays() != null) {
            prefs.setPasswordExpiryDays(request.getPasswordExpiryDays());
        }

        // Update IP restrictions
        if (request.getIpWhitelistEnabled() != null) {
            prefs.setIpWhitelistEnabled(request.getIpWhitelistEnabled());
        }

        prefs = securityRepository.save(prefs);
        log.info("Security preferences updated for user: {}", userId);
        return SecurityPreferencesDto.from(prefs);
    }

    // ==================== IP Whitelist Management ====================

    public void addIpToWhitelist(UUID userId, String ipAddress) {
        log.info("Adding IP {} to whitelist for user: {}", ipAddress, userId);

        UserSecurityPreferences prefs = securityRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Security preferences not found for user: " + userId));

        prefs.getIpWhitelist().add(ipAddress);
        securityRepository.save(prefs);

        log.info("IP added to whitelist for user: {}", userId);
    }

    public void removeIpFromWhitelist(UUID userId, String ipAddress) {
        log.info("Removing IP {} from whitelist for user: {}", ipAddress, userId);

        UserSecurityPreferences prefs = securityRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Security preferences not found for user: " + userId));

        prefs.getIpWhitelist().remove(ipAddress);
        securityRepository.save(prefs);

        log.info("IP removed from whitelist for user: {}", userId);
    }

    @Transactional(readOnly = true)
    public boolean isIpAllowed(UUID userId, String ipAddress) {
        return securityRepository.findByUserId(userId)
                .map(prefs -> prefs.isIpAllowed(ipAddress))
                .orElse(true); // Allow by default if no preferences exist
    }

    // ==================== Trusted Devices ====================

    @Transactional(readOnly = true)
    public List<TrustedDeviceDto> getTrustedDevices(UUID userId) {
        return trustedDeviceRepository.findActiveTrustedDevicesByUserId(userId).stream()
                .map(TrustedDeviceDto::from)
                .collect(Collectors.toList());
    }

    public TrustedDeviceDto trustDevice(UUID userId, TrustDeviceRequest request) {
        log.info("Trusting device for user: {}", userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        // Check if device already trusted
        Optional<TrustedDevice> existing = trustedDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, request.getDeviceFingerprint());

        TrustedDevice device;
        if (existing.isPresent()) {
            // Reactivate existing device
            device = existing.get();
            device.setTrusted(true);
            device.setTrustedAt(Instant.now());
            device.setLastUsedAt(Instant.now());
            if (request.getExpiryDays() != null) {
                device.setExpiresAt(Instant.now().plus(request.getExpiryDays(), ChronoUnit.DAYS));
            }
        } else {
            // Get expiry days from user preferences or use default
            int expiryDays = request.getExpiryDays() != null ? request.getExpiryDays() :
                    securityRepository.findByUserId(userId)
                            .map(UserSecurityPreferences::getTrustedDeviceExpiryDays)
                            .orElse(30);

            device = TrustedDevice.builder()
                    .user(user)
                    .deviceFingerprint(request.getDeviceFingerprint())
                    .deviceName(request.getDeviceName())
                    .deviceType(request.getDeviceType())
                    .osName(request.getOsName())
                    .browserName(request.getBrowserName())
                    .isTrusted(true)
                    .expiresAt(Instant.now().plus(expiryDays, ChronoUnit.DAYS))
                    .build();
        }

        device = trustedDeviceRepository.save(device);
        log.info("Device trusted for user: {}", userId);
        return TrustedDeviceDto.from(device);
    }

    public void revokeTrustedDevice(UUID userId, UUID deviceId) {
        log.info("Revoking trusted device {} for user: {}", deviceId, userId);
        trustedDeviceRepository.revokeTrust(deviceId);
        log.info("Device trust revoked");
    }

    public void revokeAllTrustedDevices(UUID userId) {
        log.info("Revoking all trusted devices for user: {}", userId);
        trustedDeviceRepository.revokeAllTrustedDevices(userId);
        log.info("All devices revoked for user: {}", userId);
    }

    public void revokeOtherTrustedDevices(UUID userId, UUID currentDeviceId) {
        log.info("Revoking other trusted devices for user: {}", userId);
        trustedDeviceRepository.revokeOtherTrustedDevices(userId, currentDeviceId);
        log.info("Other devices revoked for user: {}", userId);
    }

    @Transactional(readOnly = true)
    public boolean isDeviceTrusted(UUID userId, String deviceFingerprint) {
        return trustedDeviceRepository.isDeviceTrusted(userId, deviceFingerprint);
    }

    public void updateTrustedDeviceLastUsed(UUID userId, String deviceFingerprint) {
        trustedDeviceRepository.findValidTrustedDevice(userId, deviceFingerprint)
                .ifPresent(device -> {
                    device.updateLastUsed();
                    trustedDeviceRepository.save(device);
                });
    }

    // ==================== Maintenance ====================

    public int revokeExpiredTrustedDevices() {
        log.info("Revoking expired trusted devices");
        int count = trustedDeviceRepository.revokeExpiredDevices();
        log.info("Revoked {} expired trusted devices", count);
        return count;
    }

    public int deleteExpiredTrustedDevices(int daysAfterExpiry) {
        Instant threshold = Instant.now().minus(daysAfterExpiry, ChronoUnit.DAYS);
        log.info("Deleting trusted devices expired more than {} days ago", daysAfterExpiry);
        int count = trustedDeviceRepository.deleteExpiredDevices(threshold);
        log.info("Deleted {} expired trusted devices", count);
        return count;
    }

    // ==================== Notification Helpers ====================

    @Transactional(readOnly = true)
    public List<UUID> findUsersWithSecurityAlertsEnabled() {
        return notificationRepository.findUserIdsWithSecurityAlertsEnabled();
    }

    @Transactional(readOnly = true)
    public List<UUID> findUsersWithLoginAlertsEnabled() {
        return notificationRepository.findUserIdsWithLoginAlertsEnabled();
    }

    @Transactional(readOnly = true)
    public boolean shouldSendNotification(UUID userId, String notificationType) {
        return notificationRepository.findByUserId(userId)
                .map(prefs -> {
                    switch (notificationType.toLowerCase()) {
                        case "security_alert":
                            return prefs.isEmailSecurityAlerts();
                        case "login_alert":
                            return prefs.isEmailLoginAlerts();
                        case "marketing":
                            return prefs.isEmailMarketing();
                        case "weekly_digest":
                            return prefs.isEmailWeeklyDigest();
                        case "product_update":
                            return prefs.isEmailProductUpdates();
                        default:
                            return true;
                    }
                })
                .orElse(true); // Default to sending if no preferences
    }
}
