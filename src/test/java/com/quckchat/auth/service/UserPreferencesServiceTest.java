package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.TrustedDevice;
import com.quckapp.auth.domain.entity.UserNotificationPreferences;
import com.quckapp.auth.domain.entity.UserSecurityPreferences;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.TrustedDeviceRepository;
import com.quckapp.auth.domain.repository.UserNotificationPreferencesRepository;
import com.quckapp.auth.domain.repository.UserSecurityPreferencesRepository;
import com.quckapp.auth.dto.UserPreferencesDtos.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserPreferencesService
 */
@ExtendWith(MockitoExtension.class)
class UserPreferencesServiceTest {

    @Mock
    private UserNotificationPreferencesRepository notificationRepository;

    @Mock
    private UserSecurityPreferencesRepository securityRepository;

    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    private UserPreferencesService userPreferencesService;

    private UUID testUserId;
    private AuthUser testUser;
    private UserNotificationPreferences testNotificationPrefs;
    private UserSecurityPreferences testSecurityPrefs;
    private TrustedDevice testTrustedDevice;

    @BeforeEach
    void setUp() {
        userPreferencesService = new UserPreferencesService(
                notificationRepository,
                securityRepository,
                trustedDeviceRepository,
                authUserRepository
        );

        testUserId = UUID.randomUUID();
        testUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .build();

        testNotificationPrefs = UserNotificationPreferences.builder()
                .id(UUID.randomUUID())
                .user(testUser)
                .emailMarketing(false)
                .emailSecurityAlerts(true)
                .emailLoginAlerts(true)
                .pushDirectMessages(true)
                .pushMentions(true)
                .quietHoursEnabled(false)
                .smsEnabled(false)
                .build();

        testSecurityPrefs = UserSecurityPreferences.builder()
                .id(UUID.randomUUID())
                .user(testUser)
                .require2faForSensitiveActions(false)
                .loginNotificationEnabled(true)
                .sessionTimeoutMinutes(1440)
                .maxConcurrentSessions(5)
                .rememberTrustedDevices(true)
                .trustedDeviceExpiryDays(30)
                .ipWhitelistEnabled(false)
                .ipWhitelist(new HashSet<>())
                .build();

        testTrustedDevice = TrustedDevice.builder()
                .id(UUID.randomUUID())
                .user(testUser)
                .deviceFingerprint("fp-123")
                .deviceName("Test Device")
                .deviceType("Desktop")
                .osName("Windows 11")
                .browserName("Chrome")
                .isTrusted(true)
                .trustedAt(Instant.now())
                .lastUsedAt(Instant.now())
                .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
                .build();
    }

    @Nested
    @DisplayName("Get User Preferences Tests")
    class GetUserPreferencesTests {

        @Test
        @DisplayName("should return all user preferences")
        void shouldReturnAllUserPreferences() {
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));
            when(trustedDeviceRepository.findActiveTrustedDevicesByUserId(testUserId))
                    .thenReturn(Collections.singletonList(testTrustedDevice));

            UserPreferencesDto result = userPreferencesService.getUserPreferences(testUserId);

            assertThat(result).isNotNull();
            assertThat(result.getUserId()).isEqualTo(testUserId);
            assertThat(result.getNotificationPreferences()).isNotNull();
            assertThat(result.getSecurityPreferences()).isNotNull();
            assertThat(result.getTrustedDevices()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Notification Preferences Tests")
    class NotificationPreferencesTests {

        @Test
        @DisplayName("should return notification preferences")
        void shouldReturnNotificationPreferences() {
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));

            NotificationPreferencesDto result = userPreferencesService.getNotificationPreferences(testUserId);

            assertThat(result).isNotNull();
            assertThat(result.isEmailSecurityAlerts()).isTrue();
            assertThat(result.isPushDirectMessages()).isTrue();
        }

        @Test
        @DisplayName("should create default notification preferences when not found")
        void shouldCreateDefaultNotificationPreferencesWhenNotFound() {
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.empty());
            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(notificationRepository.save(any(UserNotificationPreferences.class)))
                    .thenAnswer(invocation -> {
                        UserNotificationPreferences prefs = invocation.getArgument(0);
                        prefs.setId(UUID.randomUUID());
                        return prefs;
                    });

            NotificationPreferencesDto result = userPreferencesService.getNotificationPreferences(testUserId);

            assertThat(result).isNotNull();
            verify(notificationRepository).save(any(UserNotificationPreferences.class));
        }

        @Test
        @DisplayName("should throw when user not found for default notification preferences")
        void shouldThrowWhenUserNotFoundForDefaultNotificationPreferences() {
            when(authUserRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userPreferencesService.createDefaultNotificationPreferences(testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User not found");
        }

        @Test
        @DisplayName("should update notification preferences")
        void shouldUpdateNotificationPreferences() {
            UpdateNotificationPreferencesRequest request = UpdateNotificationPreferencesRequest.builder()
                    .emailMarketing(true)
                    .emailSecurityAlerts(false)
                    .pushDirectMessages(false)
                    .quietHoursEnabled(true)
                    .quietHoursStart(LocalTime.of(22, 0))
                    .quietHoursEnd(LocalTime.of(7, 0))
                    .quietHoursTimezone("America/New_York")
                    .smsEnabled(true)
                    .smsSecurityOnly(false)
                    .build();

            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));
            when(notificationRepository.save(any(UserNotificationPreferences.class))).thenReturn(testNotificationPrefs);

            NotificationPreferencesDto result = userPreferencesService.updateNotificationPreferences(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(testNotificationPrefs.isEmailMarketing()).isTrue();
            assertThat(testNotificationPrefs.isEmailSecurityAlerts()).isFalse();
            assertThat(testNotificationPrefs.isPushDirectMessages()).isFalse();
            assertThat(testNotificationPrefs.isQuietHoursEnabled()).isTrue();

            verify(notificationRepository).save(testNotificationPrefs);
        }

        @Test
        @DisplayName("should create notification preferences if not exist on update")
        void shouldCreateNotificationPreferencesIfNotExistOnUpdate() {
            UpdateNotificationPreferencesRequest request = UpdateNotificationPreferencesRequest.builder()
                    .emailMarketing(true)
                    .build();

            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.empty());
            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(notificationRepository.save(any(UserNotificationPreferences.class)))
                    .thenAnswer(invocation -> {
                        UserNotificationPreferences prefs = invocation.getArgument(0);
                        prefs.setId(UUID.randomUUID());
                        return prefs;
                    });

            NotificationPreferencesDto result = userPreferencesService.updateNotificationPreferences(testUserId, request);

            assertThat(result).isNotNull();
            verify(notificationRepository).save(any(UserNotificationPreferences.class));
        }
    }

    @Nested
    @DisplayName("Security Preferences Tests")
    class SecurityPreferencesTests {

        @Test
        @DisplayName("should return security preferences")
        void shouldReturnSecurityPreferences() {
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));

            SecurityPreferencesDto result = userPreferencesService.getSecurityPreferences(testUserId);

            assertThat(result).isNotNull();
            assertThat(result.getSessionTimeoutMinutes()).isEqualTo(1440);
            assertThat(result.getMaxConcurrentSessions()).isEqualTo(5);
        }

        @Test
        @DisplayName("should create default security preferences when not found")
        void shouldCreateDefaultSecurityPreferencesWhenNotFound() {
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.empty());
            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(securityRepository.save(any(UserSecurityPreferences.class)))
                    .thenAnswer(invocation -> {
                        UserSecurityPreferences prefs = invocation.getArgument(0);
                        prefs.setId(UUID.randomUUID());
                        return prefs;
                    });

            SecurityPreferencesDto result = userPreferencesService.getSecurityPreferences(testUserId);

            assertThat(result).isNotNull();
            verify(securityRepository).save(any(UserSecurityPreferences.class));
        }

        @Test
        @DisplayName("should throw when user not found for default security preferences")
        void shouldThrowWhenUserNotFoundForDefaultSecurityPreferences() {
            when(authUserRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userPreferencesService.createDefaultSecurityPreferences(testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User not found");
        }

        @Test
        @DisplayName("should update security preferences")
        void shouldUpdateSecurityPreferences() {
            UpdateSecurityPreferencesRequest request = UpdateSecurityPreferencesRequest.builder()
                    .require2faForSensitiveActions(true)
                    .loginNotificationEnabled(false)
                    .newDeviceNotification(false)
                    .sessionTimeoutMinutes(60)
                    .maxConcurrentSessions(3)
                    .rememberTrustedDevices(false)
                    .trustedDeviceExpiryDays(7)
                    .passwordExpiryDays(90)
                    .ipWhitelistEnabled(true)
                    .build();

            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));
            when(securityRepository.save(any(UserSecurityPreferences.class))).thenReturn(testSecurityPrefs);

            SecurityPreferencesDto result = userPreferencesService.updateSecurityPreferences(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(testSecurityPrefs.isRequire2faForSensitiveActions()).isTrue();
            assertThat(testSecurityPrefs.getSessionTimeoutMinutes()).isEqualTo(60);
            assertThat(testSecurityPrefs.getMaxConcurrentSessions()).isEqualTo(3);
            assertThat(testSecurityPrefs.isIpWhitelistEnabled()).isTrue();

            verify(securityRepository).save(testSecurityPrefs);
        }
    }

    @Nested
    @DisplayName("IP Whitelist Tests")
    class IpWhitelistTests {

        @Test
        @DisplayName("should add IP to whitelist")
        void shouldAddIpToWhitelist() {
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));

            userPreferencesService.addIpToWhitelist(testUserId, "192.168.1.100");

            assertThat(testSecurityPrefs.getIpWhitelist()).contains("192.168.1.100");
            verify(securityRepository).save(testSecurityPrefs);
        }

        @Test
        @DisplayName("should throw when security preferences not found for adding IP")
        void shouldThrowWhenSecurityPreferencesNotFoundForAddingIp() {
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userPreferencesService.addIpToWhitelist(testUserId, "192.168.1.100"))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Security preferences not found");
        }

        @Test
        @DisplayName("should remove IP from whitelist")
        void shouldRemoveIpFromWhitelist() {
            testSecurityPrefs.getIpWhitelist().add("192.168.1.100");
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));

            userPreferencesService.removeIpFromWhitelist(testUserId, "192.168.1.100");

            assertThat(testSecurityPrefs.getIpWhitelist()).doesNotContain("192.168.1.100");
            verify(securityRepository).save(testSecurityPrefs);
        }

        @Test
        @DisplayName("should return true when IP is allowed")
        void shouldReturnTrueWhenIpIsAllowed() {
            testSecurityPrefs.setIpWhitelistEnabled(true);
            testSecurityPrefs.getIpWhitelist().add("192.168.1.100");
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));

            boolean result = userPreferencesService.isIpAllowed(testUserId, "192.168.1.100");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false when IP is not allowed")
        void shouldReturnFalseWhenIpIsNotAllowed() {
            testSecurityPrefs.setIpWhitelistEnabled(true);
            testSecurityPrefs.getIpWhitelist().add("192.168.1.100");
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));

            boolean result = userPreferencesService.isIpAllowed(testUserId, "10.0.0.1");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return true when whitelist is disabled")
        void shouldReturnTrueWhenWhitelistIsDisabled() {
            testSecurityPrefs.setIpWhitelistEnabled(false);
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));

            boolean result = userPreferencesService.isIpAllowed(testUserId, "10.0.0.1");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return true when no security preferences exist")
        void shouldReturnTrueWhenNoSecurityPreferencesExist() {
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.empty());

            boolean result = userPreferencesService.isIpAllowed(testUserId, "10.0.0.1");

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Trusted Devices Tests")
    class TrustedDevicesTests {

        @Test
        @DisplayName("should return trusted devices")
        void shouldReturnTrustedDevices() {
            when(trustedDeviceRepository.findActiveTrustedDevicesByUserId(testUserId))
                    .thenReturn(Collections.singletonList(testTrustedDevice));

            List<TrustedDeviceDto> result = userPreferencesService.getTrustedDevices(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getDeviceName()).isEqualTo("Test Device");
        }

        @Test
        @DisplayName("should trust new device")
        void shouldTrustNewDevice() {
            TrustDeviceRequest request = TrustDeviceRequest.builder()
                    .deviceFingerprint("new-fp-456")
                    .deviceName("New Device")
                    .deviceType("Mobile")
                    .osName("iOS 17")
                    .browserName("Safari")
                    .expiryDays(14)
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(trustedDeviceRepository.findByUserIdAndDeviceFingerprint(testUserId, "new-fp-456"))
                    .thenReturn(Optional.empty());
            when(trustedDeviceRepository.save(any(TrustedDevice.class))).thenAnswer(invocation -> {
                TrustedDevice device = invocation.getArgument(0);
                device.setId(UUID.randomUUID());
                return device;
            });

            TrustedDeviceDto result = userPreferencesService.trustDevice(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(result.getDeviceName()).isEqualTo("New Device");

            ArgumentCaptor<TrustedDevice> deviceCaptor = ArgumentCaptor.forClass(TrustedDevice.class);
            verify(trustedDeviceRepository).save(deviceCaptor.capture());
            assertThat(deviceCaptor.getValue().getDeviceFingerprint()).isEqualTo("new-fp-456");
        }

        @Test
        @DisplayName("should reactivate existing trusted device")
        void shouldReactivateExistingTrustedDevice() {
            testTrustedDevice.setTrusted(false);
            TrustDeviceRequest request = TrustDeviceRequest.builder()
                    .deviceFingerprint("fp-123")
                    .deviceName("Reactivated Device")
                    .expiryDays(30)
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(trustedDeviceRepository.findByUserIdAndDeviceFingerprint(testUserId, "fp-123"))
                    .thenReturn(Optional.of(testTrustedDevice));
            when(trustedDeviceRepository.save(any(TrustedDevice.class))).thenReturn(testTrustedDevice);

            TrustedDeviceDto result = userPreferencesService.trustDevice(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(testTrustedDevice.isTrusted()).isTrue();
            verify(trustedDeviceRepository).save(testTrustedDevice);
        }

        @Test
        @DisplayName("should use default expiry days from security preferences")
        void shouldUseDefaultExpiryDaysFromSecurityPreferences() {
            TrustDeviceRequest request = TrustDeviceRequest.builder()
                    .deviceFingerprint("new-fp-789")
                    .deviceName("New Device")
                    .build();

            testSecurityPrefs.setTrustedDeviceExpiryDays(60);

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(trustedDeviceRepository.findByUserIdAndDeviceFingerprint(testUserId, "new-fp-789"))
                    .thenReturn(Optional.empty());
            when(securityRepository.findByUserId(testUserId)).thenReturn(Optional.of(testSecurityPrefs));
            when(trustedDeviceRepository.save(any(TrustedDevice.class))).thenAnswer(invocation -> {
                TrustedDevice device = invocation.getArgument(0);
                device.setId(UUID.randomUUID());
                return device;
            });

            userPreferencesService.trustDevice(testUserId, request);

            ArgumentCaptor<TrustedDevice> deviceCaptor = ArgumentCaptor.forClass(TrustedDevice.class);
            verify(trustedDeviceRepository).save(deviceCaptor.capture());
            // Expiry should be approximately 60 days from now
            assertThat(deviceCaptor.getValue().getExpiresAt())
                    .isAfter(Instant.now().plus(59, ChronoUnit.DAYS));
        }

        @Test
        @DisplayName("should revoke trusted device")
        void shouldRevokeTrustedDevice() {
            UUID deviceId = UUID.randomUUID();

            userPreferencesService.revokeTrustedDevice(testUserId, deviceId);

            verify(trustedDeviceRepository).revokeTrust(deviceId);
        }

        @Test
        @DisplayName("should revoke all trusted devices")
        void shouldRevokeAllTrustedDevices() {
            userPreferencesService.revokeAllTrustedDevices(testUserId);

            verify(trustedDeviceRepository).revokeAllTrustedDevices(testUserId);
        }

        @Test
        @DisplayName("should revoke other trusted devices")
        void shouldRevokeOtherTrustedDevices() {
            UUID currentDeviceId = UUID.randomUUID();

            userPreferencesService.revokeOtherTrustedDevices(testUserId, currentDeviceId);

            verify(trustedDeviceRepository).revokeOtherTrustedDevices(testUserId, currentDeviceId);
        }

        @Test
        @DisplayName("should check if device is trusted")
        void shouldCheckIfDeviceIsTrusted() {
            when(trustedDeviceRepository.isDeviceTrusted(testUserId, "fp-123")).thenReturn(true);

            boolean result = userPreferencesService.isDeviceTrusted(testUserId, "fp-123");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should update trusted device last used")
        void shouldUpdateTrustedDeviceLastUsed() {
            when(trustedDeviceRepository.findValidTrustedDevice(testUserId, "fp-123"))
                    .thenReturn(Optional.of(testTrustedDevice));

            Instant beforeUpdate = testTrustedDevice.getLastUsedAt();
            userPreferencesService.updateTrustedDeviceLastUsed(testUserId, "fp-123");

            verify(trustedDeviceRepository).save(testTrustedDevice);
        }
    }

    @Nested
    @DisplayName("Maintenance Tests")
    class MaintenanceTests {

        @Test
        @DisplayName("should revoke expired trusted devices")
        void shouldRevokeExpiredTrustedDevices() {
            when(trustedDeviceRepository.revokeExpiredDevices()).thenReturn(5);

            int count = userPreferencesService.revokeExpiredTrustedDevices();

            assertThat(count).isEqualTo(5);
            verify(trustedDeviceRepository).revokeExpiredDevices();
        }

        @Test
        @DisplayName("should delete expired trusted devices")
        void shouldDeleteExpiredTrustedDevices() {
            when(trustedDeviceRepository.deleteExpiredDevices(any(Instant.class))).thenReturn(3);

            int count = userPreferencesService.deleteExpiredTrustedDevices(7);

            assertThat(count).isEqualTo(3);
            verify(trustedDeviceRepository).deleteExpiredDevices(any(Instant.class));
        }
    }

    @Nested
    @DisplayName("Notification Helper Tests")
    class NotificationHelperTests {

        @Test
        @DisplayName("should find users with security alerts enabled")
        void shouldFindUsersWithSecurityAlertsEnabled() {
            List<UUID> userIds = Arrays.asList(testUserId, UUID.randomUUID());
            when(notificationRepository.findUserIdsWithSecurityAlertsEnabled()).thenReturn(userIds);

            List<UUID> result = userPreferencesService.findUsersWithSecurityAlertsEnabled();

            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("should find users with login alerts enabled")
        void shouldFindUsersWithLoginAlertsEnabled() {
            List<UUID> userIds = Arrays.asList(testUserId, UUID.randomUUID());
            when(notificationRepository.findUserIdsWithLoginAlertsEnabled()).thenReturn(userIds);

            List<UUID> result = userPreferencesService.findUsersWithLoginAlertsEnabled();

            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("should check if notification should be sent for security alert")
        void shouldCheckIfNotificationShouldBeSentForSecurityAlert() {
            testNotificationPrefs.setEmailSecurityAlerts(true);
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));

            boolean result = userPreferencesService.shouldSendNotification(testUserId, "security_alert");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should check if notification should be sent for login alert")
        void shouldCheckIfNotificationShouldBeSentForLoginAlert() {
            testNotificationPrefs.setEmailLoginAlerts(true);
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));

            boolean result = userPreferencesService.shouldSendNotification(testUserId, "login_alert");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should check if notification should be sent for marketing")
        void shouldCheckIfNotificationShouldBeSentForMarketing() {
            testNotificationPrefs.setEmailMarketing(false);
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));

            boolean result = userPreferencesService.shouldSendNotification(testUserId, "marketing");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return true for unknown notification type")
        void shouldReturnTrueForUnknownNotificationType() {
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.of(testNotificationPrefs));

            boolean result = userPreferencesService.shouldSendNotification(testUserId, "unknown_type");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return true when no preferences exist")
        void shouldReturnTrueWhenNoPreferencesExist() {
            when(notificationRepository.findByUserId(testUserId)).thenReturn(Optional.empty());

            boolean result = userPreferencesService.shouldSendNotification(testUserId, "security_alert");

            assertThat(result).isTrue();
        }
    }
}
