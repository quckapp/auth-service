package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.DeviceType;
import com.quckapp.auth.domain.entity.LinkedDevice;
import com.quckapp.auth.domain.entity.UserProfile;
import com.quckapp.auth.domain.repository.LinkedDeviceRepository;
import com.quckapp.auth.domain.repository.UserProfileRepository;
import com.quckapp.auth.dto.UserProfileDtos.LinkDeviceRequest;
import com.quckapp.auth.dto.UserProfileDtos.LinkedDeviceDto;
import com.quckapp.auth.kafka.UserEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for LinkedDeviceService
 */
@ExtendWith(MockitoExtension.class)
class LinkedDeviceServiceTest {

    @Mock
    private LinkedDeviceRepository deviceRepository;

    @Mock
    private UserProfileRepository profileRepository;

    @Mock
    private UserEventPublisher eventPublisher;

    private LinkedDeviceService linkedDeviceService;

    private UUID testUserId;
    private UserProfile testProfile;
    private LinkedDevice testDevice;

    @BeforeEach
    void setUp() {
        linkedDeviceService = new LinkedDeviceService(deviceRepository, profileRepository, eventPublisher);

        testUserId = UUID.randomUUID();
        testProfile = UserProfile.builder()
                .id(testUserId)
                .username("testuser")
                .displayName("Test User")
                .build();

        testDevice = LinkedDevice.builder()
                .id(UUID.randomUUID())
                .userProfile(testProfile)
                .deviceId("device-123")
                .deviceName("Test Device")
                .deviceType(DeviceType.MOBILE)
                .fcmToken("fcm-token-123")
                .lastActive(Instant.now())
                .linkedAt(Instant.now())
                .build();
    }

    @Nested
    @DisplayName("Link Device Tests")
    class LinkDeviceTests {

        @Test
        @DisplayName("should link new device successfully")
        void shouldLinkNewDevice() {
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("new-device-456")
                    .deviceName("New Device")
                    .deviceType(DeviceType.MOBILE)
                    .fcmToken("new-fcm-token")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(deviceRepository.findByUserProfileIdAndDeviceId(testUserId, "new-device-456"))
                    .thenReturn(Optional.empty());
            when(deviceRepository.save(any(LinkedDevice.class))).thenAnswer(invocation -> {
                LinkedDevice device = invocation.getArgument(0);
                device.setId(UUID.randomUUID());
                return device;
            });

            LinkedDeviceDto result = linkedDeviceService.linkDevice(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(result.getDeviceId()).isEqualTo("new-device-456");
            assertThat(result.getDeviceName()).isEqualTo("New Device");
            assertThat(result.getDeviceType()).isEqualTo(DeviceType.MOBILE);

            verify(deviceRepository).save(any(LinkedDevice.class));
            verify(eventPublisher).publishDeviceLinked(eq(testUserId), any(LinkedDevice.class));
        }

        @Test
        @DisplayName("should update existing device")
        void shouldUpdateExistingDevice() {
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("device-123")
                    .deviceName("Updated Device")
                    .fcmToken("updated-fcm-token")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(deviceRepository.findByUserProfileIdAndDeviceId(testUserId, "device-123"))
                    .thenReturn(Optional.of(testDevice));
            when(deviceRepository.save(any(LinkedDevice.class))).thenReturn(testDevice);

            LinkedDeviceDto result = linkedDeviceService.linkDevice(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(testDevice.getDeviceName()).isEqualTo("Updated Device");
            assertThat(testDevice.getFcmToken()).isEqualTo("updated-fcm-token");

            verify(deviceRepository).save(testDevice);
            verify(eventPublisher).publishDeviceLinked(eq(testUserId), eq(testDevice));
        }

        @Test
        @DisplayName("should throw exception when profile not found")
        void shouldThrowWhenProfileNotFound() {
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("device-123")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> linkedDeviceService.linkDevice(testUserId, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Profile not found");

            verify(deviceRepository, never()).save(any());
        }

        @Test
        @DisplayName("should use default device type when not specified")
        void shouldUseDefaultDeviceType() {
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("new-device-789")
                    .deviceName("New Device")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(deviceRepository.findByUserProfileIdAndDeviceId(testUserId, "new-device-789"))
                    .thenReturn(Optional.empty());
            when(deviceRepository.save(any(LinkedDevice.class))).thenAnswer(invocation -> {
                LinkedDevice device = invocation.getArgument(0);
                device.setId(UUID.randomUUID());
                return device;
            });

            linkedDeviceService.linkDevice(testUserId, request);

            ArgumentCaptor<LinkedDevice> deviceCaptor = ArgumentCaptor.forClass(LinkedDevice.class);
            verify(deviceRepository).save(deviceCaptor.capture());
            assertThat(deviceCaptor.getValue().getDeviceType()).isEqualTo(DeviceType.MOBILE);
        }
    }

    @Nested
    @DisplayName("Get Linked Devices Tests")
    class GetLinkedDevicesTests {

        @Test
        @DisplayName("should return all linked devices for user")
        void shouldReturnAllLinkedDevices() {
            LinkedDevice device2 = LinkedDevice.builder()
                    .id(UUID.randomUUID())
                    .userProfile(testProfile)
                    .deviceId("device-456")
                    .deviceName("Second Device")
                    .deviceType(DeviceType.DESKTOP)
                    .lastActive(Instant.now())
                    .build();

            when(deviceRepository.findByUserProfileId(testUserId))
                    .thenReturn(Arrays.asList(testDevice, device2));

            List<LinkedDeviceDto> result = linkedDeviceService.getLinkedDevices(testUserId);

            assertThat(result).hasSize(2);
            assertThat(result).extracting(LinkedDeviceDto::getDeviceId)
                    .containsExactlyInAnyOrder("device-123", "device-456");
        }

        @Test
        @DisplayName("should return empty list when no devices")
        void shouldReturnEmptyListWhenNoDevices() {
            when(deviceRepository.findByUserProfileId(testUserId)).thenReturn(Collections.emptyList());

            List<LinkedDeviceDto> result = linkedDeviceService.getLinkedDevices(testUserId);

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Unlink Device Tests")
    class UnlinkDeviceTests {

        @Test
        @DisplayName("should unlink device successfully")
        void shouldUnlinkDeviceSuccessfully() {
            when(deviceRepository.findByUserProfileIdAndDeviceId(testUserId, "device-123"))
                    .thenReturn(Optional.of(testDevice));

            linkedDeviceService.unlinkDevice(testUserId, "device-123");

            verify(deviceRepository).delete(testDevice);
            verify(eventPublisher).publishDeviceUnlinked(testUserId, "device-123");
        }

        @Test
        @DisplayName("should throw exception when device not found")
        void shouldThrowWhenDeviceNotFound() {
            when(deviceRepository.findByUserProfileIdAndDeviceId(testUserId, "nonexistent"))
                    .thenReturn(Optional.empty());

            assertThatThrownBy(() -> linkedDeviceService.unlinkDevice(testUserId, "nonexistent"))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Device not found");

            verify(deviceRepository, never()).delete(any());
        }
    }

    @Nested
    @DisplayName("Update Device Activity Tests")
    class UpdateDeviceActivityTests {

        @Test
        @DisplayName("should update device activity")
        void shouldUpdateDeviceActivity() {
            when(deviceRepository.updateDeviceActivity(eq(testUserId), eq("device-123"), any(Instant.class)))
                    .thenReturn(1);

            linkedDeviceService.updateDeviceActivity(testUserId, "device-123");

            verify(deviceRepository).updateDeviceActivity(eq(testUserId), eq("device-123"), any(Instant.class));
        }

        @Test
        @DisplayName("should not throw when device not found for activity update")
        void shouldNotThrowWhenDeviceNotFoundForActivityUpdate() {
            when(deviceRepository.updateDeviceActivity(eq(testUserId), eq("nonexistent"), any(Instant.class)))
                    .thenReturn(0);

            assertThatNoException().isThrownBy(() ->
                    linkedDeviceService.updateDeviceActivity(testUserId, "nonexistent"));
        }
    }

    @Nested
    @DisplayName("FCM Token Management Tests")
    class FcmTokenManagementTests {

        @Test
        @DisplayName("should update FCM token for existing device")
        void shouldUpdateFcmTokenForExistingDevice() {
            when(deviceRepository.updateFcmToken(testUserId, "device-123", "new-token")).thenReturn(1);

            linkedDeviceService.updateFcmToken(testUserId, "device-123", "new-token");

            verify(deviceRepository).clearFcmToken("new-token");
            verify(deviceRepository).updateFcmToken(testUserId, "device-123", "new-token");
        }

        @Test
        @DisplayName("should create device when updating FCM token for non-existing device")
        void shouldCreateDeviceWhenUpdatingFcmTokenForNonExistingDevice() {
            when(deviceRepository.updateFcmToken(testUserId, "new-device", "new-token")).thenReturn(0);
            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(deviceRepository.findByUserProfileIdAndDeviceId(testUserId, "new-device"))
                    .thenReturn(Optional.empty());
            when(deviceRepository.save(any(LinkedDevice.class))).thenAnswer(invocation -> {
                LinkedDevice device = invocation.getArgument(0);
                device.setId(UUID.randomUUID());
                return device;
            });

            linkedDeviceService.updateFcmToken(testUserId, "new-device", "new-token");

            verify(deviceRepository).save(any(LinkedDevice.class));
        }

        @Test
        @DisplayName("should not clear token when null or blank")
        void shouldNotClearTokenWhenNullOrBlank() {
            when(deviceRepository.updateFcmToken(testUserId, "device-123", null)).thenReturn(1);

            linkedDeviceService.updateFcmToken(testUserId, "device-123", null);

            verify(deviceRepository, never()).clearFcmToken(anyString());
        }

        @Test
        @DisplayName("should get FCM tokens for user")
        void shouldGetFcmTokensForUser() {
            List<String> tokens = Arrays.asList("token1", "token2");
            when(deviceRepository.findFcmTokensByUserId(testUserId)).thenReturn(tokens);

            List<String> result = linkedDeviceService.getFcmTokens(testUserId);

            assertThat(result).containsExactly("token1", "token2");
        }

        @Test
        @DisplayName("should get FCM tokens for multiple users")
        void shouldGetFcmTokensForMultipleUsers() {
            List<UUID> userIds = Arrays.asList(testUserId, UUID.randomUUID());
            List<String> tokens = Arrays.asList("token1", "token2", "token3");
            when(deviceRepository.findFcmTokensByUserIds(userIds)).thenReturn(tokens);

            List<String> result = linkedDeviceService.getFcmTokensForUsers(userIds);

            assertThat(result).hasSize(3);
        }

        @Test
        @DisplayName("should return empty list when user ids is null or empty")
        void shouldReturnEmptyListWhenUserIdsIsNullOrEmpty() {
            assertThat(linkedDeviceService.getFcmTokensForUsers(null)).isEmpty();
            assertThat(linkedDeviceService.getFcmTokensForUsers(Collections.emptyList())).isEmpty();
        }

        @Test
        @DisplayName("should get FCM tokens grouped by users")
        void shouldGetFcmTokensGroupedByUsers() {
            UUID userId2 = UUID.randomUUID();
            List<UUID> userIds = Arrays.asList(testUserId, userId2);
            List<Object[]> results = Arrays.asList(
                    new Object[]{testUserId, "token1"},
                    new Object[]{testUserId, "token2"},
                    new Object[]{userId2, "token3"}
            );
            when(deviceRepository.findFcmTokensGroupedByUserIds(userIds)).thenReturn(results);

            Map<UUID, List<String>> result = linkedDeviceService.getFcmTokensGroupedByUsers(userIds);

            assertThat(result).hasSize(2);
            assertThat(result.get(testUserId)).containsExactly("token1", "token2");
            assertThat(result.get(userId2)).containsExactly("token3");
        }

        @Test
        @DisplayName("should return empty map when user ids is null or empty for grouped tokens")
        void shouldReturnEmptyMapWhenUserIdsIsNullOrEmptyForGroupedTokens() {
            assertThat(linkedDeviceService.getFcmTokensGroupedByUsers(null)).isEmpty();
            assertThat(linkedDeviceService.getFcmTokensGroupedByUsers(Collections.emptyList())).isEmpty();
        }
    }

    @Nested
    @DisplayName("Cleanup Tests")
    class CleanupTests {

        @Test
        @DisplayName("should cleanup inactive devices")
        void shouldCleanupInactiveDevices() {
            when(deviceRepository.deleteInactiveDevices(any(Instant.class))).thenReturn(5);

            int deleted = linkedDeviceService.cleanupInactiveDevices(30);

            assertThat(deleted).isEqualTo(5);
            verify(deviceRepository).deleteInactiveDevices(any(Instant.class));
        }
    }

    @Nested
    @DisplayName("Statistics Tests")
    class StatisticsTests {

        @Test
        @DisplayName("should get device count for user")
        void shouldGetDeviceCountForUser() {
            when(deviceRepository.countDevicesByUserId(testUserId)).thenReturn(3);

            int count = linkedDeviceService.getDeviceCount(testUserId);

            assertThat(count).isEqualTo(3);
        }

        @Test
        @DisplayName("should get device type statistics")
        void shouldGetDeviceTypeStatistics() {
            List<Object[]> stats = Arrays.asList(
                    new Object[]{DeviceType.MOBILE, 10L},
                    new Object[]{DeviceType.DESKTOP, 5L},
                    new Object[]{DeviceType.WEB, 2L}
            );
            when(deviceRepository.countByDeviceType()).thenReturn(stats);

            Map<String, Long> result = linkedDeviceService.getDeviceTypeStatistics();

            assertThat(result).hasSize(3);
            assertThat(result.get("MOBILE")).isEqualTo(10L);
            assertThat(result.get("DESKTOP")).isEqualTo(5L);
            assertThat(result.get("WEB")).isEqualTo(2L);
        }
    }
}
