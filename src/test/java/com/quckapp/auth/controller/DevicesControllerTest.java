package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.DeviceType;
import com.quckapp.auth.domain.entity.TrustedDevice;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.TrustedDeviceRepository;
import com.quckapp.auth.dto.UserProfileDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.LinkedDeviceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for DevicesController
 */
@ExtendWith(MockitoExtension.class)
class DevicesControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }
    }

    @Mock
    private LinkedDeviceService linkedDeviceService;

    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private JwtOperations jwtOperations;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final UUID TEST_USER_ID = UUID.randomUUID();
    private static final UUID TEST_DEVICE_ID = UUID.randomUUID();
    private static final String VALID_TOKEN = "valid-token";
    private static final String AUTH_HEADER = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        DevicesController controller = new DevicesController(
                linkedDeviceService, trustedDeviceRepository, authUserRepository, jwtOperations);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Link Device Tests")
    class LinkDeviceTests {

        @Test
        @DisplayName("should link device successfully")
        void shouldLinkDeviceSuccessfully() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("device-123")
                    .deviceName("iPhone 15 Pro")
                    .deviceType(DeviceType.MOBILE)
                    .fcmToken("fcm-token-123")
                    .build();

            LinkedDeviceDto response = LinkedDeviceDto.builder()
                    .deviceId("device-123")
                    .deviceName("iPhone 15 Pro")
                    .deviceType(com.quckapp.auth.domain.entity.DeviceType.MOBILE)
                    .linkedAt(Instant.now())
                    .build();

            when(linkedDeviceService.linkDevice(eq(TEST_USER_ID), any(LinkDeviceRequest.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/devices/link")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.deviceId").value("device-123"))
                    .andExpect(jsonPath("$.deviceName").value("iPhone 15 Pro"));

            verify(linkedDeviceService).linkDevice(eq(TEST_USER_ID), any(LinkDeviceRequest.class));
        }
    }

    @Nested
    @DisplayName("Get Linked Devices Tests")
    class GetLinkedDevicesTests {

        @Test
        @DisplayName("should get all linked devices")
        void shouldGetAllLinkedDevices() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            LinkedDeviceDto device = LinkedDeviceDto.builder()
                    .deviceId("device-123")
                    .deviceName("Chrome on Windows")
                    .deviceType(com.quckapp.auth.domain.entity.DeviceType.DESKTOP)
                    .build();

            when(linkedDeviceService.getLinkedDevices(TEST_USER_ID)).thenReturn(List.of(device));

            mockMvc.perform(get("/v1/devices")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.deviceCount").value(1))
                    .andExpect(jsonPath("$.devices[0].deviceId").value("device-123"));
        }

        @Test
        @DisplayName("should get specific device")
        void shouldGetSpecificDevice() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            LinkedDeviceDto device = LinkedDeviceDto.builder()
                    .deviceId("device-123")
                    .deviceName("iPhone 15 Pro")
                    .build();

            when(linkedDeviceService.getLinkedDevices(TEST_USER_ID)).thenReturn(List.of(device));

            mockMvc.perform(get("/v1/devices/{deviceId}", "device-123")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.deviceId").value("device-123"));
        }

        @Test
        @DisplayName("should return 404 for non-existent device")
        void shouldReturn404ForNonExistentDevice() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(linkedDeviceService.getLinkedDevices(TEST_USER_ID)).thenReturn(List.of());

            mockMvc.perform(get("/v1/devices/{deviceId}", "non-existent")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("Unlink Device Tests")
    class UnlinkDeviceTests {

        @Test
        @DisplayName("should unlink device successfully")
        void shouldUnlinkDeviceSuccessfully() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            mockMvc.perform(delete("/v1/devices/{deviceId}", "device-123")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Device unlinked successfully"));

            verify(linkedDeviceService).unlinkDevice(TEST_USER_ID, "device-123");
        }
    }

    @Nested
    @DisplayName("FCM Token Tests")
    class FcmTokenTests {

        @Test
        @DisplayName("should update FCM token")
        void shouldUpdateFcmToken() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            UpdateFcmTokenRequest request = UpdateFcmTokenRequest.builder()
                    .fcmToken("new-fcm-token")
                    .build();

            mockMvc.perform(put("/v1/devices/{deviceId}/fcm-token", "device-123")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("FCM token updated"));

            verify(linkedDeviceService).updateFcmToken(TEST_USER_ID, "device-123", "new-fcm-token");
        }

        @Test
        @DisplayName("should remove FCM token")
        void shouldRemoveFcmToken() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            mockMvc.perform(delete("/v1/devices/{deviceId}/fcm-token", "device-123")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("FCM token removed"));

            verify(linkedDeviceService).updateFcmToken(TEST_USER_ID, "device-123", null);
        }
    }

    @Nested
    @DisplayName("Trusted Devices Tests")
    class TrustedDevicesTests {

        @Test
        @DisplayName("should get trusted devices")
        void shouldGetTrustedDevices() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            TrustedDevice device = TrustedDevice.builder()
                    .id(TEST_DEVICE_ID)
                    .deviceFingerprint("fingerprint-123")
                    .deviceName("My Laptop")
                    .deviceType("DESKTOP")
                    .isTrusted(true)
                    .trustedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(86400 * 30))
                    .build();

            when(trustedDeviceRepository.findActiveTrustedDevicesByUserId(TEST_USER_ID))
                    .thenReturn(List.of(device));

            mockMvc.perform(get("/v1/devices/trusted")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.trustedDeviceCount").value(1))
                    .andExpect(jsonPath("$.devices[0].deviceFingerprint").value("fingerprint-123"));
        }

        @Test
        @DisplayName("should trust a new device")
        void shouldTrustNewDevice() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            AuthUser user = AuthUser.builder().id(TEST_USER_ID).build();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));
            when(trustedDeviceRepository.findByUserIdAndDeviceFingerprint(TEST_USER_ID, "fingerprint-456"))
                    .thenReturn(Optional.empty());

            TrustedDevice savedDevice = TrustedDevice.builder()
                    .id(UUID.randomUUID())
                    .deviceFingerprint("fingerprint-456")
                    .deviceName("New Device")
                    .isTrusted(true)
                    .trustedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(86400 * 30))
                    .build();
            when(trustedDeviceRepository.save(any(TrustedDevice.class))).thenReturn(savedDevice);

            DevicesController.TrustDeviceRequest request = DevicesController.TrustDeviceRequest.builder()
                    .deviceFingerprint("fingerprint-456")
                    .deviceName("New Device")
                    .deviceType("MOBILE")
                    .trustDurationDays(30)
                    .build();

            mockMvc.perform(post("/v1/devices/trusted")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.deviceFingerprint").value("fingerprint-456"));

            verify(trustedDeviceRepository).save(any(TrustedDevice.class));
        }

        @Test
        @DisplayName("should revoke device trust")
        void shouldRevokeDeviceTrust() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            AuthUser user = AuthUser.builder().id(TEST_USER_ID).build();
            TrustedDevice device = TrustedDevice.builder()
                    .id(TEST_DEVICE_ID)
                    .user(user)
                    .isTrusted(true)
                    .build();

            when(trustedDeviceRepository.findById(TEST_DEVICE_ID)).thenReturn(Optional.of(device));

            mockMvc.perform(delete("/v1/devices/trusted/{deviceId}", TEST_DEVICE_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Device trust revoked"));

            verify(trustedDeviceRepository).save(any(TrustedDevice.class));
        }

        @Test
        @DisplayName("should revoke all trusted devices")
        void shouldRevokeAllTrustedDevices() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(trustedDeviceRepository.revokeAllTrustedDevices(TEST_USER_ID)).thenReturn(3);

            mockMvc.perform(delete("/v1/devices/trusted")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("All trusted devices revoked"))
                    .andExpect(jsonPath("$.revokedCount").value(3));
        }

        @Test
        @DisplayName("should check if device is trusted")
        void shouldCheckIfDeviceIsTrusted() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(trustedDeviceRepository.isDeviceTrusted(TEST_USER_ID, "fingerprint-123")).thenReturn(true);

            mockMvc.perform(get("/v1/devices/trusted/check")
                            .header("Authorization", AUTH_HEADER)
                            .param("fingerprint", "fingerprint-123"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.fingerprint").value("fingerprint-123"))
                    .andExpect(jsonPath("$.trusted").value(true));
        }
    }

    @Nested
    @DisplayName("Device Statistics Tests")
    class DeviceStatisticsTests {

        @Test
        @DisplayName("should get device statistics")
        void shouldGetDeviceStatistics() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(linkedDeviceService.getDeviceCount(TEST_USER_ID)).thenReturn(3);
            when(trustedDeviceRepository.countActiveTrustedDevices(TEST_USER_ID)).thenReturn(2);

            LinkedDeviceDto device1 = LinkedDeviceDto.builder()
                    .deviceType(com.quckapp.auth.domain.entity.DeviceType.MOBILE)
                    .hasFcmToken(true)
                    .build();
            LinkedDeviceDto device2 = LinkedDeviceDto.builder()
                    .deviceType(com.quckapp.auth.domain.entity.DeviceType.DESKTOP)
                    .hasFcmToken(false)
                    .build();

            when(linkedDeviceService.getLinkedDevices(TEST_USER_ID)).thenReturn(List.of(device1, device2));

            mockMvc.perform(get("/v1/devices/stats")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.linkedDeviceCount").value(3))
                    .andExpect(jsonPath("$.trustedDeviceCount").value(2))
                    .andExpect(jsonPath("$.devicesWithFcmToken").value(1));
        }
    }

    @Nested
    @DisplayName("Device Activity Tests")
    class DeviceActivityTests {

        @Test
        @DisplayName("should update device activity")
        void shouldUpdateDeviceActivity() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            mockMvc.perform(put("/v1/devices/{deviceId}/activity", "device-123")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk());

            verify(linkedDeviceService).updateDeviceActivity(TEST_USER_ID, "device-123");
        }
    }
}
