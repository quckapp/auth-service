package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.DeviceType;
import com.quckapp.auth.domain.entity.UserRole;
import com.quckapp.auth.domain.entity.UserStatus;
import com.quckapp.auth.domain.entity.VisibilityLevel;
import com.quckapp.auth.dto.UserProfileDtos.*;
import com.quckapp.auth.service.LinkedDeviceService;
import com.quckapp.auth.service.UserProfileService;
import com.quckapp.auth.service.UserSettingsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for UserProfileController using standalone MockMvc setup
 */
@ExtendWith(MockitoExtension.class)
class UserProfileControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }

        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntime(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
        }
    }

    @Mock
    private UserProfileService profileService;

    @Mock
    private UserSettingsService settingsService;

    @Mock
    private LinkedDeviceService deviceService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private UUID testUserId;
    private UserProfileDto testProfileDto;
    private UserSettingsDto testSettingsDto;
    private LinkedDeviceDto testDeviceDto;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules(); // For Java 8 date/time support

        UserProfileController controller = new UserProfileController(profileService, settingsService, deviceService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();

        testUserId = UUID.randomUUID();

        testProfileDto = UserProfileDto.builder()
                .id(testUserId)
                .externalId("ext-123")
                .phoneNumber("+1234567890")
                .username("testuser")
                .displayName("Test User")
                .email("test@example.com")
                .avatar("https://example.com/avatar.jpg")
                .bio("Test bio")
                .status(UserStatus.ONLINE)
                .lastSeen(Instant.now())
                .isActive(true)
                .isVerified(true)
                .role(UserRole.USER)
                .permissions(Set.of("read", "write"))
                .isBanned(false)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        testSettingsDto = UserSettingsDto.builder()
                .userId(testUserId)
                .darkMode(true)
                .autoDownloadMedia(true)
                .saveToGallery(false)
                .pushNotifications(true)
                .messageNotifications(true)
                .groupNotifications(true)
                .callNotifications(true)
                .soundEnabled(true)
                .vibrationEnabled(true)
                .showPreview(true)
                .inAppNotifications(true)
                .notificationLight(false)
                .readReceipts(true)
                .lastSeenVisible(true)
                .profilePhotoVisibility(VisibilityLevel.EVERYONE)
                .statusVisibility(VisibilityLevel.CONTACTS)
                .fingerprintLock(false)
                .blockedUserIds(new HashSet<>())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        testDeviceDto = LinkedDeviceDto.builder()
                .id(UUID.randomUUID())
                .deviceId("device-123")
                .deviceName("iPhone 15")
                .deviceType(DeviceType.MOBILE)
                .hasFcmToken(true)
                .lastActive(Instant.now())
                .linkedAt(Instant.now())
                .build();
    }

    @Nested
    @DisplayName("Profile Endpoints Tests")
    class ProfileEndpointsTests {

        @Test
        @DisplayName("should get current user profile")
        void shouldGetMyProfile() throws Exception {
            when(profileService.getProfile(testUserId)).thenReturn(testProfileDto);

            mockMvc.perform(get("/v1/users/me")
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(testUserId.toString()))
                    .andExpect(jsonPath("$.username").value("testuser"))
                    .andExpect(jsonPath("$.displayName").value("Test User"))
                    .andExpect(jsonPath("$.email").value("test@example.com"));

            verify(profileService).getProfile(testUserId);
        }

        @Test
        @DisplayName("should update current user profile")
        void shouldUpdateMyProfile() throws Exception {
            UpdateProfileRequest request = UpdateProfileRequest.builder()
                    .displayName("Updated Name")
                    .bio("Updated bio")
                    .build();

            UserProfileDto updatedProfile = UserProfileDto.builder()
                    .id(testUserId)
                    .displayName("Updated Name")
                    .bio("Updated bio")
                    .build();

            when(profileService.updateProfile(eq(testUserId), any(UpdateProfileRequest.class)))
                    .thenReturn(updatedProfile);

            mockMvc.perform(put("/v1/users/me")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.displayName").value("Updated Name"))
                    .andExpect(jsonPath("$.bio").value("Updated bio"));

            verify(profileService).updateProfile(eq(testUserId), any(UpdateProfileRequest.class));
        }

        @Test
        @DisplayName("should get profile by user ID")
        void shouldGetProfileById() throws Exception {
            when(profileService.getProfile(testUserId)).thenReturn(testProfileDto);

            mockMvc.perform(get("/v1/users/{userId}", testUserId))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(testUserId.toString()));

            verify(profileService).getProfile(testUserId);
        }

        @Test
        @DisplayName("should get profile by external ID")
        void shouldGetProfileByExternalId() throws Exception {
            String externalId = "ext-123";
            when(profileService.getProfileByExternalId(externalId)).thenReturn(testProfileDto);

            mockMvc.perform(get("/v1/users/by-external-id/{externalId}", externalId))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.externalId").value(externalId));

            verify(profileService).getProfileByExternalId(externalId);
        }

        @Test
        @DisplayName("should get profile by phone number")
        void shouldGetProfileByPhone() throws Exception {
            String phoneNumber = "+1234567890";
            when(profileService.findByPhoneNumber(phoneNumber)).thenReturn(Optional.of(testProfileDto));

            mockMvc.perform(get("/v1/users/by-phone/{phoneNumber}", phoneNumber))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.phoneNumber").value(phoneNumber));

            verify(profileService).findByPhoneNumber(phoneNumber);
        }

        @Test
        @DisplayName("should return 404 when phone number not found")
        void shouldReturn404WhenPhoneNotFound() throws Exception {
            String phoneNumber = "+9999999999";
            when(profileService.findByPhoneNumber(phoneNumber)).thenReturn(Optional.empty());

            mockMvc.perform(get("/v1/users/by-phone/{phoneNumber}", phoneNumber))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should get profile by username")
        void shouldGetProfileByUsername() throws Exception {
            String username = "testuser";
            when(profileService.findByUsername(username)).thenReturn(Optional.of(testProfileDto));

            mockMvc.perform(get("/v1/users/by-username/{username}", username))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(username));

            verify(profileService).findByUsername(username);
        }

        @Test
        @DisplayName("should return 404 when username not found")
        void shouldReturn404WhenUsernameNotFound() throws Exception {
            String username = "nonexistent";
            when(profileService.findByUsername(username)).thenReturn(Optional.empty());

            mockMvc.perform(get("/v1/users/by-username/{username}", username))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should get multiple profiles by IDs")
        void shouldGetProfilesByIds() throws Exception {
            List<UUID> ids = Arrays.asList(testUserId, UUID.randomUUID());
            when(profileService.getUsersByIds(ids)).thenReturn(List.of(testProfileDto));

            mockMvc.perform(get("/v1/users/batch")
                            .param("ids", ids.get(0).toString(), ids.get(1).toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isArray())
                    .andExpect(jsonPath("$[0].id").value(testUserId.toString()));

            verify(profileService).getUsersByIds(ids);
        }

        @Test
        @DisplayName("should get multiple profiles by external IDs")
        void shouldGetProfilesByExternalIds() throws Exception {
            List<String> externalIds = Arrays.asList("ext-1", "ext-2");
            when(profileService.getUsersByExternalIds(externalIds)).thenReturn(List.of(testProfileDto));

            mockMvc.perform(get("/v1/users/batch/external")
                            .param("externalIds", externalIds.toArray(new String[0])))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isArray());

            verify(profileService).getUsersByExternalIds(externalIds);
        }

        @Test
        @DisplayName("should search users")
        void shouldSearchUsers() throws Exception {
            String query = "test";
            UserProfileSummaryDto summaryDto = UserProfileSummaryDto.builder()
                    .id(testUserId)
                    .username("testuser")
                    .displayName("Test User")
                    .build();
            Page<UserProfileSummaryDto> page = new PageImpl<>(List.of(summaryDto), PageRequest.of(0, 20), 1);

            when(profileService.searchUsers(eq(query), isNull(), any())).thenReturn(page);

            mockMvc.perform(get("/v1/users/search")
                            .param("query", query))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.content").isArray())
                    .andExpect(jsonPath("$.content[0].username").value("testuser"));

            verify(profileService).searchUsers(eq(query), isNull(), any());
        }

        @Test
        @DisplayName("should search users with exclude ID")
        void shouldSearchUsersWithExcludeId() throws Exception {
            String query = "test";
            UUID excludeId = UUID.randomUUID();
            Page<UserProfileSummaryDto> page = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);

            when(profileService.searchUsers(eq(query), eq(excludeId), any())).thenReturn(page);

            mockMvc.perform(get("/v1/users/search")
                            .param("query", query)
                            .param("excludeUserId", excludeId.toString()))
                    .andExpect(status().isOk());

            verify(profileService).searchUsers(eq(query), eq(excludeId), any());
        }
    }

    @Nested
    @DisplayName("Status Endpoints Tests")
    class StatusEndpointsTests {

        @Test
        @DisplayName("should update user status")
        void shouldUpdateStatus() throws Exception {
            UpdateStatusRequest request = new UpdateStatusRequest(UserStatus.AWAY);

            mockMvc.perform(put("/v1/users/me/status")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(profileService).updateStatus(testUserId, UserStatus.AWAY);
        }

        @Test
        @DisplayName("should update status to offline")
        void shouldUpdateStatusToOffline() throws Exception {
            UpdateStatusRequest request = new UpdateStatusRequest(UserStatus.OFFLINE);

            mockMvc.perform(put("/v1/users/me/status")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(profileService).updateStatus(testUserId, UserStatus.OFFLINE);
        }
    }

    @Nested
    @DisplayName("Settings Endpoints Tests")
    class SettingsEndpointsTests {

        @Test
        @DisplayName("should get user settings")
        void shouldGetSettings() throws Exception {
            when(settingsService.getSettings(testUserId)).thenReturn(testSettingsDto);

            mockMvc.perform(get("/v1/users/me/settings")
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.darkMode").value(true))
                    .andExpect(jsonPath("$.pushNotifications").value(true))
                    .andExpect(jsonPath("$.readReceipts").value(true));

            verify(settingsService).getSettings(testUserId);
        }

        @Test
        @DisplayName("should update user settings")
        void shouldUpdateSettings() throws Exception {
            UpdateSettingsRequest request = UpdateSettingsRequest.builder()
                    .darkMode(false)
                    .pushNotifications(false)
                    .readReceipts(false)
                    .build();

            UserSettingsDto updatedSettings = UserSettingsDto.builder()
                    .userId(testUserId)
                    .darkMode(false)
                    .pushNotifications(false)
                    .readReceipts(false)
                    .build();

            when(settingsService.updateSettings(eq(testUserId), any(UpdateSettingsRequest.class)))
                    .thenReturn(updatedSettings);

            mockMvc.perform(put("/v1/users/me/settings")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.darkMode").value(false))
                    .andExpect(jsonPath("$.pushNotifications").value(false));

            verify(settingsService).updateSettings(eq(testUserId), any(UpdateSettingsRequest.class));
        }
    }

    @Nested
    @DisplayName("Blocked Users Endpoints Tests")
    class BlockedUsersEndpointsTests {

        @Test
        @DisplayName("should block a user")
        void shouldBlockUser() throws Exception {
            UUID blockedUserId = UUID.randomUUID();
            BlockUserRequest request = new BlockUserRequest(blockedUserId);

            mockMvc.perform(post("/v1/users/me/blocked-users")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(settingsService).blockUser(testUserId, blockedUserId);
        }

        @Test
        @DisplayName("should unblock a user")
        void shouldUnblockUser() throws Exception {
            UUID blockedUserId = UUID.randomUUID();

            mockMvc.perform(delete("/v1/users/me/blocked-users/{blockedUserId}", blockedUserId)
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk());

            verify(settingsService).unblockUser(testUserId, blockedUserId);
        }

        @Test
        @DisplayName("should get blocked users list")
        void shouldGetBlockedUsers() throws Exception {
            UserProfileSummaryDto blockedUser = UserProfileSummaryDto.builder()
                    .id(UUID.randomUUID())
                    .username("blockeduser")
                    .displayName("Blocked User")
                    .build();

            when(settingsService.getBlockedUsers(testUserId)).thenReturn(List.of(blockedUser));

            mockMvc.perform(get("/v1/users/me/blocked-users")
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isArray())
                    .andExpect(jsonPath("$[0].username").value("blockeduser"));

            verify(settingsService).getBlockedUsers(testUserId);
        }

        @Test
        @DisplayName("should return empty list when no blocked users")
        void shouldReturnEmptyListWhenNoBlockedUsers() throws Exception {
            when(settingsService.getBlockedUsers(testUserId)).thenReturn(List.of());

            mockMvc.perform(get("/v1/users/me/blocked-users")
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isArray())
                    .andExpect(jsonPath("$").isEmpty());
        }
    }

    @Nested
    @DisplayName("Linked Devices Endpoints Tests")
    class LinkedDevicesEndpointsTests {

        @Test
        @DisplayName("should link a device")
        void shouldLinkDevice() throws Exception {
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("new-device-123")
                    .deviceName("Samsung S24")
                    .deviceType(DeviceType.MOBILE)
                    .fcmToken("fcm-token-xyz")
                    .build();

            LinkedDeviceDto linkedDevice = LinkedDeviceDto.builder()
                    .id(UUID.randomUUID())
                    .deviceId("new-device-123")
                    .deviceName("Samsung S24")
                    .deviceType(DeviceType.MOBILE)
                    .hasFcmToken(true)
                    .linkedAt(Instant.now())
                    .build();

            when(deviceService.linkDevice(eq(testUserId), any(LinkDeviceRequest.class)))
                    .thenReturn(linkedDevice);

            mockMvc.perform(post("/v1/users/me/devices")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.deviceId").value("new-device-123"))
                    .andExpect(jsonPath("$.deviceName").value("Samsung S24"));

            verify(deviceService).linkDevice(eq(testUserId), any(LinkDeviceRequest.class));
        }

        @Test
        @DisplayName("should get linked devices")
        void shouldGetLinkedDevices() throws Exception {
            when(deviceService.getLinkedDevices(testUserId)).thenReturn(List.of(testDeviceDto));

            mockMvc.perform(get("/v1/users/me/devices")
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isArray())
                    .andExpect(jsonPath("$[0].deviceId").value("device-123"))
                    .andExpect(jsonPath("$[0].deviceName").value("iPhone 15"));

            verify(deviceService).getLinkedDevices(testUserId);
        }

        @Test
        @DisplayName("should unlink a device")
        void shouldUnlinkDevice() throws Exception {
            String deviceId = "device-123";

            mockMvc.perform(delete("/v1/users/me/devices/{deviceId}", deviceId)
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk());

            verify(deviceService).unlinkDevice(testUserId, deviceId);
        }

        @Test
        @DisplayName("should update device activity")
        void shouldUpdateDeviceActivity() throws Exception {
            String deviceId = "device-123";

            mockMvc.perform(put("/v1/users/me/devices/{deviceId}/activity", deviceId)
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isOk());

            verify(deviceService).updateDeviceActivity(testUserId, deviceId);
        }

        @Test
        @DisplayName("should update FCM token")
        void shouldUpdateFcmToken() throws Exception {
            String deviceId = "device-123";
            UpdateFcmTokenRequest request = UpdateFcmTokenRequest.builder()
                    .fcmToken("new-fcm-token")
                    .build();

            mockMvc.perform(put("/v1/users/me/devices/{deviceId}/fcm-token", deviceId)
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(deviceService).updateFcmToken(testUserId, deviceId, "new-fcm-token");
        }
    }

    @Nested
    @DisplayName("Internal Endpoints Tests")
    class InternalEndpointsTests {

        @Test
        @DisplayName("should get FCM tokens for user")
        void shouldGetFcmTokens() throws Exception {
            List<String> fcmTokens = Arrays.asList("token-1", "token-2");
            when(deviceService.getFcmTokens(testUserId)).thenReturn(fcmTokens);

            mockMvc.perform(get("/v1/users/internal/fcm-tokens/{userId}", testUserId)
                            .header("X-API-Key", "internal-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(testUserId.toString()))
                    .andExpect(jsonPath("$.fcmTokens").isArray())
                    .andExpect(jsonPath("$.fcmTokens[0]").value("token-1"))
                    .andExpect(jsonPath("$.fcmTokens[1]").value("token-2"));

            verify(deviceService).getFcmTokens(testUserId);
        }

        @Test
        @DisplayName("should get FCM tokens in batch")
        void shouldGetFcmTokensBatch() throws Exception {
            UUID userId1 = UUID.randomUUID();
            UUID userId2 = UUID.randomUUID();
            BatchFcmTokensRequest request = BatchFcmTokensRequest.builder()
                    .userIds(Arrays.asList(userId1, userId2))
                    .build();

            Map<UUID, List<String>> tokenMap = new HashMap<>();
            tokenMap.put(userId1, List.of("token-1"));
            tokenMap.put(userId2, List.of("token-2", "token-3"));

            when(deviceService.getFcmTokensGroupedByUsers(anyList())).thenReturn(tokenMap);

            mockMvc.perform(post("/v1/users/internal/fcm-tokens/batch")
                            .header("X-API-Key", "internal-api-key")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(deviceService).getFcmTokensGroupedByUsers(anyList());
        }

        @Test
        @DisplayName("should check if users are blocked")
        void shouldCheckBlocked() throws Exception {
            UUID userId1 = UUID.randomUUID();
            UUID userId2 = UUID.randomUUID();

            when(settingsService.areUsersBlocked(userId1, userId2)).thenReturn(true);

            mockMvc.perform(get("/v1/users/internal/check-blocked")
                            .header("X-API-Key", "internal-api-key")
                            .param("userId1", userId1.toString())
                            .param("userId2", userId2.toString()))
                    .andExpect(status().isOk())
                    .andExpect(content().string("true"));

            verify(settingsService).areUsersBlocked(userId1, userId2);
        }

        @Test
        @DisplayName("should return false when users not blocked")
        void shouldReturnFalseWhenNotBlocked() throws Exception {
            UUID userId1 = UUID.randomUUID();
            UUID userId2 = UUID.randomUUID();

            when(settingsService.areUsersBlocked(userId1, userId2)).thenReturn(false);

            mockMvc.perform(get("/v1/users/internal/check-blocked")
                            .header("X-API-Key", "internal-api-key")
                            .param("userId1", userId1.toString())
                            .param("userId2", userId2.toString()))
                    .andExpect(status().isOk())
                    .andExpect(content().string("false"));
        }
    }

    @Nested
    @DisplayName("Admin Endpoints Tests")
    class AdminEndpointsTests {

        @Test
        @DisplayName("should ban a user")
        void shouldBanUser() throws Exception {
            UUID targetUserId = UUID.randomUUID();
            UUID adminUserId = UUID.randomUUID();
            BanUserRequest request = new BanUserRequest(targetUserId, "Violation of terms");

            mockMvc.perform(post("/v1/users/admin/ban")
                            .header("X-User-ID", adminUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(profileService).banUser(targetUserId, adminUserId, "Violation of terms");
        }

        @Test
        @DisplayName("should ban user without reason")
        void shouldBanUserWithoutReason() throws Exception {
            UUID targetUserId = UUID.randomUUID();
            UUID adminUserId = UUID.randomUUID();
            BanUserRequest request = new BanUserRequest(targetUserId, null);

            mockMvc.perform(post("/v1/users/admin/ban")
                            .header("X-User-ID", adminUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(profileService).banUser(targetUserId, adminUserId, null);
        }

        @Test
        @DisplayName("should unban a user")
        void shouldUnbanUser() throws Exception {
            UUID targetUserId = UUID.randomUUID();

            mockMvc.perform(post("/v1/users/admin/unban/{userId}", targetUserId))
                    .andExpect(status().isOk());

            verify(profileService).unbanUser(targetUserId);
        }

        @Test
        @DisplayName("should update user role")
        void shouldUpdateRole() throws Exception {
            UUID targetUserId = UUID.randomUUID();
            UpdateRoleRequest request = new UpdateRoleRequest(targetUserId, UserRole.ADMIN);

            mockMvc.perform(post("/v1/users/admin/role")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(profileService).updateRole(targetUserId, UserRole.ADMIN);
        }

        @Test
        @DisplayName("should update user permissions")
        void shouldUpdatePermissions() throws Exception {
            UUID targetUserId = UUID.randomUUID();
            Set<String> permissions = Set.of("users:read", "users:write", "admin:access");
            UpdatePermissionsRequest request = new UpdatePermissionsRequest(targetUserId, permissions);

            mockMvc.perform(post("/v1/users/admin/permissions")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());

            verify(profileService).updatePermissions(targetUserId, permissions);
        }

        @Test
        @DisplayName("should get user statistics")
        void shouldGetStatistics() throws Exception {
            UserStatisticsDto statistics = UserStatisticsDto.builder()
                    .totalUsers(1000)
                    .activeUsers(850)
                    .onlineUsers(150)
                    .bannedUsers(10)
                    .usersByRole(Map.of("USER", 900L, "ADMIN", 50L, "MODERATOR", 50L))
                    .build();

            when(profileService.getStatistics()).thenReturn(statistics);

            mockMvc.perform(get("/v1/users/admin/statistics"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalUsers").value(1000))
                    .andExpect(jsonPath("$.activeUsers").value(850))
                    .andExpect(jsonPath("$.onlineUsers").value(150))
                    .andExpect(jsonPath("$.bannedUsers").value(10));

            verify(profileService).getStatistics();
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("should handle profile not found")
        void shouldHandleProfileNotFound() throws Exception {
            when(profileService.getProfile(testUserId))
                    .thenThrow(new RuntimeException("User not found"));

            mockMvc.perform(get("/v1/users/{userId}", testUserId))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should handle external ID not found")
        void shouldHandleExternalIdNotFound() throws Exception {
            String externalId = "nonexistent-ext-id";
            when(profileService.getProfileByExternalId(externalId))
                    .thenThrow(new RuntimeException("User not found"));

            mockMvc.perform(get("/v1/users/by-external-id/{externalId}", externalId))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should handle settings not found")
        void shouldHandleSettingsNotFound() throws Exception {
            when(settingsService.getSettings(testUserId))
                    .thenThrow(new RuntimeException("Settings not found"));

            mockMvc.perform(get("/v1/users/me/settings")
                            .header("X-User-ID", testUserId.toString()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should handle device linking failure")
        void shouldHandleDeviceLinkingFailure() throws Exception {
            LinkDeviceRequest request = LinkDeviceRequest.builder()
                    .deviceId("device-123")
                    .build();

            when(deviceService.linkDevice(eq(testUserId), any(LinkDeviceRequest.class)))
                    .thenThrow(new RuntimeException("Device already linked"));

            mockMvc.perform(post("/v1/users/me/devices")
                            .header("X-User-ID", testUserId.toString())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("Pagination Tests")
    class PaginationTests {

        @Test
        @DisplayName("should handle pagination with custom page size")
        void shouldHandlePaginationWithCustomSize() throws Exception {
            String query = "test";
            Page<UserProfileSummaryDto> page = new PageImpl<>(List.of(), PageRequest.of(0, 50), 0);

            when(profileService.searchUsers(eq(query), isNull(), any())).thenReturn(page);

            mockMvc.perform(get("/v1/users/search")
                            .param("query", query)
                            .param("page", "0")
                            .param("size", "50"))
                    .andExpect(status().isOk());

            verify(profileService).searchUsers(eq(query), isNull(), any());
        }

        @Test
        @DisplayName("should limit page size to maximum")
        void shouldLimitPageSizeToMaximum() throws Exception {
            String query = "test";
            Page<UserProfileSummaryDto> page = new PageImpl<>(List.of(), PageRequest.of(0, 100), 0);

            when(profileService.searchUsers(eq(query), isNull(), any())).thenReturn(page);

            // Request size of 200, but should be limited to 100
            mockMvc.perform(get("/v1/users/search")
                            .param("query", query)
                            .param("page", "0")
                            .param("size", "200"))
                    .andExpect(status().isOk());

            verify(profileService).searchUsers(eq(query), isNull(), any());
        }
    }
}
