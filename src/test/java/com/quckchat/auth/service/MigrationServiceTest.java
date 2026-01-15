package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.UserProfileDtos.*;
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
 * Unit tests for MigrationService
 */
@ExtendWith(MockitoExtension.class)
class MigrationServiceTest {

    @Mock
    private UserProfileRepository profileRepository;

    @Mock
    private UserSettingsRepository settingsRepository;

    @Mock
    private LinkedDeviceRepository deviceRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    private MigrationService migrationService;

    private UUID testUserId;
    private UserProfile testProfile;
    private UserSettings testSettings;

    @BeforeEach
    void setUp() {
        migrationService = new MigrationService(profileRepository, settingsRepository, deviceRepository);

        testUserId = UUID.randomUUID();

        AuthUser authUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .oauthConnections(new HashSet<>())
                .build();

        testProfile = UserProfile.builder()
                .id(testUserId)
                .authUser(authUser)
                .username("testuser")
                .displayName("Test User")
                .phoneNumber("+1234567890")
                .build();

        testSettings = UserSettings.builder()
                .id(testUserId)
                .userProfile(testProfile)
                .darkMode(false)
                .pushNotifications(true)
                .blockedUserIds(new HashSet<>())
                .build();
    }

    @Nested
    @DisplayName("Import Users Batch Tests")
    class ImportUsersBatchTests {

        @Test
        @DisplayName("should import users batch successfully")
        void shouldImportUsersBatchSuccessfully() {
            MigratedUserRequest user1 = MigratedUserRequest.builder()
                    .externalId("ext-001")
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .phoneNumber("+1111111111")
                    .username("user1")
                    .displayName("User One")
                    .status("active")
                    .role("user")
                    .isActive(true)
                    .createdAt(Instant.now())
                    .build();

            MigratedUserRequest user2 = MigratedUserRequest.builder()
                    .externalId("ext-002")
                    .email("user2@example.com")
                    .passwordHash("hash2")
                    .phoneNumber("+2222222222")
                    .username("user2")
                    .displayName("User Two")
                    .status("active")
                    .role("user")
                    .isActive(true)
                    .createdAt(Instant.now())
                    .build();

            List<MigratedUserRequest> users = Arrays.asList(user1, user2);

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                user.setOauthConnections(new HashSet<>());
                return user;
            });
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));

            MigrationResult result = migrationService.importUsersBatch(users, authUserRepository);

            assertThat(result.getTotal()).isEqualTo(2);
            assertThat(result.getSuccessful()).isEqualTo(2);
            assertThat(result.getFailed()).isEqualTo(0);
            assertThat(result.getErrors()).isEmpty();

            verify(authUserRepository, times(2)).save(any(AuthUser.class));
            verify(profileRepository, times(2)).save(any(UserProfile.class));
            verify(settingsRepository, times(2)).save(any(UserSettings.class));
        }

        @Test
        @DisplayName("should handle failed user import")
        void shouldHandleFailedUserImport() {
            MigratedUserRequest user1 = MigratedUserRequest.builder()
                    .externalId("ext-001")
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .status("active")
                    .role("user")
                    .build();

            MigratedUserRequest user2 = MigratedUserRequest.builder()
                    .externalId("ext-002")
                    .email("user2@example.com")
                    .passwordHash("hash2")
                    .status("active")
                    .role("user")
                    .build();

            List<MigratedUserRequest> users = Arrays.asList(user1, user2);

            // First user succeeds, second fails
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(invocation -> {
                        AuthUser user = invocation.getArgument(0);
                        user.setId(UUID.randomUUID());
                        user.setOauthConnections(new HashSet<>());
                        return user;
                    })
                    .thenThrow(new RuntimeException("Database error"));
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));

            MigrationResult result = migrationService.importUsersBatch(users, authUserRepository);

            assertThat(result.getTotal()).isEqualTo(2);
            assertThat(result.getSuccessful()).isEqualTo(1);
            assertThat(result.getFailed()).isEqualTo(1);
            assertThat(result.getErrors()).hasSize(1);
            assertThat(result.getErrors().get(0).getExternalId()).isEqualTo("ext-002");
        }

        @Test
        @DisplayName("should import user with linked devices")
        void shouldImportUserWithLinkedDevices() {
            MigratedLinkedDevice device = MigratedLinkedDevice.builder()
                    .deviceId("device-001")
                    .deviceName("iPhone")
                    .deviceType("MOBILE")
                    .fcmToken("fcm-token-001")
                    .lastActive(Instant.now())
                    .linkedAt(Instant.now())
                    .build();

            MigratedUserRequest user = MigratedUserRequest.builder()
                    .externalId("ext-001")
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .phoneNumber("+1111111111")
                    .username("user1")
                    .displayName("User One")
                    .status("active")
                    .role("user")
                    .isActive(true)
                    .linkedDevices(Collections.singletonList(device))
                    .createdAt(Instant.now())
                    .build();

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser authUser = invocation.getArgument(0);
                authUser.setId(UUID.randomUUID());
                authUser.setOauthConnections(new HashSet<>());
                return authUser;
            });
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));
            when(deviceRepository.save(any(LinkedDevice.class))).thenAnswer(invocation -> {
                LinkedDevice linkedDevice = invocation.getArgument(0);
                linkedDevice.setId(UUID.randomUUID());
                return linkedDevice;
            });

            MigrationResult result = migrationService.importUsersBatch(Collections.singletonList(user), authUserRepository);

            assertThat(result.getSuccessful()).isEqualTo(1);
            verify(deviceRepository).save(any(LinkedDevice.class));
        }

        @Test
        @DisplayName("should import user with legacy FCM tokens")
        void shouldImportUserWithLegacyFcmTokens() {
            MigratedUserRequest user = MigratedUserRequest.builder()
                    .externalId("ext-001")
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .phoneNumber("+1111111111")
                    .username("user1")
                    .displayName("User One")
                    .status("active")
                    .role("user")
                    .isActive(true)
                    .legacyFcmTokens(Arrays.asList("legacy-token-1", "legacy-token-2"))
                    .createdAt(Instant.now())
                    .build();

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser authUser = invocation.getArgument(0);
                authUser.setId(UUID.randomUUID());
                authUser.setOauthConnections(new HashSet<>());
                return authUser;
            });
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));
            when(deviceRepository.save(any(LinkedDevice.class))).thenAnswer(invocation -> {
                LinkedDevice linkedDevice = invocation.getArgument(0);
                linkedDevice.setId(UUID.randomUUID());
                return linkedDevice;
            });

            MigrationResult result = migrationService.importUsersBatch(Collections.singletonList(user), authUserRepository);

            assertThat(result.getSuccessful()).isEqualTo(1);
            verify(deviceRepository, times(2)).save(any(LinkedDevice.class));
        }

        @Test
        @DisplayName("should import user with OAuth providers")
        void shouldImportUserWithOAuthProviders() {
            MigratedOAuthProvider oauth = MigratedOAuthProvider.builder()
                    .provider("GOOGLE")
                    .providerId("google-123")
                    .email("user@gmail.com")
                    .linkedAt(Instant.now())
                    .build();

            MigratedUserRequest user = MigratedUserRequest.builder()
                    .externalId("ext-001")
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .phoneNumber("+1111111111")
                    .username("user1")
                    .displayName("User One")
                    .status("active")
                    .role("user")
                    .isActive(true)
                    .oauthProviders(Collections.singletonList(oauth))
                    .createdAt(Instant.now())
                    .build();

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser authUser = invocation.getArgument(0);
                authUser.setId(UUID.randomUUID());
                if (authUser.getOauthConnections() == null) {
                    authUser.setOauthConnections(new HashSet<>());
                }
                return authUser;
            });
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));

            MigrationResult result = migrationService.importUsersBatch(Collections.singletonList(user), authUserRepository);

            assertThat(result.getSuccessful()).isEqualTo(1);
            // AuthUserRepository.save is called twice: once for initial save, once for OAuth connections
            verify(authUserRepository, times(2)).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should import user with 2FA enabled")
        void shouldImportUserWith2FAEnabled() {
            Set<String> backupCodes = new HashSet<>(Arrays.asList("code1", "code2", "code3"));
            MigratedUserRequest user = MigratedUserRequest.builder()
                    .externalId("ext-001")
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .phoneNumber("+1111111111")
                    .username("user1")
                    .displayName("User One")
                    .status("active")
                    .role("user")
                    .isActive(true)
                    .twoFactorEnabled(true)
                    .twoFactorSecret("JBSWY3DPEHPK3PXP")
                    .backupCodes(backupCodes)
                    .createdAt(Instant.now())
                    .build();

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser authUser = invocation.getArgument(0);
                authUser.setId(UUID.randomUUID());
                authUser.setOauthConnections(new HashSet<>());
                return authUser;
            });
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));

            MigrationResult result = migrationService.importUsersBatch(Collections.singletonList(user), authUserRepository);

            assertThat(result.getSuccessful()).isEqualTo(1);

            ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(captor.capture());
            assertThat(captor.getValue().isTwoFactorEnabled()).isTrue();
            assertThat(captor.getValue().getTwoFactorSecret()).isEqualTo("JBSWY3DPEHPK3PXP");
            assertThat(captor.getValue().getBackupCodes()).containsExactlyInAnyOrder("code1", "code2", "code3");
        }
    }

    @Nested
    @DisplayName("Import Settings Batch Tests")
    class ImportSettingsBatchTests {

        @Test
        @DisplayName("should import settings batch successfully")
        void shouldImportSettingsBatchSuccessfully() {
            MigratedSettingsRequest settings1 = MigratedSettingsRequest.builder()
                    .externalId("ext-001")
                    .darkMode(true)
                    .pushNotifications(false)
                    .readReceipts(false)
                    .profilePhotoVisibility("CONTACTS")
                    .statusVisibility("NOBODY")
                    .build();

            when(profileRepository.findByExternalId("ext-001")).thenReturn(Optional.of(testProfile));
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));
            when(settingsRepository.save(any(UserSettings.class))).thenReturn(testSettings);

            MigrationResult result = migrationService.importSettingsBatch(Collections.singletonList(settings1));

            assertThat(result.getTotal()).isEqualTo(1);
            assertThat(result.getSuccessful()).isEqualTo(1);
            assertThat(result.getFailed()).isEqualTo(0);

            assertThat(testSettings.isDarkMode()).isTrue();
            assertThat(testSettings.isPushNotifications()).isFalse();
            assertThat(testSettings.isReadReceipts()).isFalse();
            verify(settingsRepository).save(testSettings);
        }

        @Test
        @DisplayName("should handle failed settings import")
        void shouldHandleFailedSettingsImport() {
            MigratedSettingsRequest settings1 = MigratedSettingsRequest.builder()
                    .externalId("ext-nonexistent")
                    .darkMode(true)
                    .profilePhotoVisibility("EVERYONE")
                    .statusVisibility("EVERYONE")
                    .build();

            when(profileRepository.findByExternalId("ext-nonexistent")).thenReturn(Optional.empty());

            MigrationResult result = migrationService.importSettingsBatch(Collections.singletonList(settings1));

            assertThat(result.getFailed()).isEqualTo(1);
            assertThat(result.getErrors()).hasSize(1);
            assertThat(result.getErrors().get(0).getExternalId()).isEqualTo("ext-nonexistent");
        }

        @Test
        @DisplayName("should import settings with blocked users")
        void shouldImportSettingsWithBlockedUsers() {
            UUID blockedUserId = UUID.randomUUID();
            UserProfile blockedProfile = UserProfile.builder()
                    .id(blockedUserId)
                    .username("blockeduser")
                    .build();

            MigratedSettingsRequest settings = MigratedSettingsRequest.builder()
                    .externalId("ext-001")
                    .darkMode(false)
                    .profilePhotoVisibility("EVERYONE")
                    .statusVisibility("EVERYONE")
                    .blockedUserExternalIds(Collections.singletonList("ext-blocked"))
                    .build();

            when(profileRepository.findByExternalId("ext-001")).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByExternalId("ext-blocked")).thenReturn(Optional.of(blockedProfile));
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));
            when(settingsRepository.save(any(UserSettings.class))).thenReturn(testSettings);

            MigrationResult result = migrationService.importSettingsBatch(Collections.singletonList(settings));

            assertThat(result.getSuccessful()).isEqualTo(1);
            assertThat(testSettings.getBlockedUserIds()).contains(blockedUserId);
        }
    }

    @Nested
    @DisplayName("Validate Migration Tests")
    class ValidateMigrationTests {

        @Test
        @DisplayName("should validate migration with all users found")
        void shouldValidateMigrationWithAllUsersFound() {
            List<String> sampleIds = Arrays.asList("ext-001", "ext-002", "ext-003");

            when(profileRepository.findByExternalId("ext-001")).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByExternalId("ext-002")).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByExternalId("ext-003")).thenReturn(Optional.of(testProfile));

            Map<String, Object> result = migrationService.validateMigration(sampleIds);

            assertThat(result.get("totalChecked")).isEqualTo(3);
            assertThat(result.get("found")).isEqualTo(3);
            assertThat(result.get("notFound")).isEqualTo(0);
            assertThat(result.get("successRate")).isEqualTo(100.0);
            assertThat((List<?>) result.get("missingExternalIds")).isEmpty();
        }

        @Test
        @DisplayName("should validate migration with some users not found")
        void shouldValidateMigrationWithSomeUsersNotFound() {
            List<String> sampleIds = Arrays.asList("ext-001", "ext-002", "ext-missing");

            when(profileRepository.findByExternalId("ext-001")).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByExternalId("ext-002")).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByExternalId("ext-missing")).thenReturn(Optional.empty());

            Map<String, Object> result = migrationService.validateMigration(sampleIds);

            assertThat(result.get("totalChecked")).isEqualTo(3);
            assertThat(result.get("found")).isEqualTo(2);
            assertThat(result.get("notFound")).isEqualTo(1);
            assertThat((Double) result.get("successRate")).isCloseTo(66.67, within(0.1));
            assertThat(result.get("missingExternalIds")).asList().contains("ext-missing");
        }

        @Test
        @DisplayName("should handle empty sample list")
        void shouldHandleEmptySampleList() {
            Map<String, Object> result = migrationService.validateMigration(Collections.emptyList());

            assertThat(result.get("totalChecked")).isEqualTo(0);
            assertThat(result.get("successRate")).isEqualTo(100.0);
        }
    }

    @Nested
    @DisplayName("Get Migration Status Tests")
    class GetMigrationStatusTests {

        @Test
        @DisplayName("should return migration status")
        void shouldReturnMigrationStatus() {
            when(profileRepository.count()).thenReturn(1000L);
            when(settingsRepository.count()).thenReturn(1000L);
            when(deviceRepository.count()).thenReturn(2500L);

            Map<String, Object> status = migrationService.getMigrationStatus();

            assertThat(status.get("totalProfiles")).isEqualTo(1000L);
            assertThat(status.get("totalSettings")).isEqualTo(1000L);
            assertThat(status.get("totalDevices")).isEqualTo(2500L);
        }
    }
}
