package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.UserProfile;
import com.quckapp.auth.domain.entity.UserSettings;
import com.quckapp.auth.domain.entity.VisibilityLevel;
import com.quckapp.auth.domain.repository.UserProfileRepository;
import com.quckapp.auth.domain.repository.UserSettingsRepository;
import com.quckapp.auth.dto.UserProfileDtos.UpdateSettingsRequest;
import com.quckapp.auth.dto.UserProfileDtos.UserProfileSummaryDto;
import com.quckapp.auth.dto.UserProfileDtos.UserSettingsDto;
import com.quckapp.auth.kafka.UserEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserSettingsService
 */
@ExtendWith(MockitoExtension.class)
class UserSettingsServiceTest {

    @Mock
    private UserSettingsRepository settingsRepository;

    @Mock
    private UserProfileRepository profileRepository;

    @Mock
    private UserEventPublisher eventPublisher;

    private UserSettingsService userSettingsService;

    private UUID testUserId;
    private UserProfile testProfile;
    private UserSettings testSettings;

    @BeforeEach
    void setUp() {
        userSettingsService = new UserSettingsService(settingsRepository, profileRepository, eventPublisher);

        testUserId = UUID.randomUUID();
        testProfile = UserProfile.builder()
                .id(testUserId)
                .username("testuser")
                .displayName("Test User")
                .build();

        testSettings = UserSettings.builder()
                .id(testUserId)
                .userProfile(testProfile)
                .darkMode(false)
                .autoDownloadMedia(true)
                .pushNotifications(true)
                .readReceipts(true)
                .lastSeenVisible(true)
                .profilePhotoVisibility(VisibilityLevel.EVERYONE)
                .statusVisibility(VisibilityLevel.EVERYONE)
                .blockedUserIds(new HashSet<>())
                .build();
    }

    @Nested
    @DisplayName("Get Settings Tests")
    class GetSettingsTests {

        @Test
        @DisplayName("should return settings for user")
        void shouldReturnSettingsForUser() {
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));

            UserSettingsDto result = userSettingsService.getSettings(testUserId);

            assertThat(result).isNotNull();
            assertThat(result.getUserId()).isEqualTo(testUserId);
            assertThat(result.isDarkMode()).isFalse();
            assertThat(result.isPushNotifications()).isTrue();
        }

        @Test
        @DisplayName("should throw exception when settings not found")
        void shouldThrowWhenSettingsNotFound() {
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userSettingsService.getSettings(testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Settings not found");
        }
    }

    @Nested
    @DisplayName("Update Settings Tests")
    class UpdateSettingsTests {

        @Test
        @DisplayName("should update all settings successfully")
        void shouldUpdateAllSettings() {
            UpdateSettingsRequest request = UpdateSettingsRequest.builder()
                    .darkMode(true)
                    .autoDownloadMedia(false)
                    .saveToGallery(true)
                    .pushNotifications(false)
                    .messageNotifications(false)
                    .groupNotifications(false)
                    .callNotifications(false)
                    .soundEnabled(false)
                    .vibrationEnabled(false)
                    .showPreview(false)
                    .inAppNotifications(false)
                    .notificationLight(false)
                    .readReceipts(false)
                    .lastSeenVisible(false)
                    .profilePhotoVisibility(VisibilityLevel.CONTACTS)
                    .statusVisibility(VisibilityLevel.NOBODY)
                    .fingerprintLock(true)
                    .build();

            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));
            when(settingsRepository.save(any(UserSettings.class))).thenReturn(testSettings);

            UserSettingsDto result = userSettingsService.updateSettings(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(testSettings.isDarkMode()).isTrue();
            assertThat(testSettings.isAutoDownloadMedia()).isFalse();
            assertThat(testSettings.isPushNotifications()).isFalse();
            assertThat(testSettings.isReadReceipts()).isFalse();
            assertThat(testSettings.getProfilePhotoVisibility()).isEqualTo(VisibilityLevel.CONTACTS);
            assertThat(testSettings.getStatusVisibility()).isEqualTo(VisibilityLevel.NOBODY);

            verify(settingsRepository).save(testSettings);
            verify(eventPublisher).publishSettingsUpdated(testUserId);
        }

        @Test
        @DisplayName("should update only specified settings")
        void shouldUpdateOnlySpecifiedSettings() {
            UpdateSettingsRequest request = UpdateSettingsRequest.builder()
                    .darkMode(true)
                    .build();

            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));
            when(settingsRepository.save(any(UserSettings.class))).thenReturn(testSettings);

            userSettingsService.updateSettings(testUserId, request);

            assertThat(testSettings.isDarkMode()).isTrue();
            // Other settings should remain unchanged
            assertThat(testSettings.isPushNotifications()).isTrue();
            assertThat(testSettings.isReadReceipts()).isTrue();
        }

        @Test
        @DisplayName("should throw exception when settings not found for update")
        void shouldThrowWhenSettingsNotFoundForUpdate() {
            UpdateSettingsRequest request = UpdateSettingsRequest.builder()
                    .darkMode(true)
                    .build();

            when(settingsRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userSettingsService.updateSettings(testUserId, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Settings not found");

            verify(settingsRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Create Default Settings Tests")
    class CreateDefaultSettingsTests {

        @Test
        @DisplayName("should create default settings for user")
        void shouldCreateDefaultSettings() {
            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> {
                UserSettings settings = invocation.getArgument(0);
                return settings;
            });

            UserSettingsDto result = userSettingsService.createDefaultSettings(testUserId);

            assertThat(result).isNotNull();
            verify(settingsRepository).save(any(UserSettings.class));
        }

        @Test
        @DisplayName("should throw exception when profile not found")
        void shouldThrowWhenProfileNotFound() {
            when(profileRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userSettingsService.createDefaultSettings(testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Profile not found");

            verify(settingsRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Block User Tests")
    class BlockUserTests {

        @Test
        @DisplayName("should block user successfully")
        void shouldBlockUserSuccessfully() {
            UUID userToBlock = UUID.randomUUID();
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));

            userSettingsService.blockUser(testUserId, userToBlock);

            assertThat(testSettings.getBlockedUserIds()).contains(userToBlock);
            verify(settingsRepository).save(testSettings);
        }

        @Test
        @DisplayName("should throw exception when blocking yourself")
        void shouldThrowWhenBlockingYourself() {
            assertThatThrownBy(() -> userSettingsService.blockUser(testUserId, testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot block yourself");

            verify(settingsRepository, never()).save(any());
        }

        @Test
        @DisplayName("should throw exception when settings not found")
        void shouldThrowWhenSettingsNotFoundForBlock() {
            UUID userToBlock = UUID.randomUUID();
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userSettingsService.blockUser(testUserId, userToBlock))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Settings not found");
        }
    }

    @Nested
    @DisplayName("Unblock User Tests")
    class UnblockUserTests {

        @Test
        @DisplayName("should unblock user successfully")
        void shouldUnblockUserSuccessfully() {
            UUID userToUnblock = UUID.randomUUID();
            testSettings.getBlockedUserIds().add(userToUnblock);
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));

            userSettingsService.unblockUser(testUserId, userToUnblock);

            assertThat(testSettings.getBlockedUserIds()).doesNotContain(userToUnblock);
            verify(settingsRepository).save(testSettings);
        }

        @Test
        @DisplayName("should not fail when unblocking user not in blocked list")
        void shouldNotFailWhenUnblockingUserNotInBlockedList() {
            UUID userToUnblock = UUID.randomUUID();
            when(settingsRepository.findById(testUserId)).thenReturn(Optional.of(testSettings));

            assertThatNoException().isThrownBy(() ->
                    userSettingsService.unblockUser(testUserId, userToUnblock));

            verify(settingsRepository).save(testSettings);
        }
    }

    @Nested
    @DisplayName("Get Blocked Users Tests")
    class GetBlockedUsersTests {

        @Test
        @DisplayName("should return blocked user IDs")
        void shouldReturnBlockedUserIds() {
            UUID blockedUser1 = UUID.randomUUID();
            UUID blockedUser2 = UUID.randomUUID();
            Set<UUID> blockedIds = new HashSet<>(Arrays.asList(blockedUser1, blockedUser2));

            when(settingsRepository.findBlockedUserIds(testUserId)).thenReturn(blockedIds);

            Set<UUID> result = userSettingsService.getBlockedUserIds(testUserId);

            assertThat(result).containsExactlyInAnyOrder(blockedUser1, blockedUser2);
        }

        @Test
        @DisplayName("should return blocked users with profile info")
        void shouldReturnBlockedUsersWithProfileInfo() {
            UUID blockedUserId = UUID.randomUUID();
            Set<UUID> blockedIds = new HashSet<>(Collections.singletonList(blockedUserId));

            UserProfile blockedProfile = UserProfile.builder()
                    .id(blockedUserId)
                    .username("blockeduser")
                    .displayName("Blocked User")
                    .build();

            when(settingsRepository.findBlockedUserIds(testUserId)).thenReturn(blockedIds);
            when(profileRepository.findByIdIn(anyList())).thenReturn(Collections.singletonList(blockedProfile));

            List<UserProfileSummaryDto> result = userSettingsService.getBlockedUsers(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getUsername()).isEqualTo("blockeduser");
        }

        @Test
        @DisplayName("should return empty list when no blocked users")
        void shouldReturnEmptyListWhenNoBlockedUsers() {
            when(settingsRepository.findBlockedUserIds(testUserId)).thenReturn(null);

            List<UserProfileSummaryDto> result = userSettingsService.getBlockedUsers(testUserId);

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Is Blocked Tests")
    class IsBlockedTests {

        @Test
        @DisplayName("should return true when user is blocked")
        void shouldReturnTrueWhenUserIsBlocked() {
            UUID targetUserId = UUID.randomUUID();
            when(settingsRepository.isUserBlocked(testUserId, targetUserId)).thenReturn(true);

            boolean result = userSettingsService.isBlocked(testUserId, targetUserId);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false when user is not blocked")
        void shouldReturnFalseWhenUserIsNotBlocked() {
            UUID targetUserId = UUID.randomUUID();
            when(settingsRepository.isUserBlocked(testUserId, targetUserId)).thenReturn(false);

            boolean result = userSettingsService.isBlocked(testUserId, targetUserId);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should check if users are mutually blocked")
        void shouldCheckIfUsersAreMutuallyBlocked() {
            UUID userId2 = UUID.randomUUID();
            when(settingsRepository.areUsersBlocked(testUserId, userId2)).thenReturn(true);

            boolean result = userSettingsService.areUsersBlocked(testUserId, userId2);

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Privacy Query Tests")
    class PrivacyQueryTests {

        @Test
        @DisplayName("should return true when read receipts are enabled")
        void shouldReturnTrueWhenReadReceiptsEnabled() {
            when(settingsRepository.getReadReceiptsEnabled(testUserId)).thenReturn(true);

            boolean result = userSettingsService.areReadReceiptsEnabled(testUserId);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false when read receipts are disabled")
        void shouldReturnFalseWhenReadReceiptsDisabled() {
            when(settingsRepository.getReadReceiptsEnabled(testUserId)).thenReturn(false);

            boolean result = userSettingsService.areReadReceiptsEnabled(testUserId);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false when read receipts setting is null")
        void shouldReturnFalseWhenReadReceiptsSettingIsNull() {
            when(settingsRepository.getReadReceiptsEnabled(testUserId)).thenReturn(null);

            boolean result = userSettingsService.areReadReceiptsEnabled(testUserId);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return true when last seen is visible")
        void shouldReturnTrueWhenLastSeenIsVisible() {
            when(settingsRepository.getLastSeenVisible(testUserId)).thenReturn(true);

            boolean result = userSettingsService.isLastSeenVisible(testUserId);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false when last seen is not visible")
        void shouldReturnFalseWhenLastSeenIsNotVisible() {
            when(settingsRepository.getLastSeenVisible(testUserId)).thenReturn(false);

            boolean result = userSettingsService.isLastSeenVisible(testUserId);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false when last seen setting is null")
        void shouldReturnFalseWhenLastSeenSettingIsNull() {
            when(settingsRepository.getLastSeenVisible(testUserId)).thenReturn(null);

            boolean result = userSettingsService.isLastSeenVisible(testUserId);

            assertThat(result).isFalse();
        }
    }
}
