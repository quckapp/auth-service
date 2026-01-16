package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.UserProfileDtos.*;
import com.quckapp.auth.kafka.UserEventOperations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserProfileService
 */
@ExtendWith(MockitoExtension.class)
class UserProfileServiceTest {

    @Mock
    private UserProfileRepository profileRepository;

    @Mock
    private UserSettingsRepository settingsRepository;

    @Mock
    private LinkedDeviceRepository deviceRepository;

    @Mock
    private UserEventOperations eventPublisher;

    private UserProfileService userProfileService;

    private AuthUser testAuthUser;
    private UserProfile testProfile;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        userProfileService = new UserProfileService(
                profileRepository,
                settingsRepository,
                deviceRepository,
                eventPublisher
        );

        testUserId = UUID.randomUUID();
        testAuthUser = AuthUser.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .build();

        testProfile = UserProfile.builder()
                .id(testUserId)
                .authUser(testAuthUser)
                .phoneNumber("+1234567890")
                .username("testuser")
                .displayName("Test User")
                .email("test@example.com")
                .status(UserStatus.ONLINE)
                .lastSeen(Instant.now())
                .isActive(true)
                .isVerified(false)
                .role(UserRole.USER)
                .permissions(new HashSet<>())
                .isBanned(false)
                .build();
    }

    @Nested
    @DisplayName("Profile CRUD tests")
    class ProfileCrudTests {

        @Test
        @DisplayName("should create profile successfully")
        void shouldCreateProfileSuccessfully() {
            CreateProfileRequest request = CreateProfileRequest.builder()
                    .phoneNumber("+1234567890")
                    .username("newuser")
                    .displayName("New User")
                    .email("new@example.com")
                    .build();

            when(profileRepository.findByPhoneNumber(anyString())).thenReturn(Optional.empty());
            when(profileRepository.findByUsername(anyString())).thenReturn(Optional.empty());
            when(profileRepository.findByEmail(anyString())).thenReturn(Optional.empty());
            when(profileRepository.save(any(UserProfile.class))).thenAnswer(invocation -> {
                UserProfile profile = invocation.getArgument(0);
                profile.setId(UUID.randomUUID());
                return profile;
            });
            when(settingsRepository.save(any(UserSettings.class))).thenAnswer(invocation -> invocation.getArgument(0));

            UserProfileDto result = userProfileService.createProfile(testAuthUser, request);

            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo("newuser");
            assertThat(result.getDisplayName()).isEqualTo("New User");

            verify(profileRepository).save(any(UserProfile.class));
            verify(settingsRepository).save(any(UserSettings.class));
            verify(eventPublisher).publishProfileCreated(any(UserProfile.class));
        }

        @Test
        @DisplayName("should throw exception when phone number exists")
        void shouldThrowWhenPhoneExists() {
            CreateProfileRequest request = CreateProfileRequest.builder()
                    .phoneNumber("+1234567890")
                    .username("newuser")
                    .build();

            when(profileRepository.findByPhoneNumber("+1234567890")).thenReturn(Optional.of(testProfile));

            assertThatThrownBy(() -> userProfileService.createProfile(testAuthUser, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Phone number already exists");
        }

        @Test
        @DisplayName("should throw exception when username exists")
        void shouldThrowWhenUsernameExists() {
            CreateProfileRequest request = CreateProfileRequest.builder()
                    .phoneNumber("+9999999999")
                    .username("testuser")
                    .build();

            when(profileRepository.findByPhoneNumber(anyString())).thenReturn(Optional.empty());
            when(profileRepository.findByUsername("testuser")).thenReturn(Optional.of(testProfile));

            assertThatThrownBy(() -> userProfileService.createProfile(testAuthUser, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Username already exists");
        }

        @Test
        @DisplayName("should get profile by ID")
        void shouldGetProfileById() {
            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));

            UserProfileDto result = userProfileService.getProfile(testUserId);

            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo("testuser");
        }

        @Test
        @DisplayName("should throw when profile not found")
        void shouldThrowWhenProfileNotFound() {
            when(profileRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userProfileService.getProfile(testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Profile not found");
        }

        @Test
        @DisplayName("should get profile by external ID")
        void shouldGetProfileByExternalId() {
            when(profileRepository.findByExternalId("ext-123")).thenReturn(Optional.of(testProfile));

            UserProfileDto result = userProfileService.getProfileByExternalId("ext-123");

            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo("testuser");
        }

        @Test
        @DisplayName("should update profile successfully")
        void shouldUpdateProfileSuccessfully() {
            UpdateProfileRequest request = UpdateProfileRequest.builder()
                    .displayName("Updated Name")
                    .bio("New bio")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(profileRepository.save(any(UserProfile.class))).thenReturn(testProfile);

            UserProfileDto result = userProfileService.updateProfile(testUserId, request);

            assertThat(result).isNotNull();

            ArgumentCaptor<UserProfile> captor = ArgumentCaptor.forClass(UserProfile.class);
            verify(profileRepository).save(captor.capture());
            assertThat(captor.getValue().getDisplayName()).isEqualTo("Updated Name");
            assertThat(captor.getValue().getBio()).isEqualTo("New bio");

            verify(eventPublisher).publishProfileUpdated(any(UserProfile.class));
        }

        @Test
        @DisplayName("should update username if unique")
        void shouldUpdateUsernameIfUnique() {
            UpdateProfileRequest request = UpdateProfileRequest.builder()
                    .username("newusername")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByUsername("newusername")).thenReturn(Optional.empty());
            when(profileRepository.save(any(UserProfile.class))).thenReturn(testProfile);

            userProfileService.updateProfile(testUserId, request);

            ArgumentCaptor<UserProfile> captor = ArgumentCaptor.forClass(UserProfile.class);
            verify(profileRepository).save(captor.capture());
            assertThat(captor.getValue().getUsername()).isEqualTo("newusername");
        }

        @Test
        @DisplayName("should throw when updating to existing username")
        void shouldThrowWhenUpdatingToExistingUsername() {
            UserProfile otherProfile = UserProfile.builder()
                    .id(UUID.randomUUID())
                    .username("existinguser")
                    .build();

            UpdateProfileRequest request = UpdateProfileRequest.builder()
                    .username("existinguser")
                    .build();

            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(profileRepository.findByUsername("existinguser")).thenReturn(Optional.of(otherProfile));

            assertThatThrownBy(() -> userProfileService.updateProfile(testUserId, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Username already exists");
        }

        @Test
        @DisplayName("should delete profile successfully")
        void shouldDeleteProfileSuccessfully() {
            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));

            userProfileService.deleteProfile(testUserId);

            verify(eventPublisher).publishProfileDeleted(testProfile);
            verify(profileRepository).delete(testProfile);
        }
    }

    @Nested
    @DisplayName("Profile lookup tests")
    class ProfileLookupTests {

        @Test
        @DisplayName("should find by phone number")
        void shouldFindByPhoneNumber() {
            when(profileRepository.findByPhoneNumber("+1234567890")).thenReturn(Optional.of(testProfile));

            Optional<UserProfileDto> result = userProfileService.findByPhoneNumber("+1234567890");

            assertThat(result).isPresent();
            assertThat(result.get().getPhoneNumber()).isEqualTo("+1234567890");
        }

        @Test
        @DisplayName("should return empty when phone not found")
        void shouldReturnEmptyWhenPhoneNotFound() {
            when(profileRepository.findByPhoneNumber(anyString())).thenReturn(Optional.empty());

            Optional<UserProfileDto> result = userProfileService.findByPhoneNumber("+9999999999");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should find by username")
        void shouldFindByUsername() {
            when(profileRepository.findByUsername("testuser")).thenReturn(Optional.of(testProfile));

            Optional<UserProfileDto> result = userProfileService.findByUsername("testuser");

            assertThat(result).isPresent();
            assertThat(result.get().getUsername()).isEqualTo("testuser");
        }

        @Test
        @DisplayName("should find by email")
        void shouldFindByEmail() {
            when(profileRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testProfile));

            Optional<UserProfileDto> result = userProfileService.findByEmail("test@example.com");

            assertThat(result).isPresent();
            assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("should get users by IDs")
        void shouldGetUsersByIds() {
            List<UUID> ids = Arrays.asList(testUserId, UUID.randomUUID());
            when(profileRepository.findByIdIn(ids)).thenReturn(Collections.singletonList(testProfile));

            List<UserProfileDto> result = userProfileService.getUsersByIds(ids);

            assertThat(result).hasSize(1);
        }

        @Test
        @DisplayName("should get users by external IDs")
        void shouldGetUsersByExternalIds() {
            List<String> externalIds = Arrays.asList("ext-123", "ext-456");
            when(profileRepository.findByExternalIdIn(externalIds)).thenReturn(Collections.singletonList(testProfile));

            List<UserProfileDto> result = userProfileService.getUsersByExternalIds(externalIds);

            assertThat(result).hasSize(1);
        }

        @Test
        @DisplayName("should search users")
        void shouldSearchUsers() {
            Pageable pageable = PageRequest.of(0, 10);
            Page<UserProfile> page = new PageImpl<>(Collections.singletonList(testProfile));
            UUID excludeId = UUID.randomUUID();

            when(profileRepository.searchUsers("test", excludeId, pageable)).thenReturn(page);

            Page<UserProfileSummaryDto> result = userProfileService.searchUsers("test", excludeId, pageable);

            assertThat(result.getContent()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Status management tests")
    class StatusManagementTests {

        @Test
        @DisplayName("should update status successfully")
        void shouldUpdateStatusSuccessfully() {
            when(profileRepository.updateStatus(eq(testUserId), eq(UserStatus.ONLINE), any(Instant.class)))
                    .thenReturn(1);

            userProfileService.updateStatus(testUserId, UserStatus.ONLINE);

            verify(profileRepository).updateStatus(eq(testUserId), eq(UserStatus.ONLINE), any(Instant.class));
            verify(eventPublisher).publishStatusChanged(testUserId, UserStatus.ONLINE);
        }

        @Test
        @DisplayName("should throw when updating status for non-existent user")
        void shouldThrowWhenUpdatingNonExistentUser() {
            when(profileRepository.updateStatus(eq(testUserId), any(), any(Instant.class))).thenReturn(0);

            assertThatThrownBy(() -> userProfileService.updateStatus(testUserId, UserStatus.ONLINE))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Profile not found");
        }

        @Test
        @DisplayName("should update last seen")
        void shouldUpdateLastSeen() {
            userProfileService.updateLastSeen(testUserId);

            verify(profileRepository).updateLastSeen(eq(testUserId), any(Instant.class));
        }
    }

    @Nested
    @DisplayName("Admin operations tests")
    class AdminOperationsTests {

        @Test
        @DisplayName("should ban user successfully")
        void shouldBanUserSuccessfully() {
            UUID bannedBy = UUID.randomUUID();
            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(profileRepository.save(any(UserProfile.class))).thenReturn(testProfile);

            userProfileService.banUser(testUserId, bannedBy, "Violation of terms");

            verify(profileRepository).save(any(UserProfile.class));
            verify(eventPublisher).publishUserBanned(testProfile, bannedBy, "Violation of terms");
        }

        @Test
        @DisplayName("should unban user successfully")
        void shouldUnbanUserSuccessfully() {
            when(profileRepository.unbanUser(testUserId)).thenReturn(1);

            userProfileService.unbanUser(testUserId);

            verify(profileRepository).unbanUser(testUserId);
            verify(eventPublisher).publishUserUnbanned(testUserId);
        }

        @Test
        @DisplayName("should throw when unbanning non-existent user")
        void shouldThrowWhenUnbanningNonExistent() {
            when(profileRepository.unbanUser(testUserId)).thenReturn(0);

            assertThatThrownBy(() -> userProfileService.unbanUser(testUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Profile not found");
        }

        @Test
        @DisplayName("should update role successfully")
        void shouldUpdateRoleSuccessfully() {
            when(profileRepository.updateRole(testUserId, UserRole.ADMIN)).thenReturn(1);

            userProfileService.updateRole(testUserId, UserRole.ADMIN);

            verify(profileRepository).updateRole(testUserId, UserRole.ADMIN);
            verify(eventPublisher).publishRoleChanged(testUserId, UserRole.ADMIN);
        }

        @Test
        @DisplayName("should throw when updating role for non-existent user")
        void shouldThrowWhenUpdatingRoleNonExistent() {
            when(profileRepository.updateRole(testUserId, UserRole.ADMIN)).thenReturn(0);

            assertThatThrownBy(() -> userProfileService.updateRole(testUserId, UserRole.ADMIN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Profile not found");
        }

        @Test
        @DisplayName("should update permissions successfully")
        void shouldUpdatePermissionsSuccessfully() {
            Set<String> permissions = new HashSet<>(Arrays.asList("READ", "WRITE"));
            when(profileRepository.findById(testUserId)).thenReturn(Optional.of(testProfile));
            when(profileRepository.save(any(UserProfile.class))).thenReturn(testProfile);

            userProfileService.updatePermissions(testUserId, permissions);

            ArgumentCaptor<UserProfile> captor = ArgumentCaptor.forClass(UserProfile.class);
            verify(profileRepository).save(captor.capture());
            assertThat(captor.getValue().getPermissions()).containsExactlyInAnyOrder("READ", "WRITE");
        }

        @Test
        @DisplayName("should verify user successfully")
        void shouldVerifyUserSuccessfully() {
            userProfileService.verifyUser(testUserId);

            verify(profileRepository).updateVerificationStatus(testUserId, true);
        }
    }

    @Nested
    @DisplayName("Statistics tests")
    class StatisticsTests {

        @Test
        @DisplayName("should get statistics")
        void shouldGetStatistics() {
            when(profileRepository.count()).thenReturn(100L);
            when(profileRepository.countActiveUsers()).thenReturn(80L);
            when(profileRepository.countOnlineUsers()).thenReturn(20L);
            when(profileRepository.countBannedUsers()).thenReturn(5L);
            when(profileRepository.countByRole()).thenReturn(Arrays.asList(
                    new Object[]{UserRole.USER, 90L},
                    new Object[]{UserRole.ADMIN, 10L}
            ));

            UserStatisticsDto result = userProfileService.getStatistics();

            assertThat(result.getTotalUsers()).isEqualTo(100);
            assertThat(result.getActiveUsers()).isEqualTo(80);
            assertThat(result.getOnlineUsers()).isEqualTo(20);
            assertThat(result.getBannedUsers()).isEqualTo(5);
            assertThat(result.getUsersByRole()).containsEntry("USER", 90L);
            assertThat(result.getUsersByRole()).containsEntry("ADMIN", 10L);
        }
    }
}
