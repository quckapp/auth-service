package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for UserProfile entity
 */
@DisplayName("UserProfile Entity Tests")
class UserProfileTest {

    private UserProfile userProfile;

    @BeforeEach
    void setUp() {
        Set<String> permissions = new HashSet<>();
        permissions.add("read.messages");
        permissions.add("write.messages");

        userProfile = UserProfile.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .displayName("Test User")
                .email("test@example.com")
                .role(UserRole.USER)
                .permissions(permissions)
                .isActive(true)
                .isBanned(false)
                .status(UserStatus.OFFLINE)
                .build();
    }

    @Nested
    @DisplayName("hasPermission() Tests")
    class HasPermissionTests {

        @Test
        @DisplayName("should return true when user has the permission")
        void shouldReturnTrueWhenUserHasPermission() {
            assertThat(userProfile.hasPermission("read.messages")).isTrue();
            assertThat(userProfile.hasPermission("write.messages")).isTrue();
        }

        @Test
        @DisplayName("should return false when user does not have the permission")
        void shouldReturnFalseWhenUserDoesNotHavePermission() {
            assertThat(userProfile.hasPermission("delete.messages")).isFalse();
            assertThat(userProfile.hasPermission("admin.access")).isFalse();
        }

        @Test
        @DisplayName("should return false when permissions set is null")
        void shouldReturnFalseWhenPermissionsNull() {
            userProfile.setPermissions(null);

            assertThat(userProfile.hasPermission("read.messages")).isFalse();
        }

        @Test
        @DisplayName("should return false when permissions set is empty")
        void shouldReturnFalseWhenPermissionsEmpty() {
            userProfile.setPermissions(new HashSet<>());

            assertThat(userProfile.hasPermission("read.messages")).isFalse();
        }
    }

    @Nested
    @DisplayName("hasAdminAccess() Tests")
    class HasAdminAccessTests {

        @Test
        @DisplayName("should return true when role is ADMIN")
        void shouldReturnTrueWhenRoleIsAdmin() {
            userProfile.setRole(UserRole.ADMIN);

            assertThat(userProfile.hasAdminAccess()).isTrue();
        }

        @Test
        @DisplayName("should return true when role is SUPER_ADMIN")
        void shouldReturnTrueWhenRoleIsSuperAdmin() {
            userProfile.setRole(UserRole.SUPER_ADMIN);

            assertThat(userProfile.hasAdminAccess()).isTrue();
        }

        @Test
        @DisplayName("should return false when role is USER")
        void shouldReturnFalseWhenRoleIsUser() {
            userProfile.setRole(UserRole.USER);

            assertThat(userProfile.hasAdminAccess()).isFalse();
        }

        @Test
        @DisplayName("should return false when role is MODERATOR")
        void shouldReturnFalseWhenRoleIsModerator() {
            userProfile.setRole(UserRole.MODERATOR);

            assertThat(userProfile.hasAdminAccess()).isFalse();
        }

        @Test
        @DisplayName("should return false when role is null")
        void shouldReturnFalseWhenRoleIsNull() {
            userProfile.setRole(null);

            assertThat(userProfile.hasAdminAccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("hasModeratorAccess() Tests")
    class HasModeratorAccessTests {

        @Test
        @DisplayName("should return true when role is MODERATOR")
        void shouldReturnTrueWhenRoleIsModerator() {
            userProfile.setRole(UserRole.MODERATOR);

            assertThat(userProfile.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("should return true when role is ADMIN")
        void shouldReturnTrueWhenRoleIsAdmin() {
            userProfile.setRole(UserRole.ADMIN);

            assertThat(userProfile.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("should return true when role is SUPER_ADMIN")
        void shouldReturnTrueWhenRoleIsSuperAdmin() {
            userProfile.setRole(UserRole.SUPER_ADMIN);

            assertThat(userProfile.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("should return false when role is USER")
        void shouldReturnFalseWhenRoleIsUser() {
            userProfile.setRole(UserRole.USER);

            assertThat(userProfile.hasModeratorAccess()).isFalse();
        }

        @Test
        @DisplayName("should return false when role is null")
        void shouldReturnFalseWhenRoleIsNull() {
            userProfile.setRole(null);

            assertThat(userProfile.hasModeratorAccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("ban() Tests")
    class BanTests {

        @Test
        @DisplayName("should set isBanned to true")
        void shouldSetIsBannedToTrue() {
            UUID adminId = UUID.randomUUID();
            userProfile.ban(adminId, "Violation of terms");

            assertThat(userProfile.isBanned()).isTrue();
        }

        @Test
        @DisplayName("should set ban reason")
        void shouldSetBanReason() {
            UUID adminId = UUID.randomUUID();
            userProfile.ban(adminId, "Spam behavior");

            assertThat(userProfile.getBanReason()).isEqualTo("Spam behavior");
        }

        @Test
        @DisplayName("should set bannedBy user ID")
        void shouldSetBannedByUserId() {
            UUID adminId = UUID.randomUUID();
            userProfile.ban(adminId, "Violation");

            assertThat(userProfile.getBannedBy()).isEqualTo(adminId);
        }

        @Test
        @DisplayName("should set bannedAt timestamp")
        void shouldSetBannedAtTimestamp() {
            UUID adminId = UUID.randomUUID();
            Instant before = Instant.now();

            userProfile.ban(adminId, "Violation");

            assertThat(userProfile.getBannedAt()).isNotNull();
            assertThat(userProfile.getBannedAt()).isAfterOrEqualTo(before);
        }
    }

    @Nested
    @DisplayName("unban() Tests")
    class UnbanTests {

        @Test
        @DisplayName("should set isBanned to false")
        void shouldSetIsBannedToFalse() {
            userProfile.setBanned(true);

            userProfile.unban();

            assertThat(userProfile.isBanned()).isFalse();
        }

        @Test
        @DisplayName("should clear ban reason")
        void shouldClearBanReason() {
            userProfile.setBanReason("Some reason");

            userProfile.unban();

            assertThat(userProfile.getBanReason()).isNull();
        }

        @Test
        @DisplayName("should clear bannedAt")
        void shouldClearBannedAt() {
            userProfile.setBannedAt(Instant.now());

            userProfile.unban();

            assertThat(userProfile.getBannedAt()).isNull();
        }

        @Test
        @DisplayName("should clear bannedBy")
        void shouldClearBannedBy() {
            userProfile.setBannedBy(UUID.randomUUID());

            userProfile.unban();

            assertThat(userProfile.getBannedBy()).isNull();
        }
    }

    @Nested
    @DisplayName("goOnline() Tests")
    class GoOnlineTests {

        @Test
        @DisplayName("should set status to ONLINE")
        void shouldSetStatusToOnline() {
            userProfile.setStatus(UserStatus.OFFLINE);

            userProfile.goOnline();

            assertThat(userProfile.getStatus()).isEqualTo(UserStatus.ONLINE);
        }

        @Test
        @DisplayName("should update lastSeen timestamp")
        void shouldUpdateLastSeenTimestamp() {
            Instant before = Instant.now();

            userProfile.goOnline();

            assertThat(userProfile.getLastSeen()).isNotNull();
            assertThat(userProfile.getLastSeen()).isAfterOrEqualTo(before);
        }
    }

    @Nested
    @DisplayName("goOffline() Tests")
    class GoOfflineTests {

        @Test
        @DisplayName("should set status to OFFLINE")
        void shouldSetStatusToOffline() {
            userProfile.setStatus(UserStatus.ONLINE);

            userProfile.goOffline();

            assertThat(userProfile.getStatus()).isEqualTo(UserStatus.OFFLINE);
        }

        @Test
        @DisplayName("should update lastSeen timestamp")
        void shouldUpdateLastSeenTimestamp() {
            Instant before = Instant.now();

            userProfile.goOffline();

            assertThat(userProfile.getLastSeen()).isNotNull();
            assertThat(userProfile.getLastSeen()).isAfterOrEqualTo(before);
        }
    }

    @Nested
    @DisplayName("updateLastSeen() Tests")
    class UpdateLastSeenTests {

        @Test
        @DisplayName("should update lastSeen timestamp")
        void shouldUpdateLastSeenTimestamp() {
            Instant before = Instant.now();

            userProfile.updateLastSeen();

            assertThat(userProfile.getLastSeen()).isNotNull();
            assertThat(userProfile.getLastSeen()).isAfterOrEqualTo(before);
        }

        @Test
        @DisplayName("should not change status")
        void shouldNotChangeStatus() {
            userProfile.setStatus(UserStatus.AWAY);

            userProfile.updateLastSeen();

            assertThat(userProfile.getStatus()).isEqualTo(UserStatus.AWAY);
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create profile with default values")
        void shouldCreateProfileWithDefaultValues() {
            UserProfile profile = UserProfile.builder()
                    .username("user")
                    .displayName("User")
                    .build();

            assertThat(profile.isPhoneVerified()).isFalse();
            assertThat(profile.getStatus()).isEqualTo(UserStatus.OFFLINE);
            assertThat(profile.isActive()).isTrue();
            assertThat(profile.isVerified()).isFalse();
            assertThat(profile.getRole()).isEqualTo(UserRole.USER);
            assertThat(profile.isBanned()).isFalse();
        }
    }
}
