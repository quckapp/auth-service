package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for UserRole enum
 */
@DisplayName("UserRole Enum Tests")
class UserRoleTest {

    @Nested
    @DisplayName("fromString() Tests")
    class FromStringTests {

        @Test
        @DisplayName("should return USER for valid USER string")
        void shouldReturnUserForValidUserString() {
            assertThat(UserRole.fromString("USER")).isEqualTo(UserRole.USER);
            assertThat(UserRole.fromString("user")).isEqualTo(UserRole.USER);
            assertThat(UserRole.fromString("User")).isEqualTo(UserRole.USER);
        }

        @Test
        @DisplayName("should return MODERATOR for valid MODERATOR string")
        void shouldReturnModeratorForValidModeratorString() {
            assertThat(UserRole.fromString("MODERATOR")).isEqualTo(UserRole.MODERATOR);
            assertThat(UserRole.fromString("moderator")).isEqualTo(UserRole.MODERATOR);
            assertThat(UserRole.fromString("Moderator")).isEqualTo(UserRole.MODERATOR);
        }

        @Test
        @DisplayName("should return ADMIN for valid ADMIN string")
        void shouldReturnAdminForValidAdminString() {
            assertThat(UserRole.fromString("ADMIN")).isEqualTo(UserRole.ADMIN);
            assertThat(UserRole.fromString("admin")).isEqualTo(UserRole.ADMIN);
            assertThat(UserRole.fromString("Admin")).isEqualTo(UserRole.ADMIN);
        }

        @Test
        @DisplayName("should return SUPER_ADMIN for valid SUPER_ADMIN string")
        void shouldReturnSuperAdminForValidSuperAdminString() {
            assertThat(UserRole.fromString("SUPER_ADMIN")).isEqualTo(UserRole.SUPER_ADMIN);
            assertThat(UserRole.fromString("super_admin")).isEqualTo(UserRole.SUPER_ADMIN);
            assertThat(UserRole.fromString("Super_Admin")).isEqualTo(UserRole.SUPER_ADMIN);
        }

        @Test
        @DisplayName("should return USER for null input")
        void shouldReturnUserForNullInput() {
            assertThat(UserRole.fromString(null)).isEqualTo(UserRole.USER);
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "INVALID", "admin123", "MOD", "SUPERADMIN", "unknown"})
        @DisplayName("should return USER for invalid input")
        void shouldReturnUserForInvalidInput(String input) {
            assertThat(UserRole.fromString(input)).isEqualTo(UserRole.USER);
        }
    }

    @Nested
    @DisplayName("hasAdminAccess() Tests")
    class HasAdminAccessTests {

        @Test
        @DisplayName("should return true for ADMIN role")
        void shouldReturnTrueForAdminRole() {
            assertThat(UserRole.ADMIN.hasAdminAccess()).isTrue();
        }

        @Test
        @DisplayName("should return true for SUPER_ADMIN role")
        void shouldReturnTrueForSuperAdminRole() {
            assertThat(UserRole.SUPER_ADMIN.hasAdminAccess()).isTrue();
        }

        @Test
        @DisplayName("should return false for USER role")
        void shouldReturnFalseForUserRole() {
            assertThat(UserRole.USER.hasAdminAccess()).isFalse();
        }

        @Test
        @DisplayName("should return false for MODERATOR role")
        void shouldReturnFalseForModeratorRole() {
            assertThat(UserRole.MODERATOR.hasAdminAccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("hasModeratorAccess() Tests")
    class HasModeratorAccessTests {

        @Test
        @DisplayName("should return true for MODERATOR role")
        void shouldReturnTrueForModeratorRole() {
            assertThat(UserRole.MODERATOR.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("should return true for ADMIN role")
        void shouldReturnTrueForAdminRole() {
            assertThat(UserRole.ADMIN.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("should return true for SUPER_ADMIN role")
        void shouldReturnTrueForSuperAdminRole() {
            assertThat(UserRole.SUPER_ADMIN.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("should return false for USER role")
        void shouldReturnFalseForUserRole() {
            assertThat(UserRole.USER.hasModeratorAccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("Enum Values Tests")
    class EnumValuesTests {

        @Test
        @DisplayName("should have all expected role values")
        void shouldHaveAllExpectedRoleValues() {
            UserRole[] roles = UserRole.values();

            assertThat(roles).hasSize(4);
            assertThat(roles).containsExactly(
                    UserRole.USER,
                    UserRole.MODERATOR,
                    UserRole.ADMIN,
                    UserRole.SUPER_ADMIN
            );
        }

        @Test
        @DisplayName("should have correct ordinal values")
        void shouldHaveCorrectOrdinalValues() {
            assertThat(UserRole.USER.ordinal()).isEqualTo(0);
            assertThat(UserRole.MODERATOR.ordinal()).isEqualTo(1);
            assertThat(UserRole.ADMIN.ordinal()).isEqualTo(2);
            assertThat(UserRole.SUPER_ADMIN.ordinal()).isEqualTo(3);
        }

        @Test
        @DisplayName("should convert to string correctly")
        void shouldConvertToStringCorrectly() {
            assertThat(UserRole.USER.name()).isEqualTo("USER");
            assertThat(UserRole.MODERATOR.name()).isEqualTo("MODERATOR");
            assertThat(UserRole.ADMIN.name()).isEqualTo("ADMIN");
            assertThat(UserRole.SUPER_ADMIN.name()).isEqualTo("SUPER_ADMIN");
        }

        @Test
        @DisplayName("should convert from string using valueOf")
        void shouldConvertFromStringUsingValueOf() {
            assertThat(UserRole.valueOf("USER")).isEqualTo(UserRole.USER);
            assertThat(UserRole.valueOf("MODERATOR")).isEqualTo(UserRole.MODERATOR);
            assertThat(UserRole.valueOf("ADMIN")).isEqualTo(UserRole.ADMIN);
            assertThat(UserRole.valueOf("SUPER_ADMIN")).isEqualTo(UserRole.SUPER_ADMIN);
        }
    }

    @Nested
    @DisplayName("Role Hierarchy Tests")
    class RoleHierarchyTests {

        @Test
        @DisplayName("SUPER_ADMIN should have both admin and moderator access")
        void superAdminShouldHaveBothAccess() {
            assertThat(UserRole.SUPER_ADMIN.hasAdminAccess()).isTrue();
            assertThat(UserRole.SUPER_ADMIN.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("ADMIN should have both admin and moderator access")
        void adminShouldHaveBothAccess() {
            assertThat(UserRole.ADMIN.hasAdminAccess()).isTrue();
            assertThat(UserRole.ADMIN.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("MODERATOR should have only moderator access")
        void moderatorShouldHaveOnlyModeratorAccess() {
            assertThat(UserRole.MODERATOR.hasAdminAccess()).isFalse();
            assertThat(UserRole.MODERATOR.hasModeratorAccess()).isTrue();
        }

        @Test
        @DisplayName("USER should have no elevated access")
        void userShouldHaveNoElevatedAccess() {
            assertThat(UserRole.USER.hasAdminAccess()).isFalse();
            assertThat(UserRole.USER.hasModeratorAccess()).isFalse();
        }
    }
}
