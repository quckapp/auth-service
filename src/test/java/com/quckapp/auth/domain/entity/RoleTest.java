package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Role entity
 */
@DisplayName("Role Entity Tests")
class RoleTest {

    private Role role;
    private Permission testPermission;

    @BeforeEach
    void setUp() {
        role = Role.builder()
                .id(UUID.randomUUID())
                .name("TEST_ROLE")
                .description("Test role description")
                .isSystemRole(false)
                .isActive(true)
                .priority(1)
                .rolePermissions(new HashSet<>())
                .userRoles(new HashSet<>())
                .build();

        testPermission = new Permission();
        testPermission.setId(UUID.randomUUID());
        testPermission.setName("test.permission");
        testPermission.setDescription("Test permission");
    }

    @Nested
    @DisplayName("addPermission() Tests")
    class AddPermissionTests {

        @Test
        @DisplayName("should add permission to role")
        void shouldAddPermissionToRole() {
            UUID grantedBy = UUID.randomUUID();

            role.addPermission(testPermission, grantedBy);

            assertThat(role.getRolePermissions()).hasSize(1);
            RolePermission addedPermission = role.getRolePermissions().iterator().next();
            assertThat(addedPermission.getPermission()).isEqualTo(testPermission);
            assertThat(addedPermission.getRole()).isEqualTo(role);
            assertThat(addedPermission.getGrantedBy()).isEqualTo(grantedBy);
        }

        @Test
        @DisplayName("should add multiple permissions to role")
        void shouldAddMultiplePermissionsToRole() {
            UUID grantedBy = UUID.randomUUID();

            Permission permission2 = new Permission();
            permission2.setId(UUID.randomUUID());
            permission2.setName("test.permission2");

            role.addPermission(testPermission, grantedBy);
            role.addPermission(permission2, grantedBy);

            assertThat(role.getRolePermissions()).hasSize(2);
        }
    }

    @Nested
    @DisplayName("removePermission() Tests")
    class RemovePermissionTests {

        @Test
        @DisplayName("should remove permission from role")
        void shouldRemovePermissionFromRole() {
            UUID grantedBy = UUID.randomUUID();
            role.addPermission(testPermission, grantedBy);
            assertThat(role.getRolePermissions()).hasSize(1);

            role.removePermission(testPermission);

            assertThat(role.getRolePermissions()).isEmpty();
        }

        @Test
        @DisplayName("should not throw when removing non-existent permission")
        void shouldNotThrowWhenRemovingNonExistentPermission() {
            Permission nonExistent = new Permission();
            nonExistent.setId(UUID.randomUUID());
            nonExistent.setName("non.existent");

            role.removePermission(nonExistent);

            assertThat(role.getRolePermissions()).isEmpty();
        }

        @Test
        @DisplayName("should only remove matching permission")
        void shouldOnlyRemoveMatchingPermission() {
            UUID grantedBy = UUID.randomUUID();
            Permission permission2 = new Permission();
            permission2.setId(UUID.randomUUID());
            permission2.setName("test.permission2");

            role.addPermission(testPermission, grantedBy);
            role.addPermission(permission2, grantedBy);
            assertThat(role.getRolePermissions()).hasSize(2);

            role.removePermission(testPermission);

            assertThat(role.getRolePermissions()).hasSize(1);
            assertThat(role.getRolePermissions().iterator().next().getPermission()).isEqualTo(permission2);
        }
    }

    @Nested
    @DisplayName("hasPermission() Tests")
    class HasPermissionTests {

        @Test
        @DisplayName("should return true when role has the permission")
        void shouldReturnTrueWhenRoleHasPermission() {
            UUID grantedBy = UUID.randomUUID();
            role.addPermission(testPermission, grantedBy);

            assertThat(role.hasPermission("test.permission")).isTrue();
        }

        @Test
        @DisplayName("should return false when role does not have the permission")
        void shouldReturnFalseWhenRoleDoesNotHavePermission() {
            assertThat(role.hasPermission("test.permission")).isFalse();
        }

        @Test
        @DisplayName("should return false for different permission name")
        void shouldReturnFalseForDifferentPermissionName() {
            UUID grantedBy = UUID.randomUUID();
            role.addPermission(testPermission, grantedBy);

            assertThat(role.hasPermission("other.permission")).isFalse();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create role with default values")
        void shouldCreateRoleWithDefaultValues() {
            Role defaultRole = Role.builder()
                    .name("DEFAULT")
                    .build();

            assertThat(defaultRole.isSystemRole()).isFalse();
            assertThat(defaultRole.isActive()).isTrue();
            assertThat(defaultRole.getPriority()).isEqualTo(0);
            assertThat(defaultRole.getRolePermissions()).isNotNull().isEmpty();
            assertThat(defaultRole.getUserRoles()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("should create system role")
        void shouldCreateSystemRole() {
            Role systemRole = Role.builder()
                    .name("SYSTEM_ADMIN")
                    .isSystemRole(true)
                    .priority(100)
                    .build();

            assertThat(systemRole.isSystemRole()).isTrue();
            assertThat(systemRole.getPriority()).isEqualTo(100);
        }

        @Test
        @DisplayName("should create inactive role")
        void shouldCreateInactiveRole() {
            Role inactiveRole = Role.builder()
                    .name("INACTIVE")
                    .isActive(false)
                    .build();

            assertThat(inactiveRole.isActive()).isFalse();
        }
    }
}
