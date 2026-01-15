package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Permission entity
 */
@DisplayName("Permission Entity Tests")
class PermissionTest {

    private Permission permission;

    @BeforeEach
    void setUp() {
        permission = Permission.builder()
                .id(UUID.randomUUID())
                .name("read_messages")
                .description("Permission to read messages")
                .resource("messages")
                .action("read")
                .isActive(true)
                .build();
    }

    @Nested
    @DisplayName("getFullPermission() Tests")
    class GetFullPermissionTests {

        @Test
        @DisplayName("should return resource:action format")
        void shouldReturnResourceActionFormat() {
            permission.setResource("messages");
            permission.setAction("read");

            assertThat(permission.getFullPermission()).isEqualTo("messages:read");
        }

        @Test
        @DisplayName("should handle different resource and action combinations")
        void shouldHandleDifferentCombinations() {
            permission.setResource("users");
            permission.setAction("create");
            assertThat(permission.getFullPermission()).isEqualTo("users:create");

            permission.setResource("channels");
            permission.setAction("delete");
            assertThat(permission.getFullPermission()).isEqualTo("channels:delete");

            permission.setResource("workspace");
            permission.setAction("admin");
            assertThat(permission.getFullPermission()).isEqualTo("workspace:admin");
        }

        @Test
        @DisplayName("should handle resource with dots")
        void shouldHandleResourceWithDots() {
            permission.setResource("api.messages");
            permission.setAction("write");

            assertThat(permission.getFullPermission()).isEqualTo("api.messages:write");
        }

        @Test
        @DisplayName("should handle action with underscores")
        void shouldHandleActionWithUnderscores() {
            permission.setResource("files");
            permission.setAction("bulk_delete");

            assertThat(permission.getFullPermission()).isEqualTo("files:bulk_delete");
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create permission with default values")
        void shouldCreatePermissionWithDefaultValues() {
            Permission newPermission = Permission.builder()
                    .name("test_permission")
                    .resource("test")
                    .action("read")
                    .build();

            assertThat(newPermission.isActive()).isTrue();
            assertThat(newPermission.getRolePermissions()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("should create permission with all fields")
        void shouldCreatePermissionWithAllFields() {
            Permission newPermission = Permission.builder()
                    .id(UUID.randomUUID())
                    .name("full_permission")
                    .description("Full permission description")
                    .resource("admin")
                    .action("manage")
                    .isActive(false)
                    .build();

            assertThat(newPermission.getName()).isEqualTo("full_permission");
            assertThat(newPermission.getDescription()).isEqualTo("Full permission description");
            assertThat(newPermission.getResource()).isEqualTo("admin");
            assertThat(newPermission.getAction()).isEqualTo("manage");
            assertThat(newPermission.isActive()).isFalse();
        }
    }
}
