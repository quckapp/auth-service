package com.quckapp.auth.integration.service;

import com.quckapp.auth.domain.entity.Permission;
import com.quckapp.auth.domain.entity.Role;
import com.quckapp.auth.domain.repository.PermissionRepository;
import com.quckapp.auth.domain.repository.RoleRepository;
import com.quckapp.auth.dto.RbacDtos.*;
import com.quckapp.auth.service.PermissionService;
import com.quckapp.auth.service.RoleService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for PermissionService.
 * Tests permission management operations using real MySQL database.
 */
@DisplayName("PermissionService Integration Tests")
class PermissionServiceIntegrationTest extends BaseServiceIntegrationTest {

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private RoleService roleService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EntityManager entityManager;

    private UUID adminUserId;

    @BeforeEach
    void setUp() {
        adminUserId = UUID.randomUUID();
    }

    @Nested
    @DisplayName("Permission CRUD Operations")
    class PermissionCrudOperations {

        @Test
        @DisplayName("Should create permission successfully")
        @Transactional
        void shouldCreatePermission() {
            // Given
            String permName = "test:create:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Test permission for creation")
                    .resource("test")
                    .action("create")
                    .build();

            // When
            PermissionDto created = permissionService.createPermission(request);

            // Then
            assertThat(created).isNotNull();
            assertThat(created.getId()).isNotNull();
            assertThat(created.getName()).isEqualTo(permName.toLowerCase());
            assertThat(created.getDescription()).isEqualTo("Test permission for creation");
            assertThat(created.getResource()).isEqualTo("test");
            assertThat(created.getAction()).isEqualTo("create");
            assertThat(created.isActive()).isTrue();

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should fail to create duplicate permission by name")
        @Transactional
        void shouldFailToCreateDuplicatePermissionByName() {
            // Given
            String permName = "dup:name:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Original permission")
                    .resource("dup")
                    .action("name")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When/Then
            CreatePermissionRequest duplicateRequest = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Duplicate permission")
                    .resource("dup")
                    .action("other")
                    .build();

            assertThatThrownBy(() -> permissionService.createPermission(duplicateRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission already exists");

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should fail to create duplicate permission by resource and action")
        @Transactional
        void shouldFailToCreateDuplicatePermissionByResourceAction() {
            // Given
            String permName = "dup:ra:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Original permission")
                    .resource("dupresource")
                    .action("dupaction")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When/Then
            CreatePermissionRequest duplicateRequest = CreatePermissionRequest.builder()
                    .name("different:name:" + System.currentTimeMillis())
                    .description("Different name same resource:action")
                    .resource("dupresource")
                    .action("dupaction")
                    .build();

            assertThatThrownBy(() -> permissionService.createPermission(duplicateRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("resource:action already exists");

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should get permission by ID")
        @Transactional
        void shouldGetPermissionById() {
            // Given
            String permName = "get:byid:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Get by ID test")
                    .resource("get")
                    .action("byid")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When
            PermissionDto retrieved = permissionService.getPermission(created.getId());

            // Then
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getId()).isEqualTo(created.getId());
            assertThat(retrieved.getName()).isEqualTo(permName.toLowerCase());

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should get permission by name")
        @Transactional
        void shouldGetPermissionByName() {
            // Given
            String permName = "get:byname:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Get by name test")
                    .resource("get")
                    .action("byname")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When
            Optional<PermissionDto> retrieved = permissionService.getPermissionByName(permName);

            // Then
            assertThat(retrieved).isPresent();
            assertThat(retrieved.get().getName()).isEqualTo(permName.toLowerCase());

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should get permission by resource and action")
        @Transactional
        void shouldGetPermissionByResourceAndAction() {
            // Given
            String permName = "get:byra:" + System.currentTimeMillis();
            String resource = "gettest" + System.currentTimeMillis();
            String action = "byra";
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Get by resource:action test")
                    .resource(resource)
                    .action(action)
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When
            Optional<PermissionDto> retrieved = permissionService.getPermissionByResourceAndAction(resource, action);

            // Then
            assertThat(retrieved).isPresent();
            assertThat(retrieved.get().getResource()).isEqualTo(resource.toLowerCase());
            assertThat(retrieved.get().getAction()).isEqualTo(action.toLowerCase());

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should get all permissions")
        void shouldGetAllPermissions() {
            // When
            List<PermissionDto> permissions = permissionService.getAllPermissions();

            // Then
            assertThat(permissions).isNotNull();
            // At minimum, there should be permissions from Flyway migrations or none
        }

        @Test
        @DisplayName("Should get active permissions only")
        @Transactional
        void shouldGetActivePermissionsOnly() {
            // Given - Create an active and inactive permission
            String activeName = "active:perm:" + System.currentTimeMillis();
            CreatePermissionRequest activeRequest = CreatePermissionRequest.builder()
                    .name(activeName)
                    .description("Active permission")
                    .resource("active")
                    .action("test")
                    .build();
            PermissionDto active = permissionService.createPermission(activeRequest);

            String inactiveName = "inactive:perm:" + System.currentTimeMillis();
            CreatePermissionRequest inactiveRequest = CreatePermissionRequest.builder()
                    .name(inactiveName)
                    .description("Inactive permission")
                    .resource("inactive")
                    .action("test")
                    .build();
            PermissionDto inactive = permissionService.createPermission(inactiveRequest);
            permissionService.deactivatePermission(inactive.getId());

            // When
            List<PermissionDto> activePerms = permissionService.getActivePermissions();

            // Then
            assertThat(activePerms).anyMatch(p -> p.getId().equals(active.getId()));
            assertThat(activePerms).noneMatch(p -> p.getId().equals(inactive.getId()));

            // Cleanup
            permissionRepository.deleteById(active.getId());
            permissionRepository.deleteById(inactive.getId());
        }

        @Test
        @DisplayName("Should get permissions by resource")
        @Transactional
        void shouldGetPermissionsByResource() {
            // Given
            String resource = "resourcetest" + System.currentTimeMillis();
            CreatePermissionRequest request1 = CreatePermissionRequest.builder()
                    .name(resource + ":read")
                    .description("Read permission")
                    .resource(resource)
                    .action("read")
                    .build();
            CreatePermissionRequest request2 = CreatePermissionRequest.builder()
                    .name(resource + ":write")
                    .description("Write permission")
                    .resource(resource)
                    .action("write")
                    .build();
            PermissionDto perm1 = permissionService.createPermission(request1);
            PermissionDto perm2 = permissionService.createPermission(request2);

            // When
            List<PermissionDto> perms = permissionService.getPermissionsByResource(resource);

            // Then
            assertThat(perms).hasSize(2);
            assertThat(perms).allMatch(p -> p.getResource().equals(resource.toLowerCase()));

            // Cleanup
            permissionRepository.deleteById(perm1.getId());
            permissionRepository.deleteById(perm2.getId());
        }

        @Test
        @DisplayName("Should update permission")
        @Transactional
        void shouldUpdatePermission() {
            // Given
            String permName = "update:perm:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Original description")
                    .resource("update")
                    .action("test")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When
            PermissionDto updated = permissionService.updatePermission(
                    created.getId(),
                    "Updated description",
                    null
            );

            // Then
            assertThat(updated.getDescription()).isEqualTo("Updated description");
            assertThat(updated.isActive()).isTrue();

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should deactivate permission")
        @Transactional
        void shouldDeactivatePermission() {
            // Given
            String permName = "deactivate:perm:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Permission to deactivate")
                    .resource("deactivate")
                    .action("test")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When
            permissionService.deactivatePermission(created.getId());

            // Then
            PermissionDto deactivated = permissionService.getPermission(created.getId());
            assertThat(deactivated.isActive()).isFalse();

            // Cleanup
            permissionRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should delete permission not assigned to any role")
        @Transactional
        void shouldDeleteUnassignedPermission() {
            // Given
            String permName = "delete:perm:" + System.currentTimeMillis();
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Permission to delete")
                    .resource("delete")
                    .action("test")
                    .build();
            PermissionDto created = permissionService.createPermission(request);

            // When
            permissionService.deletePermission(created.getId());

            // Then
            assertThat(permissionRepository.findById(created.getId())).isEmpty();
        }

        @Test
        @DisplayName("Should fail to delete permission assigned to role")
        @Transactional
        void shouldFailToDeleteAssignedPermission() {
            // Given - Create permission and assign to a role
            String permName = "nodelete:perm:" + System.currentTimeMillis();
            CreatePermissionRequest permRequest = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Permission assigned to role")
                    .resource("nodelete")
                    .action("test")
                    .build();
            PermissionDto perm = permissionService.createPermission(permRequest);

            String roleName = "NODELETE_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role with permission")
                    .priority(10)
                    .permissionIds(Set.of(perm.getId()))
                    .build();
            RoleDto role = roleService.createRole(roleRequest, adminUserId);

            // Flush and clear to ensure role-permission relationship is persisted and visible
            entityManager.flush();
            entityManager.clear();

            // Re-fetch the permission to get the updated entity with relationships
            Permission permEntity = permissionRepository.findById(perm.getId()).orElseThrow();

            // When/Then - Use the entity directly to check if it has rolePermissions
            assertThatThrownBy(() -> permissionService.deletePermission(perm.getId()))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot delete permission that is assigned to roles");

            // Cleanup
            roleRepository.deleteById(role.getId());
            permissionRepository.deleteById(perm.getId());
        }
    }

    @Nested
    @DisplayName("Bulk Operations")
    class BulkOperations {

        @Test
        @DisplayName("Should create multiple permissions in bulk")
        @Transactional
        void shouldCreateMultiplePermissions() {
            // Given
            long timestamp = System.currentTimeMillis();
            List<CreatePermissionRequest> requests = List.of(
                    CreatePermissionRequest.builder()
                            .name("bulk1:" + timestamp)
                            .description("First bulk permission")
                            .resource("bulk")
                            .action("action1")
                            .build(),
                    CreatePermissionRequest.builder()
                            .name("bulk2:" + timestamp)
                            .description("Second bulk permission")
                            .resource("bulk")
                            .action("action2")
                            .build(),
                    CreatePermissionRequest.builder()
                            .name("bulk3:" + timestamp)
                            .description("Third bulk permission")
                            .resource("bulk")
                            .action("action3")
                            .build()
            );

            // When
            List<PermissionDto> created = permissionService.createPermissions(requests);

            // Then
            assertThat(created).hasSize(3);
            assertThat(created).allMatch(p -> p.getId() != null);
            assertThat(created).allMatch(p -> p.getResource().equals("bulk"));

            // Cleanup
            created.forEach(p -> permissionRepository.deleteById(p.getId()));
        }
    }

    @Nested
    @DisplayName("Resource Discovery Operations")
    class ResourceDiscoveryOperations {

        @Test
        @DisplayName("Should get all unique resources")
        @Transactional
        void shouldGetAllUniqueResources() {
            // Given - Create permissions with different resources
            long timestamp = System.currentTimeMillis();
            String resource1 = "uniqueresource1_" + timestamp;
            String resource2 = "uniqueresource2_" + timestamp;

            PermissionDto perm1 = permissionService.createPermission(CreatePermissionRequest.builder()
                    .name(resource1 + ":action")
                    .description("Permission 1")
                    .resource(resource1)
                    .action("action")
                    .build());
            PermissionDto perm2 = permissionService.createPermission(CreatePermissionRequest.builder()
                    .name(resource2 + ":action")
                    .description("Permission 2")
                    .resource(resource2)
                    .action("action")
                    .build());

            // When
            List<String> resources = permissionService.getAllResources();

            // Then
            assertThat(resources).contains(resource1.toLowerCase(), resource2.toLowerCase());

            // Cleanup
            permissionRepository.deleteById(perm1.getId());
            permissionRepository.deleteById(perm2.getId());
        }
    }

    @Nested
    @DisplayName("Role-Permission Integration")
    class RolePermissionIntegration {

        @Test
        @DisplayName("Should get permissions by role ID")
        @Transactional
        void shouldGetPermissionsByRoleId() {
            // Given - Create permission and role with that permission
            String permName = "role:perm:" + System.currentTimeMillis();
            CreatePermissionRequest permRequest = CreatePermissionRequest.builder()
                    .name(permName)
                    .description("Permission for role")
                    .resource("roletest")
                    .action("read")
                    .build();
            PermissionDto perm = permissionService.createPermission(permRequest);

            String roleName = "PERM_TEST_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role with permission")
                    .priority(25)
                    .permissionIds(Set.of(perm.getId()))
                    .build();
            RoleDto role = roleService.createRole(roleRequest, adminUserId);

            // When
            List<PermissionDto> rolePerms = permissionService.getPermissionsByRoleId(role.getId());

            // Then
            assertThat(rolePerms).hasSize(1);
            assertThat(rolePerms.get(0).getId()).isEqualTo(perm.getId());
            assertThat(rolePerms.get(0).getName()).isEqualTo(permName.toLowerCase());

            // Cleanup
            roleRepository.deleteById(role.getId());
            permissionRepository.deleteById(perm.getId());
        }
    }
}
