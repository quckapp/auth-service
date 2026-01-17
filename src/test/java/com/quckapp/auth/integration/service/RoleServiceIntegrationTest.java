package com.quckapp.auth.integration.service;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.AuthUser.AuthStatus;
import com.quckapp.auth.domain.entity.Permission;
import com.quckapp.auth.domain.entity.Role;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.PermissionRepository;
import com.quckapp.auth.domain.repository.RoleRepository;
import com.quckapp.auth.domain.repository.UserRoleAssignmentRepository;
import com.quckapp.auth.dto.RbacDtos.*;
import com.quckapp.auth.service.PermissionService;
import com.quckapp.auth.service.RoleService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for RoleService.
 * Tests role management, permission assignment, and user role operations
 * using real MySQL database from docker-compose.
 */
@DisplayName("RoleService Integration Tests")
class RoleServiceIntegrationTest extends BaseServiceIntegrationTest {

    @Autowired
    private RoleService roleService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private UserRoleAssignmentRepository userRoleAssignmentRepository;

    @Autowired
    private EntityManager entityManager;

    private UUID adminUserId;
    private UUID testUserId;
    private Permission testPermission;

    @BeforeEach
    void setUp() {
        adminUserId = UUID.randomUUID();
    }

    @AfterEach
    void tearDown() {
        // Clean up test data
        if (testUserId != null) {
            userRoleAssignmentRepository.deactivateAllUserRoles(testUserId);
            authUserRepository.findById(testUserId).ifPresent(authUserRepository::delete);
        }
        if (testPermission != null) {
            permissionRepository.delete(testPermission);
        }
    }

    @Nested
    @DisplayName("Role CRUD Operations")
    class RoleCrudOperations {

        @Test
        @DisplayName("Should create custom role successfully")
        @Transactional
        void shouldCreateCustomRole() {
            // Given
            String roleName = "TEST_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Test role for integration testing")
                    .priority(50)
                    .build();

            // When
            RoleDto createdRole = roleService.createRole(request, adminUserId);

            // Then
            assertThat(createdRole).isNotNull();
            assertThat(createdRole.getId()).isNotNull();
            assertThat(createdRole.getName()).isEqualTo(roleName.toUpperCase());
            assertThat(createdRole.getDescription()).isEqualTo("Test role for integration testing");
            assertThat(createdRole.getPriority()).isEqualTo(50);
            assertThat(createdRole.isSystemRole()).isFalse();
            assertThat(createdRole.isActive()).isTrue();

            // Cleanup
            roleRepository.deleteById(createdRole.getId());
        }

        @Test
        @DisplayName("Should fail to create role with duplicate name")
        void shouldFailToCreateDuplicateRole() {
            // Given - ADMIN role exists from Flyway migration
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name("ADMIN")
                    .description("Duplicate admin")
                    .priority(100)
                    .build();

            // When/Then
            assertThatThrownBy(() -> roleService.createRole(request, adminUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Role already exists");
        }

        @Test
        @DisplayName("Should get role by ID")
        @Transactional
        void shouldGetRoleById() {
            // Given - Create a test role
            String roleName = "GET_TEST_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Test role")
                    .priority(25)
                    .build();
            RoleDto created = roleService.createRole(request, adminUserId);

            // When
            RoleDto retrieved = roleService.getRole(created.getId());

            // Then
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getId()).isEqualTo(created.getId());
            assertThat(retrieved.getName()).isEqualTo(roleName.toUpperCase());

            // Cleanup
            roleRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should get role by name")
        void shouldGetRoleByName() {
            // Given - ADMIN role from Flyway

            // When
            Optional<RoleDto> role = roleService.getRoleByName("ADMIN");

            // Then
            assertThat(role).isPresent();
            assertThat(role.get().getName()).isEqualTo("ADMIN");
        }

        @Test
        @DisplayName("Should get all roles")
        void shouldGetAllRoles() {
            // When
            List<RoleDto> roles = roleService.getAllRoles();

            // Then
            assertThat(roles).isNotEmpty();
            assertThat(roles).anyMatch(r -> r.getName().equals("ADMIN"));
            assertThat(roles).anyMatch(r -> r.getName().equals("USER"));
        }

        @Test
        @DisplayName("Should get active roles ordered by priority")
        void shouldGetActiveRolesOrderedByPriority() {
            // When
            List<RoleDto> roles = roleService.getActiveRoles();

            // Then
            assertThat(roles).isNotEmpty();
            assertThat(roles).allMatch(RoleDto::isActive);

            // Verify ordering
            for (int i = 0; i < roles.size() - 1; i++) {
                assertThat(roles.get(i).getPriority())
                        .isGreaterThanOrEqualTo(roles.get(i + 1).getPriority());
            }
        }

        @Test
        @DisplayName("Should update custom role")
        @Transactional
        void shouldUpdateCustomRole() {
            // Given - Create a custom role
            String roleName = "UPDATE_TEST_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest createRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Original description")
                    .priority(30)
                    .build();
            RoleDto created = roleService.createRole(createRequest, adminUserId);

            // When
            UpdateRoleRequest updateRequest = UpdateRoleRequest.builder()
                    .description("Updated description")
                    .priority(60)
                    .active(true)
                    .build();
            RoleDto updated = roleService.updateRole(created.getId(), updateRequest);

            // Then
            assertThat(updated.getDescription()).isEqualTo("Updated description");
            assertThat(updated.getPriority()).isEqualTo(60);

            // Cleanup
            roleRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should not allow modifying system role")
        void shouldNotAllowModifyingSystemRole() {
            // Given - ADMIN is a system role
            Role adminRole = roleRepository.findByName("ADMIN").orElseThrow();

            // When/Then
            UpdateRoleRequest updateRequest = UpdateRoleRequest.builder()
                    .description("Trying to modify system role")
                    .build();

            assertThatThrownBy(() -> roleService.updateRole(adminRole.getId(), updateRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot modify system role");
        }

        @Test
        @DisplayName("Should delete custom role without users")
        @Transactional
        void shouldDeleteCustomRoleWithoutUsers() {
            // Given - Create a custom role
            String roleName = "DELETE_TEST_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role to delete")
                    .priority(10)
                    .build();
            RoleDto created = roleService.createRole(request, adminUserId);

            // When
            roleService.deleteRole(created.getId());

            // Then
            assertThat(roleRepository.findById(created.getId())).isEmpty();
        }

        @Test
        @DisplayName("Should not delete system role")
        void shouldNotDeleteSystemRole() {
            // Given
            Role adminRole = roleRepository.findByName("ADMIN").orElseThrow();

            // When/Then
            assertThatThrownBy(() -> roleService.deleteRole(adminRole.getId()))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot delete system role");
        }
    }

    @Nested
    @DisplayName("Permission Assignment Operations")
    class PermissionAssignmentOperations {

        @Test
        @DisplayName("Should create role with permissions")
        @Transactional
        void shouldCreateRoleWithPermissions() {
            // Given - Create test permission
            testPermission = Permission.builder()
                    .name("test:permission:" + System.currentTimeMillis())
                    .description("Test permission")
                    .resource("test")
                    .action("read")
                    .isActive(true)
                    .build();
            testPermission = permissionRepository.save(testPermission);

            String roleName = "ROLE_WITH_PERMS_" + System.currentTimeMillis();
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role with permissions")
                    .priority(40)
                    .permissionIds(Set.of(testPermission.getId()))
                    .build();

            // When
            RoleDto created = roleService.createRole(request, adminUserId);

            // Then
            assertThat(created).isNotNull();
            assertThat(created.getId()).isNotNull();

            // Flush and clear to ensure fresh fetch from database
            entityManager.flush();
            entityManager.clear();

            // Verify permission was assigned
            RoleWithPermissionsDto roleWithPerms = roleService.getRoleWithPermissions(created.getId());
            assertThat(roleWithPerms.getPermissions()).hasSize(1);
            assertThat(roleWithPerms.getPermissions().get(0).getName()).isEqualTo(testPermission.getName());

            // Cleanup
            roleRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should assign permissions to existing role")
        @Transactional
        void shouldAssignPermissionsToExistingRole() {
            // Given - Create test role and permission
            String roleName = "ASSIGN_PERM_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role for permission assignment")
                    .priority(35)
                    .build();
            RoleDto created = roleService.createRole(roleRequest, adminUserId);

            testPermission = Permission.builder()
                    .name("assign:permission:" + System.currentTimeMillis())
                    .description("Permission to assign")
                    .resource("assign")
                    .action("write")
                    .isActive(true)
                    .build();
            testPermission = permissionRepository.save(testPermission);

            // When
            roleService.assignPermissionsToRole(created.getId(), Set.of(testPermission.getId()), adminUserId);

            // Flush and clear to ensure fresh fetch from database
            entityManager.flush();
            entityManager.clear();

            // Then
            RoleWithPermissionsDto roleWithPerms = roleService.getRoleWithPermissions(created.getId());
            assertThat(roleWithPerms.getPermissions()).hasSize(1);
            assertThat(roleWithPerms.getPermissions().get(0).getId()).isEqualTo(testPermission.getId());

            // Cleanup
            roleRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should remove permission from role")
        @Transactional
        void shouldRemovePermissionFromRole() {
            // Given - Create role with permission
            testPermission = Permission.builder()
                    .name("remove:permission:" + System.currentTimeMillis())
                    .description("Permission to remove")
                    .resource("remove")
                    .action("delete")
                    .isActive(true)
                    .build();
            testPermission = permissionRepository.save(testPermission);

            String roleName = "REMOVE_PERM_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role to remove permission from")
                    .priority(45)
                    .permissionIds(Set.of(testPermission.getId()))
                    .build();
            RoleDto created = roleService.createRole(request, adminUserId);

            // Flush to ensure permission is linked
            entityManager.flush();
            entityManager.clear();

            // When
            roleService.removePermissionFromRole(created.getId(), testPermission.getId());

            // Flush and clear again to verify removal
            entityManager.flush();
            entityManager.clear();

            // Then - After removing, the role should exist but have no permissions
            // Use permissionService to verify no permissions are linked to this role
            List<PermissionDto> rolePerms = permissionService.getPermissionsByRoleId(created.getId());
            assertThat(rolePerms).isEmpty();

            // Cleanup
            roleRepository.deleteById(created.getId());
        }

        @Test
        @DisplayName("Should set role permissions replacing all existing")
        @Transactional
        void shouldSetRolePermissionsReplacingExisting() {
            // Given - Create role with initial permission
            Permission perm1 = Permission.builder()
                    .name("set:perm1:" + System.currentTimeMillis())
                    .description("First permission")
                    .resource("set")
                    .action("create")
                    .isActive(true)
                    .build();
            perm1 = permissionRepository.save(perm1);

            Permission perm2 = Permission.builder()
                    .name("set:perm2:" + System.currentTimeMillis())
                    .description("Second permission")
                    .resource("set")
                    .action("update")
                    .isActive(true)
                    .build();
            perm2 = permissionRepository.save(perm2);

            String roleName = "SET_PERM_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role for set permissions")
                    .priority(55)
                    .permissionIds(Set.of(perm1.getId()))
                    .build();
            RoleDto created = roleService.createRole(request, adminUserId);

            // Flush to persist the initial permission assignment
            entityManager.flush();
            entityManager.clear();

            // When - Replace with different permission
            roleService.setRolePermissions(created.getId(), Set.of(perm2.getId()), adminUserId);

            // Flush and clear to ensure fresh fetch
            entityManager.flush();
            entityManager.clear();

            // Then
            RoleWithPermissionsDto roleWithPerms = roleService.getRoleWithPermissions(created.getId());
            assertThat(roleWithPerms.getPermissions()).hasSize(1);
            assertThat(roleWithPerms.getPermissions().get(0).getId()).isEqualTo(perm2.getId());

            // Cleanup
            roleRepository.deleteById(created.getId());
            permissionRepository.delete(perm1);
            permissionRepository.delete(perm2);
        }
    }

    @Nested
    @DisplayName("User Role Assignment Operations")
    class UserRoleAssignmentOperations {

        @Test
        @DisplayName("Should assign role to user")
        @Transactional
        void shouldAssignRoleToUser() {
            // Given - Create test user and role
            AuthUser user = createTestUser("role_assign_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName = "USER_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role to assign to user")
                    .priority(20)
                    .build();
            RoleDto role = roleService.createRole(roleRequest, adminUserId);

            // When
            AssignRoleRequest assignRequest = AssignRoleRequest.builder()
                    .userId(user.getId())
                    .roleId(role.getId())
                    .build();
            UserRoleDto assignment = roleService.assignRoleToUser(assignRequest, adminUserId);

            // Then
            assertThat(assignment).isNotNull();
            assertThat(assignment.getUserId()).isEqualTo(user.getId());
            assertThat(assignment.getRoleId()).isEqualTo(role.getId());
            assertThat(assignment.getRoleName()).isEqualTo(roleName.toUpperCase());
            assertThat(assignment.isActive()).isTrue();
            assertThat(assignment.getAssignedBy()).isEqualTo(adminUserId);

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should assign role with expiration date")
        @Transactional
        void shouldAssignRoleWithExpiration() {
            // Given
            AuthUser user = createTestUser("role_expire_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName = "EXPIRE_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Expiring role")
                    .priority(15)
                    .build();
            RoleDto role = roleService.createRole(roleRequest, adminUserId);

            Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);

            // When
            AssignRoleRequest assignRequest = AssignRoleRequest.builder()
                    .userId(user.getId())
                    .roleId(role.getId())
                    .expiresAt(expiresAt)
                    .build();
            UserRoleDto assignment = roleService.assignRoleToUser(assignRequest, adminUserId);

            // Then
            assertThat(assignment.getExpiresAt()).isNotNull();
            assertThat(assignment.getExpiresAt()).isAfter(Instant.now());

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should fail to assign duplicate role to user")
        @Transactional
        void shouldFailToAssignDuplicateRole() {
            // Given
            AuthUser user = createTestUser("dup_role_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName = "DUP_CHECK_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Duplicate check role")
                    .priority(25)
                    .build();
            RoleDto role = roleService.createRole(roleRequest, adminUserId);

            AssignRoleRequest assignRequest = AssignRoleRequest.builder()
                    .userId(user.getId())
                    .roleId(role.getId())
                    .build();
            roleService.assignRoleToUser(assignRequest, adminUserId);

            // When/Then - Try to assign same role again
            assertThatThrownBy(() -> roleService.assignRoleToUser(assignRequest, adminUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User already has this role");

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should revoke role from user")
        @Transactional
        void shouldRevokeRoleFromUser() {
            // Given
            AuthUser user = createTestUser("revoke_role_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName = "REVOKE_ROLE_" + System.currentTimeMillis();
            CreateRoleRequest roleRequest = CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role to revoke")
                    .priority(30)
                    .build();
            RoleDto role = roleService.createRole(roleRequest, adminUserId);

            AssignRoleRequest assignRequest = AssignRoleRequest.builder()
                    .userId(user.getId())
                    .roleId(role.getId())
                    .build();
            roleService.assignRoleToUser(assignRequest, adminUserId);

            // When
            roleService.revokeRoleFromUser(user.getId(), role.getId());

            // Then
            List<UserRoleDto> userRoles = roleService.getUserRoles(user.getId());
            assertThat(userRoles).noneMatch(r -> r.getRoleId().equals(role.getId()));

            // Cleanup
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should get user roles")
        @Transactional
        void shouldGetUserRoles() {
            // Given
            AuthUser user = createTestUser("get_roles_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName1 = "GET_ROLE_1_" + System.currentTimeMillis();
            String roleName2 = "GET_ROLE_2_" + System.currentTimeMillis();

            RoleDto role1 = roleService.createRole(CreateRoleRequest.builder()
                    .name(roleName1).description("First role").priority(10).build(), adminUserId);
            RoleDto role2 = roleService.createRole(CreateRoleRequest.builder()
                    .name(roleName2).description("Second role").priority(20).build(), adminUserId);

            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role1.getId()).build(), adminUserId);
            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role2.getId()).build(), adminUserId);

            // When
            List<UserRoleDto> userRoles = roleService.getUserRoles(user.getId());

            // Then
            assertThat(userRoles).hasSize(2);
            assertThat(userRoles).anyMatch(r -> r.getRoleName().equals(roleName1.toUpperCase()));
            assertThat(userRoles).anyMatch(r -> r.getRoleName().equals(roleName2.toUpperCase()));

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role1.getId());
            roleRepository.deleteById(role2.getId());
        }

        @Test
        @DisplayName("Should check if user has role")
        @Transactional
        void shouldCheckIfUserHasRole() {
            // Given
            AuthUser user = createTestUser("has_role_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName = "HAS_ROLE_" + System.currentTimeMillis();
            RoleDto role = roleService.createRole(CreateRoleRequest.builder()
                    .name(roleName).description("Role to check").priority(35).build(), adminUserId);

            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role.getId()).build(), adminUserId);

            // When/Then
            assertThat(roleService.userHasRole(user.getId(), roleName)).isTrue();
            assertThat(roleService.userHasRole(user.getId(), "NON_EXISTENT_ROLE")).isFalse();

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should check if user has any of specified roles")
        @Transactional
        void shouldCheckIfUserHasAnyRole() {
            // Given
            AuthUser user = createTestUser("any_role_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            String roleName = "ANY_ROLE_" + System.currentTimeMillis();
            RoleDto role = roleService.createRole(CreateRoleRequest.builder()
                    .name(roleName).description("Any role check").priority(40).build(), adminUserId);

            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role.getId()).build(), adminUserId);

            // When/Then
            assertThat(roleService.userHasAnyRole(user.getId(), Set.of(roleName, "OTHER_ROLE"))).isTrue();
            assertThat(roleService.userHasAnyRole(user.getId(), Set.of("ROLE_A", "ROLE_B"))).isFalse();

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should revoke all roles from user")
        @Transactional
        void shouldRevokeAllRolesFromUser() {
            // Given
            AuthUser user = createTestUser("revoke_all_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            RoleDto role1 = roleService.createRole(CreateRoleRequest.builder()
                    .name("REVOKE_ALL_1_" + System.currentTimeMillis())
                    .description("First role").priority(10).build(), adminUserId);
            RoleDto role2 = roleService.createRole(CreateRoleRequest.builder()
                    .name("REVOKE_ALL_2_" + System.currentTimeMillis())
                    .description("Second role").priority(20).build(), adminUserId);

            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role1.getId()).build(), adminUserId);
            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role2.getId()).build(), adminUserId);

            // When
            roleService.revokeAllRolesFromUser(user.getId());

            // Then
            List<UserRoleDto> userRoles = roleService.getUserRoles(user.getId());
            assertThat(userRoles).isEmpty();

            // Cleanup
            roleRepository.deleteById(role1.getId());
            roleRepository.deleteById(role2.getId());
        }
    }

    @Nested
    @DisplayName("User Permission Operations")
    class UserPermissionOperations {

        @Test
        @DisplayName("Should get user permissions through assigned roles")
        @Transactional
        void shouldGetUserPermissionsThroughRoles() {
            // Given - Create user, permission, role with permission, and assign to user
            AuthUser user = createTestUser("user_perms_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            testPermission = Permission.builder()
                    .name("user:permission:" + System.currentTimeMillis())
                    .description("User permission test")
                    .resource("user")
                    .action("view")
                    .isActive(true)
                    .build();
            testPermission = permissionRepository.save(testPermission);

            String roleName = "USER_PERM_ROLE_" + System.currentTimeMillis();
            RoleDto role = roleService.createRole(CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role with permission")
                    .priority(45)
                    .permissionIds(Set.of(testPermission.getId()))
                    .build(), adminUserId);

            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role.getId()).build(), adminUserId);

            // When
            UserPermissionsDto userPerms = roleService.getUserPermissions(user.getId());

            // Then
            assertThat(userPerms).isNotNull();
            assertThat(userPerms.getUserId()).isEqualTo(user.getId());
            assertThat(userPerms.getRoles()).contains(roleName.toUpperCase());
            assertThat(userPerms.getPermissions()).contains(testPermission.getName());

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }

        @Test
        @DisplayName("Should check if user has specific permission")
        @Transactional
        void shouldCheckIfUserHasPermission() {
            // Given
            AuthUser user = createTestUser("check_perm_" + System.currentTimeMillis() + "@test.com");
            testUserId = user.getId();

            testPermission = Permission.builder()
                    .name("check:permission:" + System.currentTimeMillis())
                    .description("Permission check test")
                    .resource("check")
                    .action("execute")
                    .isActive(true)
                    .build();
            testPermission = permissionRepository.save(testPermission);

            String roleName = "CHECK_PERM_ROLE_" + System.currentTimeMillis();
            RoleDto role = roleService.createRole(CreateRoleRequest.builder()
                    .name(roleName)
                    .description("Role for permission check")
                    .priority(50)
                    .permissionIds(Set.of(testPermission.getId()))
                    .build(), adminUserId);

            roleService.assignRoleToUser(AssignRoleRequest.builder()
                    .userId(user.getId()).roleId(role.getId()).build(), adminUserId);

            // When/Then
            assertThat(roleService.userHasPermission(user.getId(), testPermission.getName())).isTrue();
            assertThat(roleService.userHasPermission(user.getId(), "nonexistent:permission")).isFalse();

            // Cleanup
            userRoleAssignmentRepository.deactivateAllUserRoles(user.getId());
            roleRepository.deleteById(role.getId());
        }
    }

    // ==================== Helper Methods ====================

    private AuthUser createTestUser(String email) {
        AuthUser user = AuthUser.builder()
                .email(email)
                .passwordHash("$2a$10$test.password.hash")
                .status(AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();
        return authUserRepository.save(user);
    }
}
