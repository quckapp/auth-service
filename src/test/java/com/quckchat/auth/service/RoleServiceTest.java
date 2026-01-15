package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.RbacDtos.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RoleService
 */
@ExtendWith(MockitoExtension.class)
class RoleServiceTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private RolePermissionRepository rolePermissionRepository;

    @Mock
    private UserRoleAssignmentRepository userRoleAssignmentRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    private RoleService roleService;

    private UUID testRoleId;
    private UUID testUserId;
    private UUID testPermissionId;
    private UUID adminUserId;
    private Role testRole;
    private Permission testPermission;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        roleService = new RoleService(
                roleRepository,
                permissionRepository,
                rolePermissionRepository,
                userRoleAssignmentRepository,
                authUserRepository
        );

        testRoleId = UUID.randomUUID();
        testUserId = UUID.randomUUID();
        testPermissionId = UUID.randomUUID();
        adminUserId = UUID.randomUUID();

        testRole = Role.builder()
                .id(testRoleId)
                .name("EDITOR")
                .description("Editor role")
                .priority(5)
                .isSystemRole(false)
                .isActive(true)
                .rolePermissions(new HashSet<>())
                .userRoles(new HashSet<>())
                .build();

        testPermission = Permission.builder()
                .id(testPermissionId)
                .name("posts:write")
                .resource("posts")
                .action("write")
                .isActive(true)
                .rolePermissions(new HashSet<>())
                .build();

        testUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .build();
    }

    @Nested
    @DisplayName("Create Role Tests")
    class CreateRoleTests {

        @Test
        @DisplayName("should create role successfully")
        void shouldCreateRoleSuccessfully() {
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name("moderator")
                    .description("Moderator role")
                    .priority(3)
                    .build();

            when(roleRepository.existsByName("moderator")).thenReturn(false);
            when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> {
                Role role = invocation.getArgument(0);
                role.setId(UUID.randomUUID());
                return role;
            });

            RoleDto result = roleService.createRole(request, adminUserId);

            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("MODERATOR");
            assertThat(result.getDescription()).isEqualTo("Moderator role");
            assertThat(result.getPriority()).isEqualTo(3);

            ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
            verify(roleRepository).save(roleCaptor.capture());
            assertThat(roleCaptor.getValue().isSystemRole()).isFalse();
            assertThat(roleCaptor.getValue().isActive()).isTrue();
        }

        @Test
        @DisplayName("should create role with permissions")
        void shouldCreateRoleWithPermissions() {
            Set<UUID> permissionIds = new HashSet<>(Collections.singletonList(testPermissionId));
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name("content-manager")
                    .description("Content Manager")
                    .priority(4)
                    .permissionIds(permissionIds)
                    .build();

            when(roleRepository.existsByName("content-manager")).thenReturn(false);
            when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> {
                Role role = invocation.getArgument(0);
                role.setId(testRoleId);
                return role;
            });
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(permissionIds)).thenReturn(Collections.singletonList(testPermission));
            when(rolePermissionRepository.existsByRoleIdAndPermissionId(any(), any())).thenReturn(false);

            RoleDto result = roleService.createRole(request, adminUserId);

            assertThat(result).isNotNull();
            verify(rolePermissionRepository).save(any(RolePermission.class));
        }

        @Test
        @DisplayName("should throw exception when role name exists")
        void shouldThrowWhenRoleNameExists() {
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name("editor")
                    .description("Editor role")
                    .priority(5)
                    .build();

            when(roleRepository.existsByName("editor")).thenReturn(true);

            assertThatThrownBy(() -> roleService.createRole(request, adminUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Role already exists");

            verify(roleRepository, never()).save(any());
        }

        @Test
        @DisplayName("should convert role name to uppercase")
        void shouldConvertRoleNameToUppercase() {
            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name("viewer")
                    .description("Viewer role")
                    .priority(1)
                    .build();

            when(roleRepository.existsByName("viewer")).thenReturn(false);
            when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> {
                Role role = invocation.getArgument(0);
                role.setId(UUID.randomUUID());
                return role;
            });

            roleService.createRole(request, adminUserId);

            ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
            verify(roleRepository).save(roleCaptor.capture());
            assertThat(roleCaptor.getValue().getName()).isEqualTo("VIEWER");
        }
    }

    @Nested
    @DisplayName("Get Role Tests")
    class GetRoleTests {

        @Test
        @DisplayName("should get role by ID")
        void shouldGetRoleById() {
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            RoleDto result = roleService.getRole(testRoleId);

            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(testRoleId);
            assertThat(result.getName()).isEqualTo("EDITOR");
        }

        @Test
        @DisplayName("should throw when role not found by ID")
        void shouldThrowWhenRoleNotFoundById() {
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> roleService.getRole(testRoleId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Role not found");
        }

        @Test
        @DisplayName("should get role with permissions")
        void shouldGetRoleWithPermissions() {
            when(roleRepository.findByIdWithPermissions(testRoleId)).thenReturn(Optional.of(testRole));

            RoleWithPermissionsDto result = roleService.getRoleWithPermissions(testRoleId);

            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(testRoleId);
        }

        @Test
        @DisplayName("should get role by name")
        void shouldGetRoleByName() {
            when(roleRepository.findByName("EDITOR")).thenReturn(Optional.of(testRole));

            Optional<RoleDto> result = roleService.getRoleByName("editor");

            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("EDITOR");
        }

        @Test
        @DisplayName("should get all roles")
        void shouldGetAllRoles() {
            Role role2 = Role.builder()
                    .id(UUID.randomUUID())
                    .name("ADMIN")
                    .isActive(true)
                    .build();

            when(roleRepository.findAll()).thenReturn(Arrays.asList(testRole, role2));

            List<RoleDto> result = roleService.getAllRoles();

            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("should get active roles ordered by priority")
        void shouldGetActiveRolesOrderedByPriority() {
            when(roleRepository.findByIsActiveTrueOrderByPriorityDesc())
                    .thenReturn(Collections.singletonList(testRole));

            List<RoleDto> result = roleService.getActiveRoles();

            assertThat(result).hasSize(1);
            verify(roleRepository).findByIsActiveTrueOrderByPriorityDesc();
        }
    }

    @Nested
    @DisplayName("Update Role Tests")
    class UpdateRoleTests {

        @Test
        @DisplayName("should update role description")
        void shouldUpdateRoleDescription() {
            UpdateRoleRequest request = UpdateRoleRequest.builder()
                    .description("Updated description")
                    .build();

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.save(any(Role.class))).thenReturn(testRole);

            RoleDto result = roleService.updateRole(testRoleId, request);

            assertThat(result).isNotNull();
            assertThat(testRole.getDescription()).isEqualTo("Updated description");
            verify(roleRepository).save(testRole);
        }

        @Test
        @DisplayName("should update role priority")
        void shouldUpdateRolePriority() {
            UpdateRoleRequest request = UpdateRoleRequest.builder()
                    .priority(10)
                    .build();

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.save(any(Role.class))).thenReturn(testRole);

            roleService.updateRole(testRoleId, request);

            assertThat(testRole.getPriority()).isEqualTo(10);
        }

        @Test
        @DisplayName("should update role active status")
        void shouldUpdateRoleActiveStatus() {
            UpdateRoleRequest request = UpdateRoleRequest.builder()
                    .active(false)
                    .build();

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.save(any(Role.class))).thenReturn(testRole);

            roleService.updateRole(testRoleId, request);

            assertThat(testRole.isActive()).isFalse();
        }

        @Test
        @DisplayName("should throw when modifying system role")
        void shouldThrowWhenModifyingSystemRole() {
            testRole.setSystemRole(true);
            UpdateRoleRequest request = UpdateRoleRequest.builder()
                    .description("New description")
                    .build();

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> roleService.updateRole(testRoleId, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot modify system role");

            verify(roleRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Delete Role Tests")
    class DeleteRoleTests {

        @Test
        @DisplayName("should delete role successfully")
        void shouldDeleteRoleSuccessfully() {
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.countActiveUsersByRoleId(testRoleId)).thenReturn(0L);

            roleService.deleteRole(testRoleId);

            verify(roleRepository).delete(testRole);
        }

        @Test
        @DisplayName("should throw when deleting system role")
        void shouldThrowWhenDeletingSystemRole() {
            testRole.setSystemRole(true);
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));

            assertThatThrownBy(() -> roleService.deleteRole(testRoleId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot delete system role");

            verify(roleRepository, never()).delete(any());
        }

        @Test
        @DisplayName("should throw when role has active users")
        void shouldThrowWhenRoleHasActiveUsers() {
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(roleRepository.countActiveUsersByRoleId(testRoleId)).thenReturn(5L);

            assertThatThrownBy(() -> roleService.deleteRole(testRoleId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot delete role with 5 active users assigned");

            verify(roleRepository, never()).delete(any());
        }
    }

    @Nested
    @DisplayName("Role Permission Management Tests")
    class RolePermissionManagementTests {

        @Test
        @DisplayName("should assign permissions to role")
        void shouldAssignPermissionsToRole() {
            Set<UUID> permissionIds = new HashSet<>(Collections.singletonList(testPermissionId));

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(permissionIds)).thenReturn(Collections.singletonList(testPermission));
            when(rolePermissionRepository.existsByRoleIdAndPermissionId(testRoleId, testPermissionId))
                    .thenReturn(false);

            roleService.assignPermissionsToRole(testRoleId, permissionIds, adminUserId);

            verify(rolePermissionRepository).save(any(RolePermission.class));
        }

        @Test
        @DisplayName("should skip already assigned permissions")
        void shouldSkipAlreadyAssignedPermissions() {
            Set<UUID> permissionIds = new HashSet<>(Collections.singletonList(testPermissionId));

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(permissionIds)).thenReturn(Collections.singletonList(testPermission));
            when(rolePermissionRepository.existsByRoleIdAndPermissionId(testRoleId, testPermissionId))
                    .thenReturn(true);

            roleService.assignPermissionsToRole(testRoleId, permissionIds, adminUserId);

            verify(rolePermissionRepository, never()).save(any());
        }

        @Test
        @DisplayName("should throw when some permissions not found")
        void shouldThrowWhenSomePermissionsNotFound() {
            UUID unknownPermissionId = UUID.randomUUID();
            Set<UUID> permissionIds = new HashSet<>(Arrays.asList(testPermissionId, unknownPermissionId));

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(permissionIds))
                    .thenReturn(Collections.singletonList(testPermission));

            assertThatThrownBy(() -> roleService.assignPermissionsToRole(testRoleId, permissionIds, adminUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Some permissions not found");
        }

        @Test
        @DisplayName("should remove permission from role")
        void shouldRemovePermissionFromRole() {
            roleService.removePermissionFromRole(testRoleId, testPermissionId);

            verify(rolePermissionRepository).deleteByRoleIdAndPermissionId(testRoleId, testPermissionId);
        }

        @Test
        @DisplayName("should set role permissions (replace all)")
        void shouldSetRolePermissions() {
            Set<UUID> newPermissionIds = new HashSet<>(Collections.singletonList(testPermissionId));

            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(permissionRepository.findAllById(newPermissionIds))
                    .thenReturn(Collections.singletonList(testPermission));
            when(rolePermissionRepository.existsByRoleIdAndPermissionId(any(), any())).thenReturn(false);

            roleService.setRolePermissions(testRoleId, newPermissionIds, adminUserId);

            verify(rolePermissionRepository).deleteAllByRoleId(testRoleId);
            verify(rolePermissionRepository).save(any(RolePermission.class));
        }
    }

    @Nested
    @DisplayName("User Role Assignment Tests")
    class UserRoleAssignmentTests {

        @Test
        @DisplayName("should assign role to user")
        void shouldAssignRoleToUser() {
            AssignRoleRequest request = AssignRoleRequest.builder()
                    .userId(testUserId)
                    .roleId(testRoleId)
                    .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(userRoleAssignmentRepository.hasActiveRole(testUserId, testRoleId)).thenReturn(false);
            when(userRoleAssignmentRepository.save(any(UserRoleAssignment.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            UserRoleDto result = roleService.assignRoleToUser(request, adminUserId);

            assertThat(result).isNotNull();
            assertThat(result.getUserId()).isEqualTo(testUserId);
            assertThat(result.getRoleId()).isEqualTo(testRoleId);

            ArgumentCaptor<UserRoleAssignment> captor = ArgumentCaptor.forClass(UserRoleAssignment.class);
            verify(userRoleAssignmentRepository).save(captor.capture());
            assertThat(captor.getValue().isActive()).isTrue();
            assertThat(captor.getValue().getAssignedBy()).isEqualTo(adminUserId);
        }

        @Test
        @DisplayName("should throw when user already has role")
        void shouldThrowWhenUserAlreadyHasRole() {
            AssignRoleRequest request = AssignRoleRequest.builder()
                    .userId(testUserId)
                    .roleId(testRoleId)
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(roleRepository.findById(testRoleId)).thenReturn(Optional.of(testRole));
            when(userRoleAssignmentRepository.hasActiveRole(testUserId, testRoleId)).thenReturn(true);

            assertThatThrownBy(() -> roleService.assignRoleToUser(request, adminUserId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User already has this role");

            verify(userRoleAssignmentRepository, never()).save(any());
        }

        @Test
        @DisplayName("should revoke role from user")
        void shouldRevokeRoleFromUser() {
            when(userRoleAssignmentRepository.deactivateUserRole(testUserId, testRoleId)).thenReturn(1);

            roleService.revokeRoleFromUser(testUserId, testRoleId);

            verify(userRoleAssignmentRepository).deactivateUserRole(testUserId, testRoleId);
        }

        @Test
        @DisplayName("should throw when role assignment not found for revocation")
        void shouldThrowWhenRoleAssignmentNotFoundForRevocation() {
            when(userRoleAssignmentRepository.deactivateUserRole(testUserId, testRoleId)).thenReturn(0);

            assertThatThrownBy(() -> roleService.revokeRoleFromUser(testUserId, testRoleId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User role assignment not found");
        }

        @Test
        @DisplayName("should revoke all roles from user")
        void shouldRevokeAllRolesFromUser() {
            roleService.revokeAllRolesFromUser(testUserId);

            verify(userRoleAssignmentRepository).deactivateAllUserRoles(testUserId);
        }

        @Test
        @DisplayName("should get user roles")
        void shouldGetUserRoles() {
            UserRoleAssignment assignment = UserRoleAssignment.builder()
                    .user(testUser)
                    .role(testRole)
                    .assignedBy(adminUserId)
                    .isActive(true)
                    .build();

            when(userRoleAssignmentRepository.findActiveByUserIdWithRoles(testUserId))
                    .thenReturn(Collections.singletonList(assignment));

            List<UserRoleDto> result = roleService.getUserRoles(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getRoleName()).isEqualTo("EDITOR");
        }

        @Test
        @DisplayName("should check if user has role")
        void shouldCheckIfUserHasRole() {
            when(userRoleAssignmentRepository.hasActiveRoleByName(testUserId, "EDITOR")).thenReturn(true);

            boolean result = roleService.userHasRole(testUserId, "editor");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should check if user has any of the specified roles")
        void shouldCheckIfUserHasAnyRole() {
            UserRoleAssignment assignment = UserRoleAssignment.builder()
                    .user(testUser)
                    .role(testRole)
                    .isActive(true)
                    .build();

            when(userRoleAssignmentRepository.findActiveByUserId(testUserId))
                    .thenReturn(Collections.singletonList(assignment));

            boolean result = roleService.userHasAnyRole(testUserId, new HashSet<>(Arrays.asList("ADMIN", "EDITOR")));

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("User Permissions Tests")
    class UserPermissionsTests {

        @Test
        @DisplayName("should get user permissions")
        void shouldGetUserPermissions() {
            UserRoleAssignment assignment = UserRoleAssignment.builder()
                    .user(testUser)
                    .role(testRole)
                    .isActive(true)
                    .build();

            Set<String> permissions = new HashSet<>(Arrays.asList("posts:read", "posts:write"));

            when(userRoleAssignmentRepository.findActiveByUserIdWithRoles(testUserId))
                    .thenReturn(Collections.singletonList(assignment));
            when(permissionRepository.findPermissionNamesByUserId(testUserId)).thenReturn(permissions);

            UserPermissionsDto result = roleService.getUserPermissions(testUserId);

            assertThat(result.getUserId()).isEqualTo(testUserId);
            assertThat(result.getRoles()).contains("EDITOR");
            assertThat(result.getPermissions()).containsExactlyInAnyOrder("posts:read", "posts:write");
        }

        @Test
        @DisplayName("should check if user has permission by name")
        void shouldCheckIfUserHasPermissionByName() {
            Set<String> permissions = new HashSet<>(Collections.singletonList("posts:write"));
            when(permissionRepository.findPermissionNamesByUserId(testUserId)).thenReturn(permissions);

            boolean result = roleService.userHasPermission(testUserId, "posts:write");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should check if user has permission by resource and action")
        void shouldCheckIfUserHasPermissionByResourceAndAction() {
            Set<String> permissions = new HashSet<>(Collections.singletonList("posts:write"));
            when(permissionRepository.findPermissionNamesByUserId(testUserId)).thenReturn(permissions);

            boolean result = roleService.userHasPermission(testUserId, "posts", "write");

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Maintenance Tests")
    class MaintenanceTests {

        @Test
        @DisplayName("should deactivate expired role assignments")
        void shouldDeactivateExpiredRoleAssignments() {
            when(userRoleAssignmentRepository.deactivateExpiredAssignments(any(Instant.class))).thenReturn(3);

            int count = roleService.deactivateExpiredAssignments();

            assertThat(count).isEqualTo(3);
            verify(userRoleAssignmentRepository).deactivateExpiredAssignments(any(Instant.class));
        }
    }
}
