package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.AuthUser.AuthStatus;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.RbacDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.PermissionService;
import com.quckapp.auth.service.RoleService;
import com.quckapp.auth.service.SessionManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for AdminController
 */
@ExtendWith(MockitoExtension.class)
class AdminControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }
    }

    @Mock
    private RoleService roleService;

    @Mock
    private PermissionService permissionService;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private SessionManagementService sessionManagementService;

    @Mock
    private JwtOperations jwtOperations;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final UUID ADMIN_USER_ID = UUID.randomUUID();
    private static final UUID TEST_USER_ID = UUID.randomUUID();
    private static final UUID TEST_ROLE_ID = UUID.randomUUID();
    private static final UUID TEST_PERMISSION_ID = UUID.randomUUID();
    private static final String VALID_TOKEN = "valid-admin-token";
    private static final String AUTH_HEADER = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        AdminController controller = new AdminController(
                roleService, permissionService, authUserRepository, sessionManagementService, jwtOperations);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    private void setupAdminAccess() {
        when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(ADMIN_USER_ID.toString());
        when(roleService.userHasPermission(ADMIN_USER_ID, "admin", "access")).thenReturn(true);
    }

    private AuthUser createTestUser() {
        return AuthUser.builder()
                .id(TEST_USER_ID)
                .email("test@example.com")
                .status(AuthStatus.ACTIVE)
                .emailVerified(true)
                .twoFactorEnabled(false)
                .createdAt(Instant.now())
                .build();
    }

    @Nested
    @DisplayName("Admin Access Verification Tests")
    class AdminAccessTests {

        @Test
        @DisplayName("should reject non-admin users")
        void shouldRejectNonAdminUsers() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(ADMIN_USER_ID.toString());
            when(roleService.userHasPermission(ADMIN_USER_ID, "admin", "access")).thenReturn(false);

            mockMvc.perform(get("/v1/admin/users")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("User Management Tests")
    class UserManagementTests {

        @Test
        @DisplayName("should list all users")
        void shouldListAllUsers() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            Page<AuthUser> page = new PageImpl<>(List.of(user), PageRequest.of(0, 20), 1);
            when(authUserRepository.findAll(any(PageRequest.class))).thenReturn(page);

            mockMvc.perform(get("/v1/admin/users")
                            .header("Authorization", AUTH_HEADER)
                            .param("page", "0")
                            .param("size", "20"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.content[0].id").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.content[0].email").value("test@example.com"));
        }

        @Test
        @DisplayName("should get user details")
        void shouldGetUserDetails() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));
            when(roleService.getUserRoles(TEST_USER_ID)).thenReturn(List.of());

            mockMvc.perform(get("/v1/admin/users/{userId}", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.status").value("ACTIVE"));
        }

        @Test
        @DisplayName("should suspend user")
        void shouldSuspendUser() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            AdminController.SuspendUserRequest request = new AdminController.SuspendUserRequest();
            request.setReason("Policy violation");

            mockMvc.perform(post("/v1/admin/users/{userId}/suspend", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User suspended successfully"));

            verify(authUserRepository).save(any(AuthUser.class));
            verify(sessionManagementService).terminateAllUserSessions(eq(TEST_USER_ID), anyString());
        }

        @Test
        @DisplayName("should activate user")
        void shouldActivateUser() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            user.setStatus(AuthStatus.SUSPENDED);
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/admin/users/{userId}/activate", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User activated successfully"));

            verify(authUserRepository).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should lock user account")
        void shouldLockUserAccount() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            AdminController.LockUserRequest request = new AdminController.LockUserRequest();
            request.setReason("Security concern");
            request.setLockHours(24);

            mockMvc.perform(post("/v1/admin/users/{userId}/lock", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User account locked"));

            verify(authUserRepository).save(any(AuthUser.class));
            verify(sessionManagementService).terminateAllUserSessions(eq(TEST_USER_ID), anyString());
        }

        @Test
        @DisplayName("should unlock user account")
        void shouldUnlockUserAccount() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            user.setLockedUntil(Instant.now().plusSeconds(3600));
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/admin/users/{userId}/unlock", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User account unlocked"));

            verify(authUserRepository).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should force password change")
        void shouldForcePasswordChange() throws Exception {
            setupAdminAccess();

            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/admin/users/{userId}/force-password-change", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authUserRepository).save(any(AuthUser.class));
        }
    }

    @Nested
    @DisplayName("Role Management Tests")
    class RoleManagementTests {

        @Test
        @DisplayName("should list all roles")
        void shouldListAllRoles() throws Exception {
            setupAdminAccess();

            RoleDto role = RoleDto.builder()
                    .id(TEST_ROLE_ID)
                    .name("ADMIN")
                    .description("Administrator role")
                    .build();

            when(roleService.getAllRoles()).thenReturn(List.of(role));

            mockMvc.perform(get("/v1/admin/roles")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(TEST_ROLE_ID.toString()))
                    .andExpect(jsonPath("$[0].name").value("ADMIN"));
        }

        @Test
        @DisplayName("should get role details")
        void shouldGetRoleDetails() throws Exception {
            setupAdminAccess();

            RoleWithPermissionsDto role = RoleWithPermissionsDto.builder()
                    .id(TEST_ROLE_ID)
                    .name("ADMIN")
                    .permissions(List.of())
                    .build();

            when(roleService.getRoleWithPermissions(TEST_ROLE_ID)).thenReturn(role);

            mockMvc.perform(get("/v1/admin/roles/{roleId}", TEST_ROLE_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_ROLE_ID.toString()))
                    .andExpect(jsonPath("$.name").value("ADMIN"));
        }

        @Test
        @DisplayName("should create new role")
        void shouldCreateNewRole() throws Exception {
            setupAdminAccess();

            CreateRoleRequest request = CreateRoleRequest.builder()
                    .name("MODERATOR")
                    .description("Moderator role")
                    .priority(50)
                    .build();

            RoleDto createdRole = RoleDto.builder()
                    .id(UUID.randomUUID())
                    .name("MODERATOR")
                    .description("Moderator role")
                    .build();

            when(roleService.createRole(any(CreateRoleRequest.class), eq(ADMIN_USER_ID)))
                    .thenReturn(createdRole);

            mockMvc.perform(post("/v1/admin/roles")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name").value("MODERATOR"));

            verify(roleService).createRole(any(CreateRoleRequest.class), eq(ADMIN_USER_ID));
        }

        @Test
        @DisplayName("should delete role")
        void shouldDeleteRole() throws Exception {
            setupAdminAccess();

            mockMvc.perform(delete("/v1/admin/roles/{roleId}", TEST_ROLE_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Role deleted successfully"));

            verify(roleService).deleteRole(TEST_ROLE_ID);
        }

        @Test
        @DisplayName("should update role")
        void shouldUpdateRole() throws Exception {
            setupAdminAccess();

            UpdateRoleRequest request = UpdateRoleRequest.builder()
                    .description("Updated role description")
                    .priority(75)
                    .active(true)
                    .build();

            RoleDto updatedRole = RoleDto.builder()
                    .id(TEST_ROLE_ID)
                    .name("ADMIN")
                    .description("Updated role description")
                    .build();

            when(roleService.updateRole(eq(TEST_ROLE_ID), any(UpdateRoleRequest.class)))
                    .thenReturn(updatedRole);

            mockMvc.perform(put("/v1/admin/roles/{roleId}", TEST_ROLE_ID)
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_ROLE_ID.toString()))
                    .andExpect(jsonPath("$.description").value("Updated role description"));

            verify(roleService).updateRole(eq(TEST_ROLE_ID), any(UpdateRoleRequest.class));
        }

        @Test
        @DisplayName("should add permissions to role")
        void shouldAddPermissionsToRole() throws Exception {
            setupAdminAccess();

            UUID permission1 = UUID.randomUUID();
            UUID permission2 = UUID.randomUUID();
            Set<UUID> permissionIds = Set.of(permission1, permission2);

            PermissionDto perm1 = PermissionDto.builder()
                    .id(permission1)
                    .name("users:read")
                    .build();
            PermissionDto perm2 = PermissionDto.builder()
                    .id(permission2)
                    .name("users:write")
                    .build();

            RoleWithPermissionsDto roleWithPerms = RoleWithPermissionsDto.builder()
                    .id(TEST_ROLE_ID)
                    .name("ADMIN")
                    .permissions(List.of(perm1, perm2))
                    .build();

            when(roleService.getRoleWithPermissions(TEST_ROLE_ID)).thenReturn(roleWithPerms);

            mockMvc.perform(post("/v1/admin/roles/{roleId}/permissions", TEST_ROLE_ID)
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(permissionIds)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_ROLE_ID.toString()))
                    .andExpect(jsonPath("$.permissions").isArray())
                    .andExpect(jsonPath("$.permissions.length()").value(2));

            verify(roleService).assignPermissionsToRole(eq(TEST_ROLE_ID), anySet(), eq(ADMIN_USER_ID));
        }

        @Test
        @DisplayName("should remove permission from role")
        void shouldRemovePermissionFromRole() throws Exception {
            setupAdminAccess();

            mockMvc.perform(delete("/v1/admin/roles/{roleId}/permissions/{permissionId}",
                            TEST_ROLE_ID, TEST_PERMISSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Permission removed from role"));

            verify(roleService).removePermissionFromRole(TEST_ROLE_ID, TEST_PERMISSION_ID);
        }
    }

    @Nested
    @DisplayName("User Role Assignment Tests")
    class UserRoleAssignmentTests {

        @Test
        @DisplayName("should get user roles")
        void shouldGetUserRoles() throws Exception {
            setupAdminAccess();

            UserRoleDto roleDto = UserRoleDto.builder()
                    .roleId(TEST_ROLE_ID)
                    .roleName("ADMIN")
                    .build();

            UserPermissionsDto permissionsDto = UserPermissionsDto.builder()
                    .userId(TEST_USER_ID)
                    .permissions(Set.of("admin:access"))
                    .build();

            when(roleService.getUserRoles(TEST_USER_ID)).thenReturn(List.of(roleDto));
            when(roleService.getUserPermissions(TEST_USER_ID)).thenReturn(permissionsDto);

            mockMvc.perform(get("/v1/admin/users/{userId}/roles", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.roles[0].roleName").value("ADMIN"));
        }

        @Test
        @DisplayName("should assign role to user")
        void shouldAssignRoleToUser() throws Exception {
            setupAdminAccess();

            AdminController.AdminAssignRoleRequest request = new AdminController.AdminAssignRoleRequest();
            request.setRoleId(TEST_ROLE_ID);

            UserRoleDto result = UserRoleDto.builder()
                    .roleId(TEST_ROLE_ID)
                    .roleName("ADMIN")
                    .build();

            when(roleService.assignRoleToUser(any(AssignRoleRequest.class), eq(ADMIN_USER_ID)))
                    .thenReturn(result);

            mockMvc.perform(post("/v1/admin/users/{userId}/roles", TEST_USER_ID)
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.roleName").value("ADMIN"));
        }

        @Test
        @DisplayName("should revoke role from user")
        void shouldRevokeRoleFromUser() throws Exception {
            setupAdminAccess();

            mockMvc.perform(delete("/v1/admin/users/{userId}/roles/{roleId}", TEST_USER_ID, TEST_ROLE_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Role revoked successfully"));

            verify(roleService).revokeRoleFromUser(TEST_USER_ID, TEST_ROLE_ID);
        }
    }

    @Nested
    @DisplayName("Permission Management Tests")
    class PermissionManagementTests {

        @Test
        @DisplayName("should list all permissions")
        void shouldListAllPermissions() throws Exception {
            setupAdminAccess();

            PermissionDto permission = PermissionDto.builder()
                    .id(TEST_PERMISSION_ID)
                    .name("admin:access")
                    .resource("admin")
                    .action("access")
                    .build();

            when(permissionService.getAllPermissions()).thenReturn(List.of(permission));

            mockMvc.perform(get("/v1/admin/permissions")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(TEST_PERMISSION_ID.toString()))
                    .andExpect(jsonPath("$[0].name").value("admin:access"));
        }

        @Test
        @DisplayName("should get permission by ID")
        void shouldGetPermissionById() throws Exception {
            setupAdminAccess();

            PermissionDto permission = PermissionDto.builder()
                    .id(TEST_PERMISSION_ID)
                    .name("admin:access")
                    .resource("admin")
                    .action("access")
                    .description("Admin access permission")
                    .build();

            when(permissionService.getPermission(TEST_PERMISSION_ID)).thenReturn(permission);

            mockMvc.perform(get("/v1/admin/permissions/{permissionId}", TEST_PERMISSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_PERMISSION_ID.toString()))
                    .andExpect(jsonPath("$.name").value("admin:access"))
                    .andExpect(jsonPath("$.resource").value("admin"))
                    .andExpect(jsonPath("$.action").value("access"));

            verify(permissionService).getPermission(TEST_PERMISSION_ID);
        }

        @Test
        @DisplayName("should create permission")
        void shouldCreatePermission() throws Exception {
            setupAdminAccess();

            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name("users:read")
                    .resource("users")
                    .action("read")
                    .description("Read users")
                    .build();

            PermissionDto createdPermission = PermissionDto.builder()
                    .id(UUID.randomUUID())
                    .name("users:read")
                    .resource("users")
                    .action("read")
                    .build();

            when(permissionService.createPermission(any(CreatePermissionRequest.class)))
                    .thenReturn(createdPermission);

            mockMvc.perform(post("/v1/admin/permissions")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.name").value("users:read"));
        }

        @Test
        @DisplayName("should delete permission")
        void shouldDeletePermission() throws Exception {
            setupAdminAccess();

            mockMvc.perform(delete("/v1/admin/permissions/{permissionId}", TEST_PERMISSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Permission deleted successfully"));

            verify(permissionService).deletePermission(TEST_PERMISSION_ID);
        }
    }

    @Nested
    @DisplayName("Statistics Tests")
    class StatisticsTests {

        @Test
        @DisplayName("should get admin statistics")
        void shouldGetAdminStatistics() throws Exception {
            setupAdminAccess();

            when(authUserRepository.count()).thenReturn(100L);
            when(roleService.getAllRoles()).thenReturn(List.of(
                    RoleDto.builder().id(UUID.randomUUID()).name("ADMIN").build(),
                    RoleDto.builder().id(UUID.randomUUID()).name("USER").build()
            ));
            when(permissionService.getAllPermissions()).thenReturn(List.of(
                    PermissionDto.builder().id(UUID.randomUUID()).name("admin:access").build()
            ));

            mockMvc.perform(get("/v1/admin/stats")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalUsers").value(100))
                    .andExpect(jsonPath("$.totalRoles").value(2))
                    .andExpect(jsonPath("$.totalPermissions").value(1));
        }
    }
}
