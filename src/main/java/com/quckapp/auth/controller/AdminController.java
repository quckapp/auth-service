package com.quckapp.auth.controller;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.AuthUser.AuthStatus;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.RbacDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.service.PermissionService;
import com.quckapp.auth.service.RoleService;
import com.quckapp.auth.service.SessionManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST Controller for Administrative operations
 * Provides endpoints for user management, role management, and permission management
 * All endpoints require admin privileges
 */
@RestController
@RequestMapping("/v1/admin")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin", description = "Administrative operations - user management, role and permission management")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {

    private final RoleService roleService;
    private final PermissionService permissionService;
    private final AuthUserRepository authUserRepository;
    private final SessionManagementService sessionManagementService;
    private final JwtOperations jwtOperations;

    // ==================== User Management ====================

    @GetMapping("/users")
    @Operation(summary = "List all users",
               description = "Get a paginated list of all users in the system")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<Page<AdminUserDto>> listUsers(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        verifyAdminAccess(authHeader);

        Pageable pageable = PageRequest.of(page, Math.min(size, 100));
        Page<AuthUser> users = authUserRepository.findAll(pageable);

        Page<AdminUserDto> userDtos = users.map(this::mapToAdminUserDto);
        return ResponseEntity.ok(userDtos);
    }

    @GetMapping("/users/{userId}")
    @Operation(summary = "Get user details",
               description = "Get detailed information about a specific user")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<AdminUserDetailDto> getUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId) {
        verifyAdminAccess(authHeader);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        AdminUserDetailDto dto = mapToAdminUserDetailDto(user);
        return ResponseEntity.ok(dto);
    }

    @PostMapping("/users/{userId}/suspend")
    @Operation(summary = "Suspend a user",
               description = "Suspend a user account. Terminates all active sessions.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User suspended successfully"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> suspendUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId,
            @Valid @RequestBody SuspendUserRequest request) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} suspending user {} with reason: {}", adminId, userId, request.getReason());

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setStatus(AuthStatus.SUSPENDED);
        authUserRepository.save(user);

        // Terminate all sessions
        sessionManagementService.terminateAllUserSessions(userId, "Account suspended: " + request.getReason());

        return ResponseEntity.ok(Map.of(
                "message", "User suspended successfully",
                "userId", userId.toString()
        ));
    }

    @PostMapping("/users/{userId}/activate")
    @Operation(summary = "Activate a user",
               description = "Activate a suspended or inactive user account")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> activateUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} activating user {}", adminId, userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setStatus(AuthStatus.ACTIVE);
        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        authUserRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "User activated successfully",
                "userId", userId.toString()
        ));
    }

    @PostMapping("/users/{userId}/lock")
    @Operation(summary = "Lock a user account",
               description = "Temporarily lock a user account for a specified duration")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> lockUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId,
            @Valid @RequestBody LockUserRequest request) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} locking user {} for {} hours", adminId, userId, request.getLockHours());

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        int lockHours = request.getLockHours() != null ? request.getLockHours() : 24;
        user.setLockedUntil(Instant.now().plus(lockHours, ChronoUnit.HOURS));
        authUserRepository.save(user);

        // Terminate all sessions
        sessionManagementService.terminateAllUserSessions(userId, "Account locked: " + request.getReason());

        return ResponseEntity.ok(Map.of(
                "message", "User account locked",
                "userId", userId.toString(),
                "lockedUntil", user.getLockedUntil().toString()
        ));
    }

    @PostMapping("/users/{userId}/unlock")
    @Operation(summary = "Unlock a user account",
               description = "Remove lock from a user account")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> unlockUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} unlocking user {}", adminId, userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setLockedUntil(null);
        user.setFailedLoginAttempts(0);
        authUserRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "User account unlocked",
                "userId", userId.toString()
        ));
    }

    @PutMapping("/users/{userId}/status")
    @Operation(summary = "Update user status",
               description = "Update the status of a user account")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> updateUserStatus(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId,
            @Valid @RequestBody UpdateUserStatusRequest request) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} updating user {} status to: {}", adminId, userId, request.getStatus());

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setStatus(request.getStatus());
        authUserRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "User status updated",
                "userId", userId.toString(),
                "status", request.getStatus().name()
        ));
    }

    @PostMapping("/users/{userId}/force-password-change")
    @Operation(summary = "Force password change",
               description = "Force a user to change their password on next login")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> forcePasswordChange(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} forcing password change for user {}", adminId, userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setForcePasswordChange(true);
        authUserRepository.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "User will be required to change password on next login",
                "userId", userId.toString()
        ));
    }

    // ==================== Role Management ====================

    @GetMapping("/roles")
    @Operation(summary = "List all roles",
               description = "Get a list of all roles in the system")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<List<RoleDto>> listRoles(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        verifyAdminAccess(authHeader);

        List<RoleDto> roles = roleService.getAllRoles();
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/roles/{roleId}")
    @Operation(summary = "Get role details",
               description = "Get detailed information about a specific role including permissions")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<RoleWithPermissionsDto> getRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID roleId) {
        verifyAdminAccess(authHeader);

        RoleWithPermissionsDto role = roleService.getRoleWithPermissions(roleId);
        return ResponseEntity.ok(role);
    }

    @PostMapping("/roles")
    @Operation(summary = "Create a new role",
               description = "Create a new role with optional permissions")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Role created successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request or role already exists")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<RoleDto> createRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody CreateRoleRequest request) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} creating role: {}", adminId, request.getName());

        RoleDto role = roleService.createRole(request, adminId);
        return ResponseEntity.ok(role);
    }

    @PutMapping("/roles/{roleId}")
    @Operation(summary = "Update a role",
               description = "Update an existing role")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<RoleDto> updateRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID roleId,
            @Valid @RequestBody UpdateRoleRequest request) {
        verifyAdminAccess(authHeader);
        log.info("Updating role: {}", roleId);

        RoleDto role = roleService.updateRole(roleId, request);
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/roles/{roleId}")
    @Operation(summary = "Delete a role",
               description = "Delete a role. Role must not be assigned to any users.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Role deleted"),
        @ApiResponse(responseCode = "400", description = "Role is still in use")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> deleteRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID roleId) {
        verifyAdminAccess(authHeader);
        log.info("Deleting role: {}", roleId);

        roleService.deleteRole(roleId);
        return ResponseEntity.ok(Map.of("message", "Role deleted successfully"));
    }

    // ==================== Role Permissions ====================

    @PostMapping("/roles/{roleId}/permissions")
    @Operation(summary = "Add permissions to role",
               description = "Add one or more permissions to a role")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<RoleWithPermissionsDto> addPermissionsToRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID roleId,
            @RequestBody Set<UUID> permissionIds) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} adding {} permissions to role {}", adminId, permissionIds.size(), roleId);

        roleService.assignPermissionsToRole(roleId, permissionIds, adminId);

        RoleWithPermissionsDto role = roleService.getRoleWithPermissions(roleId);
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/roles/{roleId}/permissions/{permissionId}")
    @Operation(summary = "Remove permission from role",
               description = "Remove a permission from a role")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> removePermissionFromRole(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID roleId,
            @PathVariable UUID permissionId) {
        verifyAdminAccess(authHeader);
        log.info("Removing permission {} from role {}", permissionId, roleId);

        roleService.removePermissionFromRole(roleId, permissionId);
        return ResponseEntity.ok(Map.of("message", "Permission removed from role"));
    }

    // ==================== User Roles ====================

    @GetMapping("/users/{userId}/roles")
    @Operation(summary = "Get user roles",
               description = "Get all roles assigned to a user")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<UserRolesResponse> getUserRoles(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId) {
        verifyAdminAccess(authHeader);

        List<UserRoleDto> roles = roleService.getUserRoles(userId);
        UserPermissionsDto permissions = roleService.getUserPermissions(userId);

        return ResponseEntity.ok(UserRolesResponse.builder()
                .userId(userId)
                .roles(roles)
                .permissions(permissions.getPermissions())
                .build());
    }

    @PostMapping("/users/{userId}/roles")
    @Operation(summary = "Assign role to user",
               description = "Assign a role to a user")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<UserRoleDto> assignRoleToUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId,
            @Valid @RequestBody AdminAssignRoleRequest request) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} assigning role {} to user {}", adminId, request.getRoleId(), userId);

        AssignRoleRequest assignRequest = AssignRoleRequest.builder()
                .userId(userId)
                .roleId(request.getRoleId())
                .expiresAt(request.getExpiresAt())
                .build();

        UserRoleDto result = roleService.assignRoleToUser(assignRequest, adminId);
        return ResponseEntity.ok(result);
    }

    @DeleteMapping("/users/{userId}/roles/{roleId}")
    @Operation(summary = "Revoke role from user",
               description = "Remove a role from a user")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> revokeRoleFromUser(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID userId,
            @PathVariable UUID roleId) {
        UUID adminId = verifyAdminAccess(authHeader);
        log.info("Admin {} revoking role {} from user {}", adminId, roleId, userId);

        roleService.revokeRoleFromUser(userId, roleId);

        return ResponseEntity.ok(Map.of(
                "message", "Role revoked successfully",
                "userId", userId.toString(),
                "roleId", roleId.toString()
        ));
    }

    // ==================== Permission Management ====================

    @GetMapping("/permissions")
    @Operation(summary = "List all permissions",
               description = "Get a list of all permissions in the system")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<List<PermissionDto>> listPermissions(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @RequestParam(required = false) String resource) {
        verifyAdminAccess(authHeader);

        List<PermissionDto> permissions;
        if (resource != null && !resource.isBlank()) {
            permissions = permissionService.getPermissionsByResource(resource);
        } else {
            permissions = permissionService.getAllPermissions();
        }

        return ResponseEntity.ok(permissions);
    }

    @GetMapping("/permissions/{permissionId}")
    @Operation(summary = "Get permission details",
               description = "Get detailed information about a specific permission")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<PermissionDto> getPermission(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID permissionId) {
        verifyAdminAccess(authHeader);

        PermissionDto permission = permissionService.getPermission(permissionId);
        return ResponseEntity.ok(permission);
    }

    @PostMapping("/permissions")
    @Operation(summary = "Create a new permission",
               description = "Create a new permission")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Permission created"),
        @ApiResponse(responseCode = "400", description = "Permission already exists")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<PermissionDto> createPermission(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody CreatePermissionRequest request) {
        verifyAdminAccess(authHeader);
        log.info("Creating permission: {}:{}", request.getResource(), request.getAction());

        PermissionDto permission = permissionService.createPermission(request);
        return ResponseEntity.ok(permission);
    }

    @DeleteMapping("/permissions/{permissionId}")
    @Operation(summary = "Delete a permission",
               description = "Delete a permission. Permission must not be assigned to any roles.")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> deletePermission(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @PathVariable UUID permissionId) {
        verifyAdminAccess(authHeader);
        log.info("Deleting permission: {}", permissionId);

        permissionService.deletePermission(permissionId);
        return ResponseEntity.ok(Map.of("message", "Permission deleted successfully"));
    }

    // ==================== Statistics ====================

    @GetMapping("/stats")
    @Operation(summary = "Get admin statistics",
               description = "Get system-wide statistics for administrative overview")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<AdminStatsResponse> getAdminStats(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        verifyAdminAccess(authHeader);

        long totalUsers = authUserRepository.count();

        return ResponseEntity.ok(AdminStatsResponse.builder()
                .totalUsers(totalUsers)
                .totalRoles(roleService.getAllRoles().size())
                .totalPermissions(permissionService.getAllPermissions().size())
                .build());
    }

    // ==================== Helper Methods ====================

    private UUID verifyAdminAccess(String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);
        UUID userUuid = UUID.fromString(userId);

        // Check if user has admin permission
        if (!roleService.userHasPermission(userUuid, "admin", "access")) {
            throw new RuntimeException("Admin access required");
        }

        return userUuid;
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }

    private AdminUserDto mapToAdminUserDto(AuthUser user) {
        return AdminUserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .status(user.getStatus())
                .emailVerified(user.isEmailVerified())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .locked(user.isLocked())
                .lockedUntil(user.getLockedUntil())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }

    private AdminUserDetailDto mapToAdminUserDetailDto(AuthUser user) {
        List<UserRoleDto> roles = roleService.getUserRoles(user.getId());

        return AdminUserDetailDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .externalId(user.getExternalId())
                .status(user.getStatus())
                .emailVerified(user.isEmailVerified())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .locked(user.isLocked())
                .lockedUntil(user.getLockedUntil())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .forcePasswordChange(user.isForcePasswordChange())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .lastLoginIp(user.getLastLoginIp())
                .passwordChangedAt(user.getPasswordChangedAt())
                .roles(roles)
                .build();
    }

    // ==================== Request/Response DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class SuspendUserRequest {
        @NotBlank
        private String reason;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class LockUserRequest {
        @NotBlank
        private String reason;
        private Integer lockHours; // Default 24 hours
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class UpdateUserStatusRequest {
        @NotNull
        private AuthStatus status;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AdminAssignRoleRequest {
        @NotNull
        private UUID roleId;
        private Instant expiresAt;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AdminUserDto {
        private UUID id;
        private String email;
        private AuthStatus status;
        private boolean emailVerified;
        private boolean twoFactorEnabled;
        private boolean locked;
        private Instant lockedUntil;
        private Instant createdAt;
        private Instant lastLoginAt;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AdminUserDetailDto {
        private UUID id;
        private String email;
        private String externalId;
        private AuthStatus status;
        private boolean emailVerified;
        private boolean twoFactorEnabled;
        private boolean locked;
        private Instant lockedUntil;
        private int failedLoginAttempts;
        private boolean forcePasswordChange;
        private Instant createdAt;
        private Instant updatedAt;
        private Instant lastLoginAt;
        private String lastLoginIp;
        private Instant passwordChangedAt;
        private List<UserRoleDto> roles;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class UserRolesResponse {
        private UUID userId;
        private List<UserRoleDto> roles;
        private Set<String> permissions;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AdminStatsResponse {
        private long totalUsers;
        private int totalRoles;
        private int totalPermissions;
    }
}
