package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.RbacDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for Role management operations
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final UserRoleAssignmentRepository userRoleAssignmentRepository;
    private final AuthUserRepository authUserRepository;

    // ==================== Role CRUD ====================

    public RoleDto createRole(CreateRoleRequest request, UUID createdBy) {
        log.info("Creating role: {}", request.getName());

        if (roleRepository.existsByName(request.getName())) {
            throw new RuntimeException("Role already exists: " + request.getName());
        }

        Role role = Role.builder()
                .name(request.getName().toUpperCase())
                .description(request.getDescription())
                .priority(request.getPriority())
                .isSystemRole(false)
                .isActive(true)
                .build();

        role = roleRepository.save(role);

        // Assign permissions if provided
        if (request.getPermissionIds() != null && !request.getPermissionIds().isEmpty()) {
            assignPermissionsToRole(role.getId(), request.getPermissionIds(), createdBy);
        }

        log.info("Role created successfully: {}", role.getId());
        return RoleDto.from(role);
    }

    @Transactional(readOnly = true)
    public RoleDto getRole(UUID roleId) {
        Role role = findRoleOrThrow(roleId);
        return RoleDto.from(role);
    }

    @Transactional(readOnly = true)
    public RoleWithPermissionsDto getRoleWithPermissions(UUID roleId) {
        Role role = roleRepository.findByIdWithPermissions(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleId));
        return RoleWithPermissionsDto.from(role);
    }

    @Transactional(readOnly = true)
    public Optional<RoleDto> getRoleByName(String name) {
        return roleRepository.findByName(name.toUpperCase())
                .map(RoleDto::from);
    }

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(RoleDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<RoleDto> getActiveRoles() {
        return roleRepository.findByIsActiveTrueOrderByPriorityDesc().stream()
                .map(RoleDto::from)
                .collect(Collectors.toList());
    }

    public RoleDto updateRole(UUID roleId, UpdateRoleRequest request) {
        log.info("Updating role: {}", roleId);
        Role role = findRoleOrThrow(roleId);

        if (role.isSystemRole()) {
            throw new RuntimeException("Cannot modify system role: " + role.getName());
        }

        if (request.getDescription() != null) {
            role.setDescription(request.getDescription());
        }
        if (request.getPriority() != null) {
            role.setPriority(request.getPriority());
        }
        if (request.getActive() != null) {
            role.setActive(request.getActive());
        }

        role = roleRepository.save(role);
        log.info("Role updated successfully: {}", roleId);
        return RoleDto.from(role);
    }

    public void deleteRole(UUID roleId) {
        log.info("Deleting role: {}", roleId);
        Role role = findRoleOrThrow(roleId);

        if (role.isSystemRole()) {
            throw new RuntimeException("Cannot delete system role: " + role.getName());
        }

        long userCount = roleRepository.countActiveUsersByRoleId(roleId);
        if (userCount > 0) {
            throw new RuntimeException("Cannot delete role with " + userCount + " active users assigned");
        }

        roleRepository.delete(role);
        log.info("Role deleted successfully: {}", roleId);
    }

    // ==================== Role Permission Management ====================

    public void assignPermissionsToRole(UUID roleId, Set<UUID> permissionIds, UUID assignedBy) {
        log.info("Assigning {} permissions to role {}", permissionIds.size(), roleId);
        Role role = findRoleOrThrow(roleId);

        List<Permission> permissions = permissionRepository.findAllById(permissionIds);
        if (permissions.size() != permissionIds.size()) {
            throw new RuntimeException("Some permissions not found");
        }

        for (Permission permission : permissions) {
            if (!rolePermissionRepository.existsByRoleIdAndPermissionId(roleId, permission.getId())) {
                RolePermission rolePermission = RolePermission.builder()
                        .role(role)
                        .permission(permission)
                        .grantedBy(assignedBy)
                        .build();
                rolePermissionRepository.save(rolePermission);
            }
        }

        log.info("Permissions assigned to role: {}", roleId);
    }

    public void removePermissionFromRole(UUID roleId, UUID permissionId) {
        log.info("Removing permission {} from role {}", permissionId, roleId);
        rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permissionId);
        log.info("Permission removed from role");
    }

    public void setRolePermissions(UUID roleId, Set<UUID> permissionIds, UUID assignedBy) {
        log.info("Setting permissions for role {}", roleId);
        Role role = findRoleOrThrow(roleId);

        // Remove existing permissions
        rolePermissionRepository.deleteAllByRoleId(roleId);

        // Assign new permissions
        if (permissionIds != null && !permissionIds.isEmpty()) {
            assignPermissionsToRole(roleId, permissionIds, assignedBy);
        }

        log.info("Permissions set for role: {}", roleId);
    }

    // ==================== User Role Assignment ====================

    public UserRoleDto assignRoleToUser(AssignRoleRequest request, UUID assignedBy) {
        log.info("Assigning role {} to user {}", request.getRoleId(), request.getUserId());

        AuthUser user = authUserRepository.findById(request.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found: " + request.getUserId()));

        Role role = findRoleOrThrow(request.getRoleId());

        if (userRoleAssignmentRepository.hasActiveRole(request.getUserId(), request.getRoleId())) {
            throw new RuntimeException("User already has this role");
        }

        UserRoleAssignment assignment = UserRoleAssignment.builder()
                .user(user)
                .role(role)
                .assignedBy(assignedBy)
                .expiresAt(request.getExpiresAt())
                .isActive(true)
                .build();

        assignment = userRoleAssignmentRepository.save(assignment);
        log.info("Role assigned to user: {}", request.getUserId());
        return UserRoleDto.from(assignment);
    }

    public void revokeRoleFromUser(UUID userId, UUID roleId) {
        log.info("Revoking role {} from user {}", roleId, userId);
        int updated = userRoleAssignmentRepository.deactivateUserRole(userId, roleId);
        if (updated == 0) {
            throw new RuntimeException("User role assignment not found");
        }
        log.info("Role revoked from user: {}", userId);
    }

    public void revokeAllRolesFromUser(UUID userId) {
        log.info("Revoking all roles from user: {}", userId);
        userRoleAssignmentRepository.deactivateAllUserRoles(userId);
        log.info("All roles revoked from user: {}", userId);
    }

    @Transactional(readOnly = true)
    public List<UserRoleDto> getUserRoles(UUID userId) {
        return userRoleAssignmentRepository.findActiveByUserIdWithRoles(userId).stream()
                .map(UserRoleDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public boolean userHasRole(UUID userId, String roleName) {
        return userRoleAssignmentRepository.hasActiveRoleByName(userId, roleName.toUpperCase());
    }

    @Transactional(readOnly = true)
    public boolean userHasAnyRole(UUID userId, Set<String> roleNames) {
        Set<String> upperNames = roleNames.stream()
                .map(String::toUpperCase)
                .collect(Collectors.toSet());

        return userRoleAssignmentRepository.findActiveByUserId(userId).stream()
                .anyMatch(ura -> upperNames.contains(ura.getRole().getName()));
    }

    // ==================== User Permissions ====================

    @Transactional(readOnly = true)
    public UserPermissionsDto getUserPermissions(UUID userId) {
        Set<String> roles = userRoleAssignmentRepository.findActiveByUserIdWithRoles(userId).stream()
                .map(ura -> ura.getRole().getName())
                .collect(Collectors.toSet());

        Set<String> permissions = permissionRepository.findPermissionNamesByUserId(userId);

        return UserPermissionsDto.builder()
                .userId(userId)
                .roles(roles)
                .permissions(permissions)
                .build();
    }

    @Transactional(readOnly = true)
    public boolean userHasPermission(UUID userId, String permissionName) {
        Set<String> permissions = permissionRepository.findPermissionNamesByUserId(userId);
        return permissions.contains(permissionName);
    }

    @Transactional(readOnly = true)
    public boolean userHasPermission(UUID userId, String resource, String action) {
        return userHasPermission(userId, resource + ":" + action);
    }

    // ==================== Maintenance ====================

    public int deactivateExpiredAssignments() {
        log.info("Deactivating expired role assignments");
        int count = userRoleAssignmentRepository.deactivateExpiredAssignments(Instant.now());
        log.info("Deactivated {} expired role assignments", count);
        return count;
    }

    // ==================== Helper Methods ====================

    private Role findRoleOrThrow(UUID roleId) {
        return roleRepository.findById(roleId)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleId));
    }
}
