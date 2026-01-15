package com.quckapp.auth.dto;

import com.quckapp.auth.domain.entity.Permission;
import com.quckapp.auth.domain.entity.Role;
import com.quckapp.auth.domain.entity.UserRoleAssignment;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * DTOs for Role-Based Access Control operations
 */
public class RbacDtos {

    // ==================== Role DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RoleDto {
        private UUID id;
        private String name;
        private String description;
        private boolean systemRole;
        private boolean active;
        private int priority;
        private Instant createdAt;
        private Instant updatedAt;

        public static RoleDto from(Role role) {
            return RoleDto.builder()
                    .id(role.getId())
                    .name(role.getName())
                    .description(role.getDescription())
                    .systemRole(role.isSystemRole())
                    .active(role.isActive())
                    .priority(role.getPriority())
                    .createdAt(role.getCreatedAt())
                    .updatedAt(role.getUpdatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RoleWithPermissionsDto {
        private UUID id;
        private String name;
        private String description;
        private boolean systemRole;
        private boolean active;
        private int priority;
        private List<PermissionDto> permissions;
        private Instant createdAt;
        private Instant updatedAt;

        public static RoleWithPermissionsDto from(Role role) {
            return RoleWithPermissionsDto.builder()
                    .id(role.getId())
                    .name(role.getName())
                    .description(role.getDescription())
                    .systemRole(role.isSystemRole())
                    .active(role.isActive())
                    .priority(role.getPriority())
                    .permissions(role.getRolePermissions().stream()
                            .map(rp -> PermissionDto.from(rp.getPermission()))
                            .collect(Collectors.toList()))
                    .createdAt(role.getCreatedAt())
                    .updatedAt(role.getUpdatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CreateRoleRequest {
        private String name;
        private String description;
        private int priority;
        private Set<UUID> permissionIds;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateRoleRequest {
        private String description;
        private Integer priority;
        private Boolean active;
    }

    // ==================== Permission DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PermissionDto {
        private UUID id;
        private String name;
        private String description;
        private String resource;
        private String action;
        private boolean active;
        private Instant createdAt;

        public static PermissionDto from(Permission permission) {
            return PermissionDto.builder()
                    .id(permission.getId())
                    .name(permission.getName())
                    .description(permission.getDescription())
                    .resource(permission.getResource())
                    .action(permission.getAction())
                    .active(permission.isActive())
                    .createdAt(permission.getCreatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CreatePermissionRequest {
        private String name;
        private String description;
        private String resource;
        private String action;
    }

    // ==================== User Role Assignment DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserRoleDto {
        private UUID userId;
        private UUID roleId;
        private String roleName;
        private int rolePriority;
        private Instant assignedAt;
        private UUID assignedBy;
        private Instant expiresAt;
        private boolean active;

        public static UserRoleDto from(UserRoleAssignment assignment) {
            return UserRoleDto.builder()
                    .userId(assignment.getUser().getId())
                    .roleId(assignment.getRole().getId())
                    .roleName(assignment.getRole().getName())
                    .rolePriority(assignment.getRole().getPriority())
                    .assignedAt(assignment.getAssignedAt())
                    .assignedBy(assignment.getAssignedBy())
                    .expiresAt(assignment.getExpiresAt())
                    .active(assignment.isActive())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AssignRoleRequest {
        private UUID userId;
        private UUID roleId;
        private Instant expiresAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserPermissionsDto {
        private UUID userId;
        private Set<String> roles;
        private Set<String> permissions;
    }
}
