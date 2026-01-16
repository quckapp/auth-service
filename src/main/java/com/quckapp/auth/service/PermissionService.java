package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.Permission;
import com.quckapp.auth.domain.repository.PermissionRepository;
import com.quckapp.auth.dto.RbacDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for Permission management operations
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class PermissionService {

    private final PermissionRepository permissionRepository;

    // ==================== Permission CRUD ====================

    public PermissionDto createPermission(CreatePermissionRequest request) {
        log.info("Creating permission: {}", request.getName());

        if (permissionRepository.existsByName(request.getName())) {
            throw new RuntimeException("Permission already exists: " + request.getName());
        }

        if (permissionRepository.findByResourceAndAction(request.getResource(), request.getAction()).isPresent()) {
            throw new RuntimeException("Permission for resource:action already exists: "
                    + request.getResource() + ":" + request.getAction());
        }

        Permission permission = Permission.builder()
                .name(request.getName().toLowerCase())
                .description(request.getDescription())
                .resource(request.getResource().toLowerCase())
                .action(request.getAction().toLowerCase())
                .isActive(true)
                .build();

        permission = permissionRepository.save(permission);
        log.info("Permission created successfully: {}", permission.getId());
        return PermissionDto.from(permission);
    }

    @Transactional(readOnly = true)
    public PermissionDto getPermission(UUID permissionId) {
        Permission permission = findPermissionOrThrow(permissionId);
        return PermissionDto.from(permission);
    }

    @Transactional(readOnly = true)
    public Optional<PermissionDto> getPermissionByName(String name) {
        return permissionRepository.findByName(name.toLowerCase())
                .map(PermissionDto::from);
    }

    @Transactional(readOnly = true)
    public Optional<PermissionDto> getPermissionByResourceAndAction(String resource, String action) {
        return permissionRepository.findByResourceAndAction(resource.toLowerCase(), action.toLowerCase())
                .map(PermissionDto::from);
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getAllPermissions() {
        return permissionRepository.findAll().stream()
                .map(PermissionDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getActivePermissions() {
        return permissionRepository.findByIsActiveTrue().stream()
                .map(PermissionDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getPermissionsByResource(String resource) {
        return permissionRepository.findByResource(resource.toLowerCase()).stream()
                .map(PermissionDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getPermissionsByRoleId(UUID roleId) {
        return permissionRepository.findByRoleId(roleId).stream()
                .map(PermissionDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<String> getAllResources() {
        return permissionRepository.findAllResources();
    }

    public PermissionDto updatePermission(UUID permissionId, String description, Boolean active) {
        log.info("Updating permission: {}", permissionId);
        Permission permission = findPermissionOrThrow(permissionId);

        if (description != null) {
            permission.setDescription(description);
        }
        if (active != null) {
            permission.setActive(active);
        }

        permission = permissionRepository.save(permission);
        log.info("Permission updated successfully: {}", permissionId);
        return PermissionDto.from(permission);
    }

    public void deletePermission(UUID permissionId) {
        log.info("Deleting permission: {}", permissionId);
        Permission permission = findPermissionOrThrow(permissionId);

        // Check if permission is used by any role
        if (!permission.getRolePermissions().isEmpty()) {
            throw new RuntimeException("Cannot delete permission that is assigned to roles");
        }

        permissionRepository.delete(permission);
        log.info("Permission deleted successfully: {}", permissionId);
    }

    public void deactivatePermission(UUID permissionId) {
        log.info("Deactivating permission: {}", permissionId);
        Permission permission = findPermissionOrThrow(permissionId);
        permission.setActive(false);
        permissionRepository.save(permission);
        log.info("Permission deactivated: {}", permissionId);
    }

    // ==================== Bulk Operations ====================

    public List<PermissionDto> createPermissions(List<CreatePermissionRequest> requests) {
        log.info("Creating {} permissions", requests.size());
        return requests.stream()
                .map(this::createPermission)
                .collect(Collectors.toList());
    }

    // ==================== Helper Methods ====================

    private Permission findPermissionOrThrow(UUID permissionId) {
        return permissionRepository.findById(permissionId)
                .orElseThrow(() -> new RuntimeException("Permission not found: " + permissionId));
    }
}
