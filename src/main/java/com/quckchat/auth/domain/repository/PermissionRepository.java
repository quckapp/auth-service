package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Repository for Permission entity operations
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    Optional<Permission> findByName(String name);

    boolean existsByName(String name);

    Optional<Permission> findByResourceAndAction(String resource, String action);

    List<Permission> findByIsActiveTrue();

    List<Permission> findByResource(String resource);

    @Query("SELECT DISTINCT p.resource FROM Permission p WHERE p.isActive = true ORDER BY p.resource")
    List<String> findAllResources();

    @Query("SELECT p FROM Permission p WHERE p.name IN :names")
    List<Permission> findByNameIn(@Param("names") Set<String> names);

    @Query("SELECT DISTINCT p FROM Permission p " +
           "JOIN p.rolePermissions rp " +
           "JOIN rp.role r " +
           "JOIN r.userRoles ur " +
           "WHERE ur.user.id = :userId AND ur.isActive = true " +
           "AND (ur.expiresAt IS NULL OR ur.expiresAt > CURRENT_TIMESTAMP) " +
           "AND r.isActive = true AND p.isActive = true")
    Set<Permission> findPermissionsByUserId(@Param("userId") UUID userId);

    @Query("SELECT DISTINCT p.name FROM Permission p " +
           "JOIN p.rolePermissions rp " +
           "JOIN rp.role r " +
           "JOIN r.userRoles ur " +
           "WHERE ur.user.id = :userId AND ur.isActive = true " +
           "AND (ur.expiresAt IS NULL OR ur.expiresAt > CURRENT_TIMESTAMP) " +
           "AND r.isActive = true AND p.isActive = true")
    Set<String> findPermissionNamesByUserId(@Param("userId") UUID userId);

    @Query("SELECT p FROM Permission p " +
           "JOIN p.rolePermissions rp " +
           "WHERE rp.role.id = :roleId AND p.isActive = true")
    List<Permission> findByRoleId(@Param("roleId") UUID roleId);
}
