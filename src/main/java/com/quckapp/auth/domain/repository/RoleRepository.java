package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Repository for Role entity operations
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByName(String name);

    boolean existsByName(String name);

    List<Role> findByIsActiveTrue();

    List<Role> findByIsSystemRoleTrue();

    List<Role> findByIsActiveTrueOrderByPriorityDesc();

    @Query("SELECT r FROM Role r WHERE r.name IN :names AND r.isActive = true")
    List<Role> findByNameIn(@Param("names") Set<String> names);

    @Query("SELECT r FROM Role r JOIN FETCH r.rolePermissions rp JOIN FETCH rp.permission WHERE r.id = :id")
    Optional<Role> findByIdWithPermissions(@Param("id") UUID id);

    @Query("SELECT r FROM Role r JOIN FETCH r.rolePermissions rp JOIN FETCH rp.permission WHERE r.name = :name")
    Optional<Role> findByNameWithPermissions(@Param("name") String name);

    @Query("SELECT DISTINCT r FROM Role r " +
           "JOIN r.userRoles ur " +
           "WHERE ur.user.id = :userId AND ur.isActive = true " +
           "AND (ur.expiresAt IS NULL OR ur.expiresAt > CURRENT_TIMESTAMP)")
    List<Role> findActiveRolesByUserId(@Param("userId") UUID userId);

    @Query("SELECT COUNT(ur) FROM UserRoleAssignment ur WHERE ur.role.id = :roleId AND ur.isActive = true")
    long countActiveUsersByRoleId(@Param("roleId") UUID roleId);
}
