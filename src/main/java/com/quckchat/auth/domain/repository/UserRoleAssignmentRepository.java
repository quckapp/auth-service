package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.UserRoleAssignment;
import com.quckapp.auth.domain.entity.UserRoleAssignmentId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for UserRoleAssignment entity operations
 */
@Repository
public interface UserRoleAssignmentRepository extends JpaRepository<UserRoleAssignment, UserRoleAssignmentId> {

    List<UserRoleAssignment> findByUserId(UUID userId);

    List<UserRoleAssignment> findByRoleId(UUID roleId);

    @Query("SELECT ura FROM UserRoleAssignment ura " +
           "WHERE ura.user.id = :userId AND ura.isActive = true " +
           "AND (ura.expiresAt IS NULL OR ura.expiresAt > CURRENT_TIMESTAMP)")
    List<UserRoleAssignment> findActiveByUserId(@Param("userId") UUID userId);

    @Query("SELECT ura FROM UserRoleAssignment ura " +
           "JOIN FETCH ura.role r " +
           "WHERE ura.user.id = :userId AND ura.isActive = true " +
           "AND (ura.expiresAt IS NULL OR ura.expiresAt > CURRENT_TIMESTAMP)")
    List<UserRoleAssignment> findActiveByUserIdWithRoles(@Param("userId") UUID userId);

    boolean existsByUserIdAndRoleId(UUID userId, UUID roleId);

    @Query("SELECT CASE WHEN COUNT(ura) > 0 THEN true ELSE false END FROM UserRoleAssignment ura " +
           "WHERE ura.user.id = :userId AND ura.role.id = :roleId AND ura.isActive = true " +
           "AND (ura.expiresAt IS NULL OR ura.expiresAt > CURRENT_TIMESTAMP)")
    boolean hasActiveRole(@Param("userId") UUID userId, @Param("roleId") UUID roleId);

    @Query("SELECT CASE WHEN COUNT(ura) > 0 THEN true ELSE false END FROM UserRoleAssignment ura " +
           "WHERE ura.user.id = :userId AND ura.role.name = :roleName AND ura.isActive = true " +
           "AND (ura.expiresAt IS NULL OR ura.expiresAt > CURRENT_TIMESTAMP)")
    boolean hasActiveRoleByName(@Param("userId") UUID userId, @Param("roleName") String roleName);

    @Modifying
    @Query("UPDATE UserRoleAssignment ura SET ura.isActive = false WHERE ura.user.id = :userId AND ura.role.id = :roleId")
    int deactivateUserRole(@Param("userId") UUID userId, @Param("roleId") UUID roleId);

    @Modifying
    @Query("UPDATE UserRoleAssignment ura SET ura.isActive = false WHERE ura.user.id = :userId")
    int deactivateAllUserRoles(@Param("userId") UUID userId);

    @Modifying
    @Query("DELETE FROM UserRoleAssignment ura WHERE ura.user.id = :userId")
    int deleteAllByUserId(@Param("userId") UUID userId);

    @Query("SELECT ura FROM UserRoleAssignment ura WHERE ura.expiresAt IS NOT NULL AND ura.expiresAt < :now AND ura.isActive = true")
    List<UserRoleAssignment> findExpiredAssignments(@Param("now") Instant now);

    @Modifying
    @Query("UPDATE UserRoleAssignment ura SET ura.isActive = false WHERE ura.expiresAt IS NOT NULL AND ura.expiresAt < :now AND ura.isActive = true")
    int deactivateExpiredAssignments(@Param("now") Instant now);

    @Query("SELECT COUNT(ura) FROM UserRoleAssignment ura WHERE ura.role.id = :roleId AND ura.isActive = true")
    long countActiveByRoleId(@Param("roleId") UUID roleId);
}
