package com.quckchat.auth.domain.repository;

import com.quckchat.auth.domain.entity.UserProfile;
import com.quckchat.auth.domain.entity.UserRole;
import com.quckchat.auth.domain.entity.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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
 * Repository for UserProfile entity operations
 */
@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, UUID> {

    // Find by unique identifiers
    Optional<UserProfile> findByPhoneNumber(String phoneNumber);

    Optional<UserProfile> findByUsername(String username);

    Optional<UserProfile> findByEmail(String email);

    @Query("SELECT u FROM UserProfile u JOIN u.authUser a WHERE a.externalId = :externalId")
    Optional<UserProfile> findByExternalId(@Param("externalId") String externalId);

    // Batch lookups
    List<UserProfile> findByIdIn(List<UUID> ids);

    @Query("SELECT u FROM UserProfile u JOIN u.authUser a WHERE a.externalId IN :externalIds")
    List<UserProfile> findByExternalIdIn(@Param("externalIds") List<String> externalIds);

    // Search users
    @Query("SELECT u FROM UserProfile u WHERE " +
           "(LOWER(u.username) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
           "LOWER(u.displayName) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
           "u.phoneNumber LIKE CONCAT('%', :query, '%') OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%'))) " +
           "AND u.isActive = true AND u.isBanned = false " +
           "AND (:excludeUserId IS NULL OR u.id != :excludeUserId)")
    Page<UserProfile> searchUsers(
            @Param("query") String query,
            @Param("excludeUserId") UUID excludeUserId,
            Pageable pageable);

    // Existence checks
    boolean existsByPhoneNumber(String phoneNumber);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    // Status queries
    @Query("SELECT u FROM UserProfile u WHERE u.status = :status")
    List<UserProfile> findByStatus(@Param("status") UserStatus status);

    @Query("SELECT u FROM UserProfile u WHERE u.id IN :userIds AND u.status = 'ONLINE'")
    List<UserProfile> findOnlineUsersByIds(@Param("userIds") List<UUID> userIds);

    // Role queries
    @Query("SELECT u FROM UserProfile u WHERE u.role = :role")
    List<UserProfile> findByRole(@Param("role") UserRole role);

    @Query("SELECT u FROM UserProfile u WHERE u.role IN ('ADMIN', 'SUPER_ADMIN')")
    List<UserProfile> findAdmins();

    @Query("SELECT u FROM UserProfile u WHERE u.role IN ('MODERATOR', 'ADMIN', 'SUPER_ADMIN')")
    List<UserProfile> findModerators();

    // Banned users
    @Query("SELECT u FROM UserProfile u WHERE u.isBanned = true")
    Page<UserProfile> findBannedUsers(Pageable pageable);

    // Update operations
    @Modifying
    @Query("UPDATE UserProfile u SET u.status = :status, u.lastSeen = :lastSeen WHERE u.id = :userId")
    int updateStatus(
            @Param("userId") UUID userId,
            @Param("status") UserStatus status,
            @Param("lastSeen") Instant lastSeen);

    @Modifying
    @Query("UPDATE UserProfile u SET u.lastSeen = :lastSeen WHERE u.id = :userId")
    int updateLastSeen(@Param("userId") UUID userId, @Param("lastSeen") Instant lastSeen);

    @Modifying
    @Query("UPDATE UserProfile u SET u.isBanned = true, u.banReason = :reason, " +
           "u.bannedAt = :bannedAt, u.bannedBy = :bannedBy WHERE u.id = :userId")
    int banUser(
            @Param("userId") UUID userId,
            @Param("reason") String reason,
            @Param("bannedAt") Instant bannedAt,
            @Param("bannedBy") UUID bannedBy);

    @Modifying
    @Query("UPDATE UserProfile u SET u.isBanned = false, u.banReason = null, " +
           "u.bannedAt = null, u.bannedBy = null WHERE u.id = :userId")
    int unbanUser(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE UserProfile u SET u.role = :role WHERE u.id = :userId")
    int updateRole(@Param("userId") UUID userId, @Param("role") UserRole role);

    @Modifying
    @Query("UPDATE UserProfile u SET u.isVerified = :verified WHERE u.id = :userId")
    int updateVerificationStatus(@Param("userId") UUID userId, @Param("verified") boolean verified);

    // Statistics
    @Query("SELECT COUNT(u) FROM UserProfile u WHERE u.isActive = true")
    long countActiveUsers();

    @Query("SELECT COUNT(u) FROM UserProfile u WHERE u.status = 'ONLINE'")
    long countOnlineUsers();

    @Query("SELECT COUNT(u) FROM UserProfile u WHERE u.isBanned = true")
    long countBannedUsers();

    @Query("SELECT u.role, COUNT(u) FROM UserProfile u GROUP BY u.role")
    List<Object[]> countByRole();
}
