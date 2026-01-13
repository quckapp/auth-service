package com.quckchat.auth.domain.repository;

import com.quckchat.auth.domain.entity.UserSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Set;
import java.util.UUID;

/**
 * Repository for UserSettings entity operations
 */
@Repository
public interface UserSettingsRepository extends JpaRepository<UserSettings, UUID> {

    // Blocked users queries
    @Query("SELECT s.blockedUserIds FROM UserSettings s WHERE s.id = :userId")
    Set<UUID> findBlockedUserIds(@Param("userId") UUID userId);

    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END " +
           "FROM UserSettings s WHERE s.id = :userId AND :targetUserId MEMBER OF s.blockedUserIds")
    boolean isUserBlocked(@Param("userId") UUID userId, @Param("targetUserId") UUID targetUserId);

    // Check if any of the users has blocked the other
    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END " +
           "FROM UserSettings s WHERE " +
           "(s.id = :userId1 AND :userId2 MEMBER OF s.blockedUserIds) OR " +
           "(s.id = :userId2 AND :userId1 MEMBER OF s.blockedUserIds)")
    boolean areUsersBlocked(@Param("userId1") UUID userId1, @Param("userId2") UUID userId2);

    // Notification settings queries
    @Query("SELECT s FROM UserSettings s WHERE s.id = :userId AND s.pushNotifications = true")
    UserSettings findIfPushNotificationsEnabled(@Param("userId") UUID userId);

    // Privacy settings queries
    @Query("SELECT s.readReceipts FROM UserSettings s WHERE s.id = :userId")
    Boolean getReadReceiptsEnabled(@Param("userId") UUID userId);

    @Query("SELECT s.lastSeenVisible FROM UserSettings s WHERE s.id = :userId")
    Boolean getLastSeenVisible(@Param("userId") UUID userId);

    // Bulk update operations
    @Modifying
    @Query("UPDATE UserSettings s SET s.pushNotifications = :enabled WHERE s.id = :userId")
    int updatePushNotifications(@Param("userId") UUID userId, @Param("enabled") boolean enabled);

    @Modifying
    @Query("UPDATE UserSettings s SET s.darkMode = :enabled WHERE s.id = :userId")
    int updateDarkMode(@Param("userId") UUID userId, @Param("enabled") boolean enabled);
}
