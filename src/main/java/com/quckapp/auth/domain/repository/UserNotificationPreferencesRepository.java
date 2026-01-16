package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.UserNotificationPreferences;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for UserNotificationPreferences entity operations
 */
@Repository
public interface UserNotificationPreferencesRepository extends JpaRepository<UserNotificationPreferences, UUID> {

    Optional<UserNotificationPreferences> findByUserId(UUID userId);

    boolean existsByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM UserNotificationPreferences unp WHERE unp.user.id = :userId")
    int deleteByUserId(@Param("userId") UUID userId);

    // Find users with specific notification preferences enabled
    @Query("SELECT unp.user.id FROM UserNotificationPreferences unp WHERE unp.emailSecurityAlerts = true")
    List<UUID> findUserIdsWithSecurityAlertsEnabled();

    @Query("SELECT unp.user.id FROM UserNotificationPreferences unp WHERE unp.emailLoginAlerts = true")
    List<UUID> findUserIdsWithLoginAlertsEnabled();

    @Query("SELECT unp.user.id FROM UserNotificationPreferences unp WHERE unp.pushSystemAlerts = true")
    List<UUID> findUserIdsWithPushSystemAlertsEnabled();

    @Query("SELECT unp.user.id FROM UserNotificationPreferences unp WHERE unp.smsEnabled = true")
    List<UUID> findUserIdsWithSmsEnabled();

    // Find users who can receive notifications (not in quiet hours would be checked in service layer)
    @Query("SELECT unp FROM UserNotificationPreferences unp WHERE unp.user.id IN :userIds")
    List<UserNotificationPreferences> findByUserIdIn(@Param("userIds") List<UUID> userIds);

    // Update specific preferences
    @Modifying
    @Query("UPDATE UserNotificationPreferences unp SET unp.emailMarketing = :enabled WHERE unp.user.id = :userId")
    int updateEmailMarketing(@Param("userId") UUID userId, @Param("enabled") boolean enabled);

    @Modifying
    @Query("UPDATE UserNotificationPreferences unp SET unp.pushDirectMessages = :enabled WHERE unp.user.id = :userId")
    int updatePushDirectMessages(@Param("userId") UUID userId, @Param("enabled") boolean enabled);

    @Modifying
    @Query("UPDATE UserNotificationPreferences unp SET unp.quietHoursEnabled = :enabled WHERE unp.user.id = :userId")
    int updateQuietHoursEnabled(@Param("userId") UUID userId, @Param("enabled") boolean enabled);
}
