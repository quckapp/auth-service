package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.UserSecurityPreferences;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for UserSecurityPreferences entity operations
 */
@Repository
public interface UserSecurityPreferencesRepository extends JpaRepository<UserSecurityPreferences, UUID> {

    Optional<UserSecurityPreferences> findByUserId(UUID userId);

    boolean existsByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM UserSecurityPreferences usp WHERE usp.user.id = :userId")
    int deleteByUserId(@Param("userId") UUID userId);

    // Find users with specific security preferences
    @Query("SELECT usp.user.id FROM UserSecurityPreferences usp WHERE usp.require2faForSensitiveActions = true")
    List<UUID> findUserIdsRequiring2faForSensitiveActions();

    @Query("SELECT usp.user.id FROM UserSecurityPreferences usp WHERE usp.ipWhitelistEnabled = true")
    List<UUID> findUserIdsWithIpWhitelistEnabled();

    @Query("SELECT usp FROM UserSecurityPreferences usp WHERE usp.passwordExpiryDays > 0")
    List<UserSecurityPreferences> findWithPasswordExpiry();

    // Find users exceeding session limits
    @Query("SELECT usp FROM UserSecurityPreferences usp WHERE usp.maxConcurrentSessions < :sessionCount")
    List<UserSecurityPreferences> findUsersExceedingSessionLimit(@Param("sessionCount") int sessionCount);

    // Update specific preferences
    @Modifying
    @Query("UPDATE UserSecurityPreferences usp SET usp.loginNotificationEnabled = :enabled WHERE usp.user.id = :userId")
    int updateLoginNotification(@Param("userId") UUID userId, @Param("enabled") boolean enabled);

    @Modifying
    @Query("UPDATE UserSecurityPreferences usp SET usp.sessionTimeoutMinutes = :timeout WHERE usp.user.id = :userId")
    int updateSessionTimeout(@Param("userId") UUID userId, @Param("timeout") int timeout);

    @Modifying
    @Query("UPDATE UserSecurityPreferences usp SET usp.maxConcurrentSessions = :maxSessions WHERE usp.user.id = :userId")
    int updateMaxConcurrentSessions(@Param("userId") UUID userId, @Param("maxSessions") int maxSessions);

    @Modifying
    @Query("UPDATE UserSecurityPreferences usp SET usp.ipWhitelistEnabled = :enabled WHERE usp.user.id = :userId")
    int updateIpWhitelistEnabled(@Param("userId") UUID userId, @Param("enabled") boolean enabled);

    @Modifying
    @Query("UPDATE UserSecurityPreferences usp SET usp.requirePasswordChangeOnNextLogin = :required WHERE usp.user.id = :userId")
    int updateRequirePasswordChange(@Param("userId") UUID userId, @Param("required") boolean required);
}
