package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.ActiveSession;
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
 * Repository for ActiveSession entity operations
 */
@Repository
public interface ActiveSessionRepository extends JpaRepository<ActiveSession, UUID> {

    // Find by user
    List<ActiveSession> findByUserId(UUID userId);

    @Query("SELECT s FROM ActiveSession s WHERE s.user.id = :userId AND s.isActive = true AND s.expiresAt > CURRENT_TIMESTAMP")
    List<ActiveSession> findActiveByUserId(@Param("userId") UUID userId);

    // Find by token
    Optional<ActiveSession> findBySessionTokenHash(String sessionTokenHash);

    @Query("SELECT s FROM ActiveSession s WHERE s.sessionTokenHash = :tokenHash AND s.isActive = true AND s.expiresAt > CURRENT_TIMESTAMP")
    Optional<ActiveSession> findValidBySessionTokenHash(@Param("tokenHash") String tokenHash);

    // Find by device
    Optional<ActiveSession> findByUserIdAndDeviceId(UUID userId, String deviceId);

    @Query("SELECT s FROM ActiveSession s WHERE s.user.id = :userId AND s.deviceId = :deviceId AND s.isActive = true")
    Optional<ActiveSession> findActiveByUserIdAndDeviceId(@Param("userId") UUID userId, @Param("deviceId") String deviceId);

    // Count sessions
    @Query("SELECT COUNT(s) FROM ActiveSession s WHERE s.user.id = :userId AND s.isActive = true AND s.expiresAt > CURRENT_TIMESTAMP")
    int countActiveSessionsByUserId(@Param("userId") UUID userId);

    // Check existence
    boolean existsByUserIdAndDeviceId(UUID userId, String deviceId);

    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END FROM ActiveSession s " +
           "WHERE s.user.id = :userId AND s.deviceId = :deviceId AND s.isActive = true AND s.expiresAt > CURRENT_TIMESTAMP")
    boolean hasActiveSession(@Param("userId") UUID userId, @Param("deviceId") String deviceId);

    // Update operations
    @Modifying
    @Query("UPDATE ActiveSession s SET s.lastActivityAt = :now WHERE s.id = :sessionId")
    int updateLastActivity(@Param("sessionId") UUID sessionId, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.isActive = false WHERE s.id = :sessionId")
    int deactivateSession(@Param("sessionId") UUID sessionId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.isActive = false WHERE s.user.id = :userId")
    int deactivateAllUserSessions(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.isActive = false WHERE s.user.id = :userId AND s.id != :excludeSessionId")
    int deactivateOtherSessions(@Param("userId") UUID userId, @Param("excludeSessionId") UUID excludeSessionId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.isTrusted = true WHERE s.id = :sessionId")
    int markAsTrusted(@Param("sessionId") UUID sessionId);

    // Cleanup expired sessions
    @Query("SELECT s FROM ActiveSession s WHERE s.expiresAt < :now OR (s.isActive = false AND s.lastActivityAt < :threshold)")
    List<ActiveSession> findExpiredOrInactiveSessions(@Param("now") Instant now, @Param("threshold") Instant threshold);

    @Modifying
    @Query("DELETE FROM ActiveSession s WHERE s.expiresAt < :threshold")
    int deleteExpiredSessions(@Param("threshold") Instant threshold);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.isActive = false WHERE s.expiresAt < CURRENT_TIMESTAMP AND s.isActive = true")
    int deactivateExpiredSessions();

    // Statistics
    @Query("SELECT s.deviceType, COUNT(s) FROM ActiveSession s WHERE s.isActive = true GROUP BY s.deviceType")
    List<Object[]> countActiveSessionsByDeviceType();

    @Query("SELECT s.country, COUNT(s) FROM ActiveSession s WHERE s.isActive = true AND s.country IS NOT NULL GROUP BY s.country ORDER BY COUNT(s) DESC")
    List<Object[]> countActiveSessionsByCountry();

    @Query("SELECT COUNT(DISTINCT s.user.id) FROM ActiveSession s WHERE s.isActive = true AND s.lastActivityAt > :since")
    long countActiveUsersInPeriod(@Param("since") Instant since);
}
