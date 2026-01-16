package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.LoginHistory;
import com.quckapp.auth.domain.entity.LoginMethod;
import com.quckapp.auth.domain.entity.LoginStatus;
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
 * Repository for LoginHistory entity operations
 */
@Repository
public interface LoginHistoryRepository extends JpaRepository<LoginHistory, UUID> {

    // Find by user
    List<LoginHistory> findByUserId(UUID userId);

    Page<LoginHistory> findByUserId(UUID userId, Pageable pageable);

    List<LoginHistory> findByUserIdOrderByCreatedAtDesc(UUID userId);

    Page<LoginHistory> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    // Find by email (for failed login attempts where user may not exist)
    List<LoginHistory> findByEmail(String email);

    Page<LoginHistory> findByEmailOrderByCreatedAtDesc(String email, Pageable pageable);

    // Find by status
    List<LoginHistory> findByLoginStatus(LoginStatus loginStatus);

    Page<LoginHistory> findByUserIdAndLoginStatus(UUID userId, LoginStatus loginStatus, Pageable pageable);

    // Find by IP
    List<LoginHistory> findByIpAddress(String ipAddress);

    Page<LoginHistory> findByIpAddressOrderByCreatedAtDesc(String ipAddress, Pageable pageable);

    // Find recent logins
    @Query("SELECT lh FROM LoginHistory lh WHERE lh.user.id = :userId AND lh.createdAt > :since ORDER BY lh.createdAt DESC")
    List<LoginHistory> findRecentByUserId(@Param("userId") UUID userId, @Param("since") Instant since);

    // Find last successful login
    @Query("SELECT lh FROM LoginHistory lh WHERE lh.user.id = :userId AND lh.loginStatus = 'SUCCESS' ORDER BY lh.createdAt DESC")
    List<LoginHistory> findLastSuccessfulLogin(@Param("userId") UUID userId, Pageable pageable);

    default Optional<LoginHistory> findLastSuccessfulLoginByUserId(UUID userId) {
        List<LoginHistory> results = findLastSuccessfulLogin(userId, Pageable.ofSize(1));
        return results.isEmpty() ? Optional.empty() : Optional.of(results.get(0));
    }

    // Count failed attempts
    @Query("SELECT COUNT(lh) FROM LoginHistory lh WHERE lh.email = :email AND lh.loginStatus != 'SUCCESS' AND lh.createdAt > :since")
    int countFailedAttemptsSince(@Param("email") String email, @Param("since") Instant since);

    @Query("SELECT COUNT(lh) FROM LoginHistory lh WHERE lh.ipAddress = :ip AND lh.loginStatus != 'SUCCESS' AND lh.createdAt > :since")
    int countFailedAttemptsFromIpSince(@Param("ip") String ip, @Param("since") Instant since);

    // Find suspicious logins
    @Query("SELECT lh FROM LoginHistory lh WHERE lh.user.id = :userId AND (lh.isVpn = true OR lh.isTor = true OR lh.isProxy = true OR lh.riskScore > :riskThreshold) ORDER BY lh.createdAt DESC")
    List<LoginHistory> findSuspiciousLoginsByUserId(@Param("userId") UUID userId, @Param("riskThreshold") int riskThreshold);

    @Query("SELECT lh FROM LoginHistory lh WHERE lh.riskScore > :threshold ORDER BY lh.createdAt DESC")
    Page<LoginHistory> findHighRiskLogins(@Param("threshold") int threshold, Pageable pageable);

    // Find by device
    List<LoginHistory> findByDeviceId(String deviceId);

    @Query("SELECT DISTINCT lh.deviceId FROM LoginHistory lh WHERE lh.user.id = :userId AND lh.deviceId IS NOT NULL")
    List<String> findDistinctDeviceIdsByUserId(@Param("userId") UUID userId);

    // Find by country
    List<LoginHistory> findByCountryCode(String countryCode);

    @Query("SELECT DISTINCT lh.countryCode FROM LoginHistory lh WHERE lh.user.id = :userId AND lh.countryCode IS NOT NULL")
    List<String> findDistinctCountriesByUserId(@Param("userId") UUID userId);

    // Statistics
    @Query("SELECT lh.loginStatus, COUNT(lh) FROM LoginHistory lh WHERE lh.createdAt > :since GROUP BY lh.loginStatus")
    List<Object[]> countByLoginStatusSince(@Param("since") Instant since);

    @Query("SELECT lh.loginMethod, COUNT(lh) FROM LoginHistory lh WHERE lh.createdAt > :since AND lh.loginStatus = 'SUCCESS' GROUP BY lh.loginMethod")
    List<Object[]> countSuccessfulByLoginMethodSince(@Param("since") Instant since);

    @Query("SELECT lh.countryCode, COUNT(lh) FROM LoginHistory lh WHERE lh.createdAt > :since AND lh.countryCode IS NOT NULL GROUP BY lh.countryCode ORDER BY COUNT(lh) DESC")
    List<Object[]> countByCountrySince(@Param("since") Instant since);

    @Query("SELECT DATE(lh.createdAt), COUNT(lh) FROM LoginHistory lh WHERE lh.createdAt > :since GROUP BY DATE(lh.createdAt) ORDER BY DATE(lh.createdAt)")
    List<Object[]> countDailyLoginsSince(@Param("since") Instant since);

    // Cleanup
    @Modifying
    @Query("DELETE FROM LoginHistory lh WHERE lh.createdAt < :threshold")
    int deleteOlderThan(@Param("threshold") Instant threshold);

    @Query("SELECT COUNT(lh) FROM LoginHistory lh WHERE lh.user.id = :userId")
    long countByUserId(@Param("userId") UUID userId);
}
