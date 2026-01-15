package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.AnomalySeverity;
import com.quckapp.auth.domain.entity.AnomalyType;
import com.quckapp.auth.domain.entity.LoginAnomaly;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Repository for LoginAnomaly entity operations
 */
@Repository
public interface LoginAnomalyRepository extends JpaRepository<LoginAnomaly, UUID> {

    // Find by user
    List<LoginAnomaly> findByUserId(UUID userId);

    Page<LoginAnomaly> findByUserId(UUID userId, Pageable pageable);

    List<LoginAnomaly> findByUserIdOrderByCreatedAtDesc(UUID userId);

    // Find unresolved anomalies
    List<LoginAnomaly> findByUserIdAndIsResolvedFalse(UUID userId);

    Page<LoginAnomaly> findByIsResolvedFalseOrderByCreatedAtDesc(Pageable pageable);

    @Query("SELECT la FROM LoginAnomaly la WHERE la.isResolved = false AND la.severity = :severity ORDER BY la.createdAt DESC")
    List<LoginAnomaly> findUnresolvedBySeverity(@Param("severity") AnomalySeverity severity);

    // Find by type
    List<LoginAnomaly> findByAnomalyType(AnomalyType anomalyType);

    Page<LoginAnomaly> findByAnomalyTypeAndIsResolvedFalse(AnomalyType anomalyType, Pageable pageable);

    // Find by severity
    List<LoginAnomaly> findBySeverity(AnomalySeverity severity);

    @Query("SELECT la FROM LoginAnomaly la WHERE la.severity IN ('HIGH', 'CRITICAL') AND la.isResolved = false ORDER BY la.createdAt DESC")
    List<LoginAnomaly> findCriticalUnresolved();

    // Find by login history
    List<LoginAnomaly> findByLoginHistoryId(UUID loginHistoryId);

    // Count anomalies
    @Query("SELECT COUNT(la) FROM LoginAnomaly la WHERE la.user.id = :userId AND la.isResolved = false")
    int countUnresolvedByUserId(@Param("userId") UUID userId);

    @Query("SELECT COUNT(la) FROM LoginAnomaly la WHERE la.isResolved = false")
    long countAllUnresolved();

    @Query("SELECT COUNT(la) FROM LoginAnomaly la WHERE la.isResolved = false AND la.severity = :severity")
    long countUnresolvedBySeverity(@Param("severity") AnomalySeverity severity);

    // Find recent anomalies
    @Query("SELECT la FROM LoginAnomaly la WHERE la.user.id = :userId AND la.createdAt > :since ORDER BY la.createdAt DESC")
    List<LoginAnomaly> findRecentByUserId(@Param("userId") UUID userId, @Param("since") Instant since);

    @Query("SELECT la FROM LoginAnomaly la WHERE la.createdAt > :since ORDER BY la.createdAt DESC")
    Page<LoginAnomaly> findRecentAnomalies(@Param("since") Instant since, Pageable pageable);

    // Update operations
    @Modifying
    @Query("UPDATE LoginAnomaly la SET la.isResolved = true, la.resolvedAt = :now, la.resolvedBy = :resolvedBy, la.resolutionNotes = :notes WHERE la.id = :id")
    int resolveAnomaly(
            @Param("id") UUID id,
            @Param("now") Instant now,
            @Param("resolvedBy") UUID resolvedBy,
            @Param("notes") String notes);

    @Modifying
    @Query("UPDATE LoginAnomaly la SET la.isResolved = true, la.resolvedAt = :now, la.resolvedBy = :resolvedBy WHERE la.user.id = :userId AND la.isResolved = false")
    int resolveAllForUser(@Param("userId") UUID userId, @Param("now") Instant now, @Param("resolvedBy") UUID resolvedBy);

    // Statistics
    @Query("SELECT la.anomalyType, COUNT(la) FROM LoginAnomaly la WHERE la.createdAt > :since GROUP BY la.anomalyType ORDER BY COUNT(la) DESC")
    List<Object[]> countByTypeSince(@Param("since") Instant since);

    @Query("SELECT la.severity, COUNT(la) FROM LoginAnomaly la WHERE la.isResolved = false GROUP BY la.severity")
    List<Object[]> countUnresolvedBySeverity();

    @Query("SELECT DATE(la.createdAt), COUNT(la) FROM LoginAnomaly la WHERE la.createdAt > :since GROUP BY DATE(la.createdAt) ORDER BY DATE(la.createdAt)")
    List<Object[]> countDailyAnomaliesSince(@Param("since") Instant since);

    // Cleanup
    @Modifying
    @Query("DELETE FROM LoginAnomaly la WHERE la.isResolved = true AND la.resolvedAt < :threshold")
    int deleteResolvedOlderThan(@Param("threshold") Instant threshold);
}
