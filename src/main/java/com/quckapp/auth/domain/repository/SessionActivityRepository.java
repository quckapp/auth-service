package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.SessionActivity;
import com.quckapp.auth.domain.entity.SessionActivityType;
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
 * Repository for SessionActivity entity operations
 */
@Repository
public interface SessionActivityRepository extends JpaRepository<SessionActivity, UUID> {

    List<SessionActivity> findBySessionId(UUID sessionId);

    Page<SessionActivity> findBySessionId(UUID sessionId, Pageable pageable);

    List<SessionActivity> findBySessionIdOrderByCreatedAtDesc(UUID sessionId);

    List<SessionActivity> findBySessionIdAndActivityType(UUID sessionId, SessionActivityType activityType);

    @Query("SELECT sa FROM SessionActivity sa " +
           "JOIN sa.session s " +
           "WHERE s.user.id = :userId " +
           "ORDER BY sa.createdAt DESC")
    Page<SessionActivity> findByUserId(@Param("userId") UUID userId, Pageable pageable);

    @Query("SELECT sa FROM SessionActivity sa " +
           "JOIN sa.session s " +
           "WHERE s.user.id = :userId AND sa.activityType = :activityType " +
           "ORDER BY sa.createdAt DESC")
    List<SessionActivity> findByUserIdAndActivityType(
            @Param("userId") UUID userId,
            @Param("activityType") SessionActivityType activityType);

    @Query("SELECT sa FROM SessionActivity sa WHERE sa.createdAt BETWEEN :start AND :end ORDER BY sa.createdAt DESC")
    List<SessionActivity> findByDateRange(@Param("start") Instant start, @Param("end") Instant end);

    @Query("SELECT sa.activityType, COUNT(sa) FROM SessionActivity sa " +
           "WHERE sa.createdAt > :since " +
           "GROUP BY sa.activityType " +
           "ORDER BY COUNT(sa) DESC")
    List<Object[]> countByActivityTypeSince(@Param("since") Instant since);

    @Modifying
    @Query("DELETE FROM SessionActivity sa WHERE sa.session.id = :sessionId")
    int deleteBySessionId(@Param("sessionId") UUID sessionId);

    @Modifying
    @Query("DELETE FROM SessionActivity sa WHERE sa.createdAt < :threshold")
    int deleteOlderThan(@Param("threshold") Instant threshold);

    @Query("SELECT COUNT(sa) FROM SessionActivity sa WHERE sa.session.id = :sessionId")
    long countBySessionId(@Param("sessionId") UUID sessionId);
}
