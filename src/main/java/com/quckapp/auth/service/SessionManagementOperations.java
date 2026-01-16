package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.ActiveSession;
import com.quckapp.auth.domain.entity.SessionActivityType;
import com.quckapp.auth.dto.SessionDtos.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Interface for session management operations.
 * Extracted for testability with Java 25+ Mockito compatibility.
 */
public interface SessionManagementOperations {

    // ==================== Session Creation ====================

    ActiveSessionDto createSession(UUID userId, CreateSessionRequest request);

    // ==================== Session Retrieval ====================

    ActiveSessionDto getSession(UUID sessionId);

    Optional<ActiveSessionDto> getSessionByToken(String tokenHash);

    UserSessionsResponse getUserSessions(UUID userId, UUID currentSessionId);

    List<ActiveSessionDto> getActiveSessions(UUID userId);

    // ==================== Session Validation ====================

    boolean isSessionValid(UUID sessionId);

    boolean isSessionValid(String tokenHash);

    // ==================== Session Updates ====================

    void updateSessionActivity(UUID sessionId, String ipAddress, String userAgent);

    void markSessionAsTrusted(UUID sessionId);

    // ==================== Session Termination ====================

    void terminateSession(UUID sessionId, String reason);

    void terminateAllUserSessions(UUID userId, String reason);

    void terminateOtherSessions(UUID userId, UUID currentSessionId, String reason);

    // ==================== Session Activity ====================

    void logActivity(ActiveSession session, SessionActivityType activityType,
                    String ipAddress, String userAgent, String details);

    List<SessionActivityDto> getSessionActivities(UUID sessionId);

    Page<SessionActivityDto> getUserActivities(UUID userId, Pageable pageable);

    // ==================== Maintenance ====================

    int cleanupExpiredSessions();

    int deleteOldSessions(int daysOld);

    int deleteOldActivities(int daysOld);

    // ==================== Statistics ====================

    SessionStatisticsDto getStatistics();

    int countActiveSessions(UUID userId);
}
