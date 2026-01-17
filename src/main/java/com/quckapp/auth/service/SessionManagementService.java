package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.SessionDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for Session management operations
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class SessionManagementService implements SessionManagementOperations {

    private final ActiveSessionRepository sessionRepository;
    private final SessionActivityRepository activityRepository;
    private final AuthUserRepository authUserRepository;
    private final UserSecurityPreferencesRepository securityPreferencesRepository;
    private final PasswordEncoder passwordEncoder;

    // ==================== Session Creation ====================

    public ActiveSessionDto createSession(UUID userId, CreateSessionRequest request) {
        log.info("Creating session for user: {}", userId);

        AuthUser user = authUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        // Check max concurrent sessions
        int currentSessions = sessionRepository.countActiveSessionsByUserId(userId);
        int maxSessions = getMaxConcurrentSessions(userId);

        if (currentSessions >= maxSessions) {
            log.warn("User {} has reached max concurrent sessions ({})", userId, maxSessions);
            // Optionally: terminate oldest session or throw error
            terminateOldestSession(userId);
        }

        // Hash the session token
        String tokenHash = passwordEncoder.encode(request.getSessionToken());

        ActiveSession session = ActiveSession.builder()
                .id(request.getSessionId())  // Use session ID from JWT token
                .user(user)
                .sessionTokenHash(tokenHash)
                .deviceId(request.getDeviceId())
                .deviceName(request.getDeviceName())
                .deviceType(request.getDeviceType() != null ? request.getDeviceType() : "UNKNOWN")
                .osName(request.getOsName())
                .osVersion(request.getOsVersion())
                .browserName(request.getBrowserName())
                .browserVersion(request.getBrowserVersion())
                .ipAddress(request.getIpAddress())
                .country(request.getCountry())
                .city(request.getCity())
                .latitude(request.getLatitude())
                .longitude(request.getLongitude())
                .isActive(true)
                .isTrusted(false)
                .lastActivityAt(Instant.now())
                .expiresAt(Instant.now().plus(request.getExpiryMinutes(), ChronoUnit.MINUTES))
                .build();

        session = sessionRepository.save(session);

        // Log activity
        logActivity(session, SessionActivityType.SESSION_CREATED, request.getIpAddress(), request.getUserAgent(), null);

        log.info("Session created successfully: {}", session.getId());
        return ActiveSessionDto.from(session);
    }

    // ==================== Session Retrieval ====================

    @Transactional(readOnly = true)
    public ActiveSessionDto getSession(UUID sessionId) {
        ActiveSession session = findSessionOrThrow(sessionId);
        return ActiveSessionDto.from(session);
    }

    @Transactional(readOnly = true)
    public Optional<ActiveSessionDto> getSessionByToken(String tokenHash) {
        return sessionRepository.findBySessionTokenHash(tokenHash)
                .map(ActiveSessionDto::from);
    }

    @Transactional(readOnly = true)
    public UserSessionsResponse getUserSessions(UUID userId, UUID currentSessionId) {
        List<ActiveSession> sessions = sessionRepository.findByUserId(userId);
        List<ActiveSession> activeSessions = sessionRepository.findActiveByUserId(userId);

        List<ActiveSessionDto> sessionDtos = sessions.stream()
                .map(s -> {
                    ActiveSessionDto dto = ActiveSessionDto.from(s);
                    if (currentSessionId != null && s.getId().equals(currentSessionId)) {
                        dto.markAsCurrent();
                    }
                    return dto;
                })
                .collect(Collectors.toList());

        return UserSessionsResponse.builder()
                .userId(userId)
                .totalSessions(sessions.size())
                .activeSessions(activeSessions.size())
                .sessions(sessionDtos)
                .currentSessionId(currentSessionId)
                .build();
    }

    @Transactional(readOnly = true)
    public List<ActiveSessionDto> getActiveSessions(UUID userId) {
        return sessionRepository.findActiveByUserId(userId).stream()
                .map(ActiveSessionDto::from)
                .collect(Collectors.toList());
    }

    // ==================== Session Validation ====================

    @Transactional(readOnly = true)
    public boolean isSessionValid(UUID sessionId) {
        return sessionRepository.findById(sessionId)
                .map(ActiveSession::isValid)
                .orElse(false);
    }

    @Transactional(readOnly = true)
    public boolean isSessionValid(String tokenHash) {
        return sessionRepository.findValidBySessionTokenHash(tokenHash).isPresent();
    }

    // ==================== Session Updates ====================

    public void updateSessionActivity(UUID sessionId, String ipAddress, String userAgent) {
        log.debug("Updating activity for session: {}", sessionId);
        sessionRepository.updateLastActivity(sessionId, Instant.now());
    }

    public void markSessionAsTrusted(UUID sessionId) {
        log.info("Marking session as trusted: {}", sessionId);
        sessionRepository.markAsTrusted(sessionId);
    }

    // ==================== Session Termination ====================

    public void terminateSession(UUID sessionId, String reason) {
        log.info("Terminating session {}: {}", sessionId, reason);
        ActiveSession session = findSessionOrThrow(sessionId);

        session.terminate();
        sessionRepository.save(session);

        // Log activity
        logActivity(session, SessionActivityType.SESSION_TERMINATED, null, null, reason);

        log.info("Session terminated: {}", sessionId);
    }

    public void terminateAllUserSessions(UUID userId, String reason) {
        log.info("Terminating all sessions for user {}: {}", userId, reason);
        int count = sessionRepository.deactivateAllUserSessions(userId);
        log.info("Terminated {} sessions for user: {}", count, userId);
    }

    public void terminateOtherSessions(UUID userId, UUID currentSessionId, String reason) {
        log.info("Terminating other sessions for user: {}", userId);
        int count = sessionRepository.deactivateOtherSessions(userId, currentSessionId);
        log.info("Terminated {} other sessions for user: {}", count, userId);
    }

    private void terminateOldestSession(UUID userId) {
        List<ActiveSession> sessions = sessionRepository.findActiveByUserId(userId);
        if (!sessions.isEmpty()) {
            sessions.sort(Comparator.comparing(ActiveSession::getCreatedAt));
            terminateSession(sessions.get(0).getId(), "Max concurrent sessions exceeded");
        }
    }

    // ==================== Session Activity ====================

    public void logActivity(ActiveSession session, SessionActivityType activityType,
                          String ipAddress, String userAgent, String details) {
        SessionActivity activity = SessionActivity.builder()
                .session(session)
                .activityType(activityType)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .details(details)
                .build();

        activityRepository.save(activity);
    }

    @Transactional(readOnly = true)
    public List<SessionActivityDto> getSessionActivities(UUID sessionId) {
        return activityRepository.findBySessionIdOrderByCreatedAtDesc(sessionId).stream()
                .map(SessionActivityDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Page<SessionActivityDto> getUserActivities(UUID userId, Pageable pageable) {
        return activityRepository.findByUserId(userId, pageable)
                .map(SessionActivityDto::from);
    }

    // ==================== Maintenance ====================

    public int cleanupExpiredSessions() {
        log.info("Cleaning up expired sessions");
        int deactivated = sessionRepository.deactivateExpiredSessions();
        log.info("Deactivated {} expired sessions", deactivated);
        return deactivated;
    }

    public int deleteOldSessions(int daysOld) {
        Instant threshold = Instant.now().minus(daysOld, ChronoUnit.DAYS);
        log.info("Deleting sessions older than {} days", daysOld);
        int deleted = sessionRepository.deleteExpiredSessions(threshold);
        log.info("Deleted {} old sessions", deleted);
        return deleted;
    }

    public int deleteOldActivities(int daysOld) {
        Instant threshold = Instant.now().minus(daysOld, ChronoUnit.DAYS);
        log.info("Deleting session activities older than {} days", daysOld);
        int deleted = activityRepository.deleteOlderThan(threshold);
        log.info("Deleted {} old session activities", deleted);
        return deleted;
    }

    // ==================== Statistics ====================

    @Transactional(readOnly = true)
    public SessionStatisticsDto getStatistics() {
        Instant last24h = Instant.now().minus(24, ChronoUnit.HOURS);

        Map<String, Long> byDeviceType = sessionRepository.countActiveSessionsByDeviceType().stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));

        Map<String, Long> byCountry = sessionRepository.countActiveSessionsByCountry().stream()
                .limit(10)
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));

        return SessionStatisticsDto.builder()
                .totalActiveSessions(sessionRepository.count())
                .activeUsersLast24h(sessionRepository.countActiveUsersInPeriod(last24h))
                .sessionsByDeviceType(byDeviceType)
                .sessionsByCountry(byCountry)
                .build();
    }

    @Transactional(readOnly = true)
    public int countActiveSessions(UUID userId) {
        return sessionRepository.countActiveSessionsByUserId(userId);
    }

    // ==================== Helper Methods ====================

    private ActiveSession findSessionOrThrow(UUID sessionId) {
        return sessionRepository.findById(sessionId)
                .orElseThrow(() -> new RuntimeException("Session not found: " + sessionId));
    }

    private int getMaxConcurrentSessions(UUID userId) {
        return securityPreferencesRepository.findByUserId(userId)
                .map(UserSecurityPreferences::getMaxConcurrentSessions)
                .orElse(5); // Default max sessions
    }
}
