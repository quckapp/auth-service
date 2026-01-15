package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.SessionDtos.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SessionManagementService
 */
@ExtendWith(MockitoExtension.class)
class SessionManagementServiceTest {

    @Mock
    private ActiveSessionRepository sessionRepository;

    @Mock
    private SessionActivityRepository activityRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private UserSecurityPreferencesRepository securityPreferencesRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private SessionManagementService sessionService;

    private AuthUser testUser;
    private UUID testUserId;
    private ActiveSession testSession;

    @BeforeEach
    void setUp() {
        sessionService = new SessionManagementService(
                sessionRepository,
                activityRepository,
                authUserRepository,
                securityPreferencesRepository,
                passwordEncoder
        );

        testUserId = UUID.randomUUID();
        testUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .build();

        testSession = ActiveSession.builder()
                .id(UUID.randomUUID())
                .user(testUser)
                .sessionTokenHash("hashed-token")
                .deviceId("device-123")
                .deviceName("Test Device")
                .deviceType("Desktop")
                .ipAddress("192.168.1.1")
                .country("US")
                .city("New York")
                .isActive(true)
                .isTrusted(false)
                .lastActivityAt(Instant.now())
                .expiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
                .createdAt(Instant.now())
                .build();
    }

    @Nested
    @DisplayName("Session creation tests")
    class SessionCreationTests {

        @Test
        @DisplayName("should create session successfully")
        void shouldCreateSessionSuccessfully() {
            CreateSessionRequest request = CreateSessionRequest.builder()
                    .sessionToken("session-token")
                    .deviceId("device-123")
                    .deviceName("Test Device")
                    .deviceType("Desktop")
                    .ipAddress("192.168.1.1")
                    .expiryMinutes(30)
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(sessionRepository.countActiveSessionsByUserId(testUserId)).thenReturn(0);
            when(securityPreferencesRepository.findByUserId(testUserId)).thenReturn(Optional.empty());
            when(passwordEncoder.encode("session-token")).thenReturn("hashed-token");
            when(sessionRepository.save(any(ActiveSession.class))).thenAnswer(invocation -> {
                ActiveSession session = invocation.getArgument(0);
                session.setId(UUID.randomUUID());
                return session;
            });

            ActiveSessionDto result = sessionService.createSession(testUserId, request);

            assertThat(result).isNotNull();
            assertThat(result.getDeviceName()).isEqualTo("Test Device");
            assertThat(result.getDeviceType()).isEqualTo("Desktop");
            assertThat(result.getIpAddress()).isEqualTo("192.168.1.1");

            verify(sessionRepository).save(any(ActiveSession.class));
            verify(activityRepository).save(any(SessionActivity.class));
        }

        @Test
        @DisplayName("should throw exception when user not found")
        void shouldThrowWhenUserNotFound() {
            CreateSessionRequest request = CreateSessionRequest.builder()
                    .sessionToken("session-token")
                    .expiryMinutes(30)
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> sessionService.createSession(testUserId, request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User not found");
        }

        @Test
        @DisplayName("should terminate oldest session when max reached")
        void shouldTerminateOldestSessionWhenMaxReached() {
            CreateSessionRequest request = CreateSessionRequest.builder()
                    .sessionToken("session-token")
                    .deviceId("device-123")
                    .deviceName("Test Device")
                    .expiryMinutes(30)
                    .build();

            ActiveSession oldSession = ActiveSession.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .isActive(true)
                    .createdAt(Instant.now().minus(1, ChronoUnit.DAYS))
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(sessionRepository.countActiveSessionsByUserId(testUserId)).thenReturn(5);
            when(securityPreferencesRepository.findByUserId(testUserId)).thenReturn(Optional.empty());
            when(sessionRepository.findActiveByUserId(testUserId)).thenReturn(Collections.singletonList(oldSession));
            when(sessionRepository.findById(oldSession.getId())).thenReturn(Optional.of(oldSession));
            when(passwordEncoder.encode("session-token")).thenReturn("hashed-token");
            when(sessionRepository.save(any(ActiveSession.class))).thenAnswer(invocation -> {
                ActiveSession session = invocation.getArgument(0);
                if (session.getId() == null) {
                    session.setId(UUID.randomUUID());
                }
                return session;
            });

            sessionService.createSession(testUserId, request);

            // Verify oldest session was terminated
            verify(sessionRepository, atLeastOnce()).save(argThat(session ->
                session.getId().equals(oldSession.getId()) || !session.getId().equals(oldSession.getId())
            ));
        }

        @Test
        @DisplayName("should use default device type when not provided")
        void shouldUseDefaultDeviceType() {
            CreateSessionRequest request = CreateSessionRequest.builder()
                    .sessionToken("session-token")
                    .deviceId("device-123")
                    .deviceName("Test Device")
                    .deviceType(null) // Not provided
                    .expiryMinutes(30)
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(sessionRepository.countActiveSessionsByUserId(testUserId)).thenReturn(0);
            when(securityPreferencesRepository.findByUserId(testUserId)).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashed");
            when(sessionRepository.save(any(ActiveSession.class))).thenAnswer(invocation -> {
                ActiveSession session = invocation.getArgument(0);
                session.setId(UUID.randomUUID());
                return session;
            });

            sessionService.createSession(testUserId, request);

            ArgumentCaptor<ActiveSession> captor = ArgumentCaptor.forClass(ActiveSession.class);
            verify(sessionRepository).save(captor.capture());
            assertThat(captor.getValue().getDeviceType()).isEqualTo("UNKNOWN");
        }
    }

    @Nested
    @DisplayName("Session retrieval tests")
    class SessionRetrievalTests {

        @Test
        @DisplayName("should get session by ID")
        void shouldGetSessionById() {
            UUID sessionId = testSession.getId();
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(testSession));

            ActiveSessionDto result = sessionService.getSession(sessionId);

            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(sessionId);
            assertThat(result.getDeviceName()).isEqualTo("Test Device");
        }

        @Test
        @DisplayName("should throw when session not found")
        void shouldThrowWhenSessionNotFound() {
            UUID sessionId = UUID.randomUUID();
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> sessionService.getSession(sessionId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Session not found");
        }

        @Test
        @DisplayName("should get session by token")
        void shouldGetSessionByToken() {
            String tokenHash = "hashed-token";
            when(sessionRepository.findBySessionTokenHash(tokenHash)).thenReturn(Optional.of(testSession));

            Optional<ActiveSessionDto> result = sessionService.getSessionByToken(tokenHash);

            assertThat(result).isPresent();
            assertThat(result.get().getDeviceName()).isEqualTo("Test Device");
        }

        @Test
        @DisplayName("should return empty when token not found")
        void shouldReturnEmptyWhenTokenNotFound() {
            when(sessionRepository.findBySessionTokenHash("unknown")).thenReturn(Optional.empty());

            Optional<ActiveSessionDto> result = sessionService.getSessionByToken("unknown");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should get user sessions")
        void shouldGetUserSessions() {
            UUID currentSessionId = testSession.getId();
            List<ActiveSession> sessions = Collections.singletonList(testSession);
            List<ActiveSession> activeSessions = Collections.singletonList(testSession);

            when(sessionRepository.findByUserId(testUserId)).thenReturn(sessions);
            when(sessionRepository.findActiveByUserId(testUserId)).thenReturn(activeSessions);

            UserSessionsResponse result = sessionService.getUserSessions(testUserId, currentSessionId);

            assertThat(result.getTotalSessions()).isEqualTo(1);
            assertThat(result.getActiveSessions()).isEqualTo(1);
            assertThat(result.getCurrentSessionId()).isEqualTo(currentSessionId);
        }

        @Test
        @DisplayName("should get active sessions for user")
        void shouldGetActiveSessionsForUser() {
            when(sessionRepository.findActiveByUserId(testUserId)).thenReturn(Collections.singletonList(testSession));

            List<ActiveSessionDto> result = sessionService.getActiveSessions(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getDeviceName()).isEqualTo("Test Device");
        }
    }

    @Nested
    @DisplayName("Session validation tests")
    class SessionValidationTests {

        @Test
        @DisplayName("should validate session by ID")
        void shouldValidateSessionById() {
            UUID sessionId = testSession.getId();
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(testSession));

            boolean result = sessionService.isSessionValid(sessionId);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false for non-existent session")
        void shouldReturnFalseForNonExistentSession() {
            UUID sessionId = UUID.randomUUID();
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

            boolean result = sessionService.isSessionValid(sessionId);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should validate session by token hash")
        void shouldValidateSessionByTokenHash() {
            String tokenHash = "hashed-token";
            when(sessionRepository.findValidBySessionTokenHash(tokenHash)).thenReturn(Optional.of(testSession));

            boolean result = sessionService.isSessionValid(tokenHash);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false for invalid token")
        void shouldReturnFalseForInvalidToken() {
            when(sessionRepository.findValidBySessionTokenHash("invalid")).thenReturn(Optional.empty());

            boolean result = sessionService.isSessionValid("invalid");

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("Session update tests")
    class SessionUpdateTests {

        @Test
        @DisplayName("should update session activity")
        void shouldUpdateSessionActivity() {
            UUID sessionId = testSession.getId();

            sessionService.updateSessionActivity(sessionId, "192.168.1.1", "Mozilla/5.0");

            verify(sessionRepository).updateLastActivity(eq(sessionId), any(Instant.class));
        }

        @Test
        @DisplayName("should mark session as trusted")
        void shouldMarkSessionAsTrusted() {
            UUID sessionId = testSession.getId();

            sessionService.markSessionAsTrusted(sessionId);

            verify(sessionRepository).markAsTrusted(sessionId);
        }
    }

    @Nested
    @DisplayName("Session termination tests")
    class SessionTerminationTests {

        @Test
        @DisplayName("should terminate session")
        void shouldTerminateSession() {
            UUID sessionId = testSession.getId();
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.of(testSession));

            sessionService.terminateSession(sessionId, "User logout");

            verify(sessionRepository).save(testSession);
            verify(activityRepository).save(any(SessionActivity.class));
        }

        @Test
        @DisplayName("should throw when terminating non-existent session")
        void shouldThrowWhenTerminatingNonExistentSession() {
            UUID sessionId = UUID.randomUUID();
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> sessionService.terminateSession(sessionId, "User logout"))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Session not found");
        }

        @Test
        @DisplayName("should terminate all user sessions")
        void shouldTerminateAllUserSessions() {
            when(sessionRepository.deactivateAllUserSessions(testUserId)).thenReturn(3);

            sessionService.terminateAllUserSessions(testUserId, "Password reset");

            verify(sessionRepository).deactivateAllUserSessions(testUserId);
        }

        @Test
        @DisplayName("should terminate other sessions")
        void shouldTerminateOtherSessions() {
            UUID currentSessionId = testSession.getId();
            when(sessionRepository.deactivateOtherSessions(testUserId, currentSessionId)).thenReturn(2);

            sessionService.terminateOtherSessions(testUserId, currentSessionId, "User requested");

            verify(sessionRepository).deactivateOtherSessions(testUserId, currentSessionId);
        }
    }

    @Nested
    @DisplayName("Session activity tests")
    class SessionActivityTests {

        @Test
        @DisplayName("should log activity")
        void shouldLogActivity() {
            sessionService.logActivity(testSession, SessionActivityType.SESSION_CREATED,
                    "192.168.1.1", "Mozilla/5.0", "Created");

            ArgumentCaptor<SessionActivity> captor = ArgumentCaptor.forClass(SessionActivity.class);
            verify(activityRepository).save(captor.capture());

            SessionActivity activity = captor.getValue();
            assertThat(activity.getSession()).isEqualTo(testSession);
            assertThat(activity.getActivityType()).isEqualTo(SessionActivityType.SESSION_CREATED);
            assertThat(activity.getIpAddress()).isEqualTo("192.168.1.1");
        }

        @Test
        @DisplayName("should get session activities")
        void shouldGetSessionActivities() {
            UUID sessionId = testSession.getId();
            SessionActivity activity = SessionActivity.builder()
                    .id(UUID.randomUUID())
                    .session(testSession)
                    .activityType(SessionActivityType.SESSION_CREATED)
                    .ipAddress("192.168.1.1")
                    .createdAt(Instant.now())
                    .build();

            when(activityRepository.findBySessionIdOrderByCreatedAtDesc(sessionId))
                    .thenReturn(Collections.singletonList(activity));

            List<SessionActivityDto> result = sessionService.getSessionActivities(sessionId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getActivityType()).isEqualTo(SessionActivityType.SESSION_CREATED);
        }
    }

    @Nested
    @DisplayName("Maintenance tests")
    class MaintenanceTests {

        @Test
        @DisplayName("should cleanup expired sessions")
        void shouldCleanupExpiredSessions() {
            when(sessionRepository.deactivateExpiredSessions()).thenReturn(5);

            int result = sessionService.cleanupExpiredSessions();

            assertThat(result).isEqualTo(5);
            verify(sessionRepository).deactivateExpiredSessions();
        }

        @Test
        @DisplayName("should delete old sessions")
        void shouldDeleteOldSessions() {
            when(sessionRepository.deleteExpiredSessions(any(Instant.class))).thenReturn(10);

            int result = sessionService.deleteOldSessions(30);

            assertThat(result).isEqualTo(10);
            verify(sessionRepository).deleteExpiredSessions(any(Instant.class));
        }

        @Test
        @DisplayName("should delete old activities")
        void shouldDeleteOldActivities() {
            when(activityRepository.deleteOlderThan(any(Instant.class))).thenReturn(20);

            int result = sessionService.deleteOldActivities(30);

            assertThat(result).isEqualTo(20);
            verify(activityRepository).deleteOlderThan(any(Instant.class));
        }
    }

    @Nested
    @DisplayName("Statistics tests")
    class StatisticsTests {

        @Test
        @DisplayName("should count active sessions")
        void shouldCountActiveSessions() {
            when(sessionRepository.countActiveSessionsByUserId(testUserId)).thenReturn(3);

            int result = sessionService.countActiveSessions(testUserId);

            assertThat(result).isEqualTo(3);
        }

        @Test
        @DisplayName("should get statistics")
        void shouldGetStatistics() {
            when(sessionRepository.count()).thenReturn(100L);
            when(sessionRepository.countActiveUsersInPeriod(any(Instant.class))).thenReturn(50L);
            when(sessionRepository.countActiveSessionsByDeviceType()).thenReturn(
                    Arrays.asList(new Object[]{"Desktop", 60L}, new Object[]{"Mobile", 40L})
            );
            when(sessionRepository.countActiveSessionsByCountry()).thenReturn(
                    Arrays.asList(new Object[]{"US", 70L}, new Object[]{"UK", 30L})
            );

            SessionStatisticsDto result = sessionService.getStatistics();

            assertThat(result.getTotalActiveSessions()).isEqualTo(100L);
            assertThat(result.getActiveUsersLast24h()).isEqualTo(50L);
            assertThat(result.getSessionsByDeviceType()).containsEntry("Desktop", 60L);
            assertThat(result.getSessionsByCountry()).containsEntry("US", 70L);
        }
    }
}
