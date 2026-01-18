package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.SessionActivityType;
import com.quckapp.auth.dto.SessionDtos.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.SessionManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for SessionController
 */
@ExtendWith(MockitoExtension.class)
class SessionControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }
    }

    @Mock
    private SessionManagementService sessionManagementService;

    @Mock
    private JwtOperations jwtOperations;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final UUID TEST_USER_ID = UUID.randomUUID();
    private static final UUID TEST_SESSION_ID = UUID.randomUUID();
    private static final String VALID_TOKEN = "valid-token";
    private static final String AUTH_HEADER = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        SessionController controller = new SessionController(sessionManagementService, jwtOperations);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Get User Sessions Tests")
    class GetUserSessionsTests {

        @Test
        @DisplayName("should get all user sessions successfully")
        void shouldGetAllUserSessions() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(jwtOperations.extractSessionId(VALID_TOKEN)).thenReturn(TEST_SESSION_ID.toString());

            UserSessionsResponse response = UserSessionsResponse.builder()
                    .userId(TEST_USER_ID)
                    .totalSessions(2)
                    .activeSessions(1)
                    .currentSessionId(TEST_SESSION_ID)
                    .build();

            when(sessionManagementService.getUserSessions(TEST_USER_ID, TEST_SESSION_ID)).thenReturn(response);

            mockMvc.perform(get("/v1/sessions")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.totalSessions").value(2));

            verify(sessionManagementService).getUserSessions(TEST_USER_ID, TEST_SESSION_ID);
        }

        @Test
        @DisplayName("should reject request with invalid auth header")
        void shouldRejectInvalidAuthHeader() throws Exception {
            mockMvc.perform(get("/v1/sessions")
                            .header("Authorization", "Invalid"))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Get Active Sessions Tests")
    class GetActiveSessionsTests {

        @Test
        @DisplayName("should get active sessions")
        void shouldGetActiveSessions() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(TEST_SESSION_ID)
                    .userId(TEST_USER_ID)
                    .deviceName("Chrome on Windows")
                    .ipAddress("192.168.1.1")
                    .active(true)
                    .createdAt(Instant.now())
                    .build();

            when(sessionManagementService.getActiveSessions(TEST_USER_ID)).thenReturn(List.of(session));

            mockMvc.perform(get("/v1/sessions/active")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(TEST_SESSION_ID.toString()))
                    .andExpect(jsonPath("$[0].deviceName").value("Chrome on Windows"));

            verify(sessionManagementService).getActiveSessions(TEST_USER_ID);
        }
    }

    @Nested
    @DisplayName("Get Session By ID Tests")
    class GetSessionByIdTests {

        @Test
        @DisplayName("should get specific session")
        void shouldGetSpecificSession() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(TEST_SESSION_ID)
                    .userId(TEST_USER_ID)
                    .deviceName("Chrome on Windows")
                    .build();

            when(sessionManagementService.getSession(TEST_SESSION_ID)).thenReturn(session);

            mockMvc.perform(get("/v1/sessions/{sessionId}", TEST_SESSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_SESSION_ID.toString()));

            verify(sessionManagementService).getSession(TEST_SESSION_ID);
        }

        @Test
        @DisplayName("should return 404 when session belongs to different user")
        void shouldReturn404WhenSessionBelongsToDifferentUser() throws Exception {
            UUID otherUserId = UUID.randomUUID();
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(TEST_SESSION_ID)
                    .userId(otherUserId)
                    .build();

            when(sessionManagementService.getSession(TEST_SESSION_ID)).thenReturn(session);

            mockMvc.perform(get("/v1/sessions/{sessionId}", TEST_SESSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("Session Count Tests")
    class SessionCountTests {

        @Test
        @DisplayName("should get session count")
        void shouldGetSessionCount() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(sessionManagementService.countActiveSessions(TEST_USER_ID)).thenReturn(3);

            mockMvc.perform(get("/v1/sessions/count")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.activeSessions").value(3));

            verify(sessionManagementService).countActiveSessions(TEST_USER_ID);
        }
    }

    @Nested
    @DisplayName("Session Activities Tests")
    class SessionActivitiesTests {

        @Test
        @DisplayName("should get session activities")
        void shouldGetSessionActivities() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(TEST_SESSION_ID)
                    .userId(TEST_USER_ID)
                    .build();

            SessionActivityDto activity = SessionActivityDto.builder()
                    .id(UUID.randomUUID())
                    .activityType(SessionActivityType.SESSION_CREATED)
                    .createdAt(Instant.now())
                    .build();

            when(sessionManagementService.getSession(TEST_SESSION_ID)).thenReturn(session);
            when(sessionManagementService.getSessionActivities(TEST_SESSION_ID)).thenReturn(List.of(activity));

            mockMvc.perform(get("/v1/sessions/{sessionId}/activities", TEST_SESSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].activityType").value("SESSION_CREATED"));

            verify(sessionManagementService).getSessionActivities(TEST_SESSION_ID);
        }

        @Test
        @DisplayName("should get user activities with pagination")
        void shouldGetUserActivitiesWithPagination() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            SessionActivityDto activity = SessionActivityDto.builder()
                    .id(UUID.randomUUID())
                    .activityType(SessionActivityType.SESSION_CREATED)
                    .createdAt(Instant.now())
                    .build();

            Page<SessionActivityDto> page = new PageImpl<>(List.of(activity), PageRequest.of(0, 20), 1);
            when(sessionManagementService.getUserActivities(eq(TEST_USER_ID), any())).thenReturn(page);

            mockMvc.perform(get("/v1/sessions/activities")
                            .header("Authorization", AUTH_HEADER)
                            .param("page", "0")
                            .param("size", "20"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.content[0].activityType").value("SESSION_CREATED"));
        }
    }

    @Nested
    @DisplayName("Trust Session Tests")
    class TrustSessionTests {

        @Test
        @DisplayName("should mark session as trusted")
        void shouldMarkSessionAsTrusted() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(TEST_SESSION_ID)
                    .userId(TEST_USER_ID)
                    .build();

            when(sessionManagementService.getSession(TEST_SESSION_ID)).thenReturn(session);

            mockMvc.perform(put("/v1/sessions/{sessionId}/trust", TEST_SESSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk());

            verify(sessionManagementService).markSessionAsTrusted(TEST_SESSION_ID);
        }
    }

    @Nested
    @DisplayName("Terminate Session Tests")
    class TerminateSessionTests {

        @Test
        @DisplayName("should terminate specific session")
        void shouldTerminateSpecificSession() throws Exception {
            UUID sessionToTerminate = UUID.randomUUID();
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(jwtOperations.extractSessionId(VALID_TOKEN)).thenReturn(TEST_SESSION_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(sessionToTerminate)
                    .userId(TEST_USER_ID)
                    .build();

            when(sessionManagementService.getSession(sessionToTerminate)).thenReturn(session);

            mockMvc.perform(delete("/v1/sessions/{sessionId}", sessionToTerminate)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk());

            verify(sessionManagementService).terminateSession(eq(sessionToTerminate), anyString());
        }

        @Test
        @DisplayName("should reject terminating current session")
        void shouldRejectTerminatingCurrentSession() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(jwtOperations.extractSessionId(VALID_TOKEN)).thenReturn(TEST_SESSION_ID.toString());

            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(TEST_SESSION_ID)
                    .userId(TEST_USER_ID)
                    .build();

            when(sessionManagementService.getSession(TEST_SESSION_ID)).thenReturn(session);

            mockMvc.perform(delete("/v1/sessions/{sessionId}", TEST_SESSION_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should terminate all other sessions")
        void shouldTerminateAllOtherSessions() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(jwtOperations.extractSessionId(VALID_TOKEN)).thenReturn(TEST_SESSION_ID.toString());

            mockMvc.perform(delete("/v1/sessions")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(sessionManagementService).terminateOtherSessions(eq(TEST_USER_ID), eq(TEST_SESSION_ID), anyString());
        }

        @Test
        @DisplayName("should terminate all sessions including current")
        void shouldTerminateAllSessions() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            mockMvc.perform(delete("/v1/sessions/all")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(sessionManagementService).terminateAllUserSessions(eq(TEST_USER_ID), anyString());
        }
    }
}
