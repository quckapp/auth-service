package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.AuthService;
import com.quckapp.auth.service.SessionManagementService;
import com.quckapp.auth.service.UserProfileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for InternalController
 */
@ExtendWith(MockitoExtension.class)
class InternalControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
        }
    }

    @Mock
    private JwtOperations jwtOperations;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private AuthService authService;

    @Mock
    private SessionManagementService sessionManagementService;

    @Mock
    private UserProfileService userProfileService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final String VALID_API_KEY = "test-api-key";
    private static final UUID TEST_USER_ID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        InternalController controller = new InternalController(authUserRepository, jwtOperations, authService, sessionManagementService, userProfileService);

        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    private AuthUser createTestUser() {
        return AuthUser.builder()
                .id(TEST_USER_ID)
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true)
                .twoFactorEnabled(false)
                .build();
    }

    @Nested
    @DisplayName("Token Introspection Tests")
    class TokenIntrospectionTests {

        @Test
        @DisplayName("should introspect valid token")
        void shouldIntrospectValidToken() throws Exception {
            InternalController.TokenIntrospectionRequest request = new InternalController.TokenIntrospectionRequest();
            request.setToken("valid-access-token");

            when(jwtOperations.isTokenExpired("valid-access-token")).thenReturn(false);
            when(jwtOperations.extractUserId("valid-access-token")).thenReturn(TEST_USER_ID.toString());
            when(jwtOperations.extractEmail("valid-access-token")).thenReturn("test@example.com");
            when(jwtOperations.extractSessionId("valid-access-token")).thenReturn("session-123");
            when(jwtOperations.extractExternalId("valid-access-token")).thenReturn("ext-123");
            when(jwtOperations.extractTokenType("valid-access-token")).thenReturn("access");
            when(jwtOperations.extractExpiration("valid-access-token")).thenReturn(new Date(System.currentTimeMillis() + 3600000));
            when(jwtOperations.extractIssuedAt("valid-access-token")).thenReturn(new Date());

            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/internal/token/introspect")
                            .header("X-API-Key", VALID_API_KEY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.active").value(true))
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"));
        }

        @Test
        @DisplayName("should return inactive for expired token")
        void shouldReturnInactiveForExpiredToken() throws Exception {
            InternalController.TokenIntrospectionRequest request = new InternalController.TokenIntrospectionRequest();
            request.setToken("expired-token");

            when(jwtOperations.isTokenExpired("expired-token")).thenReturn(true);

            mockMvc.perform(post("/v1/internal/token/introspect")
                            .header("X-API-Key", VALID_API_KEY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.active").value(false));
        }
    }

    @Nested
    @DisplayName("User Validation Tests")
    class UserValidationTests {

        @Test
        @DisplayName("should validate existing user")
        void shouldValidateExistingUser() throws Exception {
            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/internal/users/{userId}/validate", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(true))
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.status").value("ACTIVE"));
        }

        @Test
        @DisplayName("should return invalid for non-existent user")
        void shouldReturnInvalidForNonExistentUser() throws Exception {
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.empty());

            mockMvc.perform(get("/v1/internal/users/{userId}/validate", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(false));
        }

        @Test
        @DisplayName("should batch validate users")
        void shouldBatchValidateUsers() throws Exception {
            UUID userId2 = UUID.randomUUID();
            AuthUser user1 = createTestUser();

            InternalController.BatchUserValidationRequest request = new InternalController.BatchUserValidationRequest();
            request.setUserIds(List.of(TEST_USER_ID, userId2));

            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user1));
            when(authUserRepository.findById(userId2)).thenReturn(Optional.empty());

            mockMvc.perform(post("/v1/internal/users/validate/batch")
                            .header("X-API-Key", VALID_API_KEY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.validCount").value(1))
                    .andExpect(jsonPath("$.invalidCount").value(1));
        }
    }

    @Nested
    @DisplayName("User Lookup Tests")
    class UserLookupTests {

        @Test
        @DisplayName("should lookup user by email")
        void shouldLookupUserByEmail() throws Exception {
            AuthUser user = createTestUser();
            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/internal/users/by-email/{email}", "test@example.com")
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"));
        }

        @Test
        @DisplayName("should return 404 for non-existent email")
        void shouldReturn404ForNonExistentEmail() throws Exception {
            when(authUserRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

            mockMvc.perform(get("/v1/internal/users/by-email/{email}", "unknown@example.com")
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should lookup user by external ID")
        void shouldLookupUserByExternalId() throws Exception {
            AuthUser user = createTestUser();
            when(authUserRepository.findByExternalId("ext-123")).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/internal/users/by-external-id/{externalId}", "ext-123")
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.externalId").value("ext-123"));
        }
    }

    @Nested
    @DisplayName("Session Management Tests")
    class SessionManagementTests {

        @Test
        @DisplayName("should get session count for user")
        void shouldGetSessionCountForUser() throws Exception {
            when(sessionManagementService.countActiveSessions(TEST_USER_ID)).thenReturn(3);

            mockMvc.perform(get("/v1/internal/users/{userId}/sessions/count", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.activeSessions").value(3));
        }

        @Test
        @DisplayName("should terminate all sessions for user")
        void shouldTerminateAllSessionsForUser() throws Exception {
            mockMvc.perform(post("/v1/internal/users/{userId}/sessions/terminate-all", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY)
                            .param("reason", "Administrative action"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(sessionManagementService).terminateAllUserSessions(eq(TEST_USER_ID), anyString());
        }
    }

    @Nested
    @DisplayName("Account Lock/Unlock Tests")
    class AccountLockTests {

        @Test
        @DisplayName("should lock user account")
        void shouldLockUserAccount() throws Exception {
            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            InternalController.LockAccountRequest request = new InternalController.LockAccountRequest();
            request.setReason("Security concern");
            request.setDurationMinutes(60);

            mockMvc.perform(post("/v1/internal/users/{userId}/lock", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authUserRepository).save(any(AuthUser.class));
            verify(sessionManagementService).terminateAllUserSessions(eq(TEST_USER_ID), anyString());
        }

        @Test
        @DisplayName("should unlock user account")
        void shouldUnlockUserAccount() throws Exception {
            AuthUser user = createTestUser();
            user.setLockedUntil(Instant.now().plusSeconds(3600));
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/internal/users/{userId}/unlock", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authUserRepository).save(any(AuthUser.class));
        }
    }

    @Nested
    @DisplayName("Status Update Tests")
    class StatusUpdateTests {

        @Test
        @DisplayName("should update user status")
        void shouldUpdateUserStatus() throws Exception {
            AuthUser user = createTestUser();
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            InternalController.UpdateStatusInternalRequest request = new InternalController.UpdateStatusInternalRequest();
            request.setStatus("SUSPENDED");

            mockMvc.perform(post("/v1/internal/users/{userId}/status", TEST_USER_ID)
                            .header("X-API-Key", VALID_API_KEY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authUserRepository).save(any(AuthUser.class));
        }
    }

    @Nested
    @DisplayName("Security Reporting Tests")
    class SecurityReportingTests {

        @Test
        @DisplayName("should report suspicious activity")
        void shouldReportSuspiciousActivity() throws Exception {
            InternalController.SuspiciousActivityRequest request = new InternalController.SuspiciousActivityRequest();
            request.setUserId(TEST_USER_ID);
            request.setActivityType("UNUSUAL_LOGIN_PATTERN");
            request.setSourceService("auth-service");
            request.setDetails("Multiple failed login attempts from different IPs");

            mockMvc.perform(post("/v1/internal/security/report-suspicious")
                            .header("X-API-Key", VALID_API_KEY)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Suspicious activity reported"));
        }
    }

    @Nested
    @DisplayName("Health Check Tests")
    class HealthCheckTests {

        @Test
        @DisplayName("should return health status")
        void shouldReturnHealthStatus() throws Exception {
            mockMvc.perform(get("/v1/internal/health")
                            .header("X-API-Key", VALID_API_KEY))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("healthy"))
                    .andExpect(jsonPath("$.service").value("auth-service"));
        }
    }
}
