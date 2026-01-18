package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.AuthService;
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
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for TokenController
 */
@ExtendWith(MockitoExtension.class)
class TokenControllerTest {

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
    private AuthService authService;

    @Mock
    private JwtOperations jwtOperations;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final UUID TEST_USER_ID = UUID.randomUUID();
    private static final String VALID_TOKEN = "valid-token";
    private static final String AUTH_HEADER = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        TokenController controller = new TokenController(authService, jwtOperations, refreshTokenRepository);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Token Refresh Tests")
    class TokenRefreshTests {

        @Test
        @DisplayName("should refresh token successfully")
        void shouldRefreshTokenSuccessfully() throws Exception {
            RefreshTokenRequest request = RefreshTokenRequest.builder()
                    .refreshToken("old-refresh-token")
                    .build();

            TokenResponse response = TokenResponse.builder()
                    .accessToken("new-access-token")
                    .refreshToken("new-refresh-token")
                    .tokenType("Bearer")
                    .expiresIn(3600)
                    .build();

            when(authService.refreshToken(any(RefreshTokenRequest.class), any(ClientInfo.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/token/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));

            verify(authService).refreshToken(any(RefreshTokenRequest.class), any(ClientInfo.class));
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("should validate token successfully")
        void shouldValidateTokenSuccessfully() throws Exception {
            TokenValidationRequest request = TokenValidationRequest.builder()
                    .token("token-to-validate")
                    .build();

            TokenValidationResponse response = TokenValidationResponse.builder()
                    .valid(true)
                    .userId(TEST_USER_ID.toString())
                    .email("test@example.com")
                    .build();

            when(authService.validateToken(any(TokenValidationRequest.class))).thenReturn(response);

            mockMvc.perform(post("/v1/token/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(true))
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()));

            verify(authService).validateToken(any(TokenValidationRequest.class));
        }
    }

    @Nested
    @DisplayName("Token Info Tests")
    class TokenInfoTests {

        @Test
        @DisplayName("should get token info successfully")
        void shouldGetTokenInfoSuccessfully() throws Exception {
            Date expiration = Date.from(Instant.now().plusSeconds(3600));
            Date issuedAt = Date.from(Instant.now());

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(jwtOperations.extractEmail(VALID_TOKEN)).thenReturn("test@example.com");
            when(jwtOperations.extractSessionId(VALID_TOKEN)).thenReturn("session-123");
            when(jwtOperations.extractTokenType(VALID_TOKEN)).thenReturn("ACCESS");
            when(jwtOperations.extractExpiration(VALID_TOKEN)).thenReturn(expiration);
            when(jwtOperations.extractIssuedAt(VALID_TOKEN)).thenReturn(issuedAt);
            when(jwtOperations.isTokenExpired(VALID_TOKEN)).thenReturn(false);

            mockMvc.perform(get("/v1/token/info")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.valid").value(true));
        }

        @Test
        @DisplayName("should return invalid token info on error")
        void shouldReturnInvalidTokenInfoOnError() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenThrow(new RuntimeException("Invalid token"));

            mockMvc.perform(get("/v1/token/info")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(false));
        }
    }

    @Nested
    @DisplayName("Token Revocation Tests")
    class TokenRevocationTests {

        @Test
        @DisplayName("should revoke specific token")
        void shouldRevokeSpecificToken() throws Exception {
            RevokeTokenRequest request = RevokeTokenRequest.builder()
                    .token("token-to-revoke")
                    .build();

            mockMvc.perform(post("/v1/token/revoke")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).revokeToken(eq(VALID_TOKEN), any(RevokeTokenRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should revoke all tokens")
        void shouldRevokeAllTokens() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            mockMvc.perform(post("/v1/token/revoke-all")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(authService).revokeAllTokens(eq(VALID_TOKEN), any(ClientInfo.class));
        }
    }

    @Nested
    @DisplayName("Active Tokens Tests")
    class ActiveTokensTests {

        @Test
        @DisplayName("should get active tokens")
        void shouldGetActiveTokens() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            RefreshToken token = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .deviceId("device-123")
                    .deviceName("Chrome on Windows")
                    .ipAddress("192.168.1.1")
                    .createdAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(86400))
                    .build();

            when(refreshTokenRepository.findValidTokensByUserId(eq(TEST_USER_ID), any(Instant.class)))
                    .thenReturn(List.of(token));

            mockMvc.perform(get("/v1/token/active")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.activeTokenCount").value(1))
                    .andExpect(jsonPath("$.tokens[0].deviceId").value("device-123"));
        }

        @Test
        @DisplayName("should get token count")
        void shouldGetTokenCount() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(refreshTokenRepository.countActiveTokensByUserId(eq(TEST_USER_ID), any(Instant.class)))
                    .thenReturn(5);

            mockMvc.perform(get("/v1/token/count")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.activeTokens").value(5));
        }
    }

    @Nested
    @DisplayName("Token History Tests")
    class TokenHistoryTests {

        @Test
        @DisplayName("should get token history")
        void shouldGetTokenHistory() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            RefreshToken token = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .deviceId("device-123")
                    .deviceName("Chrome on Windows")
                    .ipAddress("192.168.1.1")
                    .createdAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(86400))
                    .revoked(false)
                    .build();

            when(refreshTokenRepository.findByUserId(TEST_USER_ID)).thenReturn(List.of(token));

            mockMvc.perform(get("/v1/token/history")
                            .header("Authorization", AUTH_HEADER)
                            .param("limit", "20"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.totalTokens").value(1))
                    .andExpect(jsonPath("$.entries[0].deviceId").value("device-123"));
        }
    }
}
