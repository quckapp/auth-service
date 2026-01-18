package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.TwoFactorService;
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

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for TwoFactorController
 */
@ExtendWith(MockitoExtension.class)
class TwoFactorControllerTest {

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
    private TwoFactorService twoFactorService;

    @Mock
    private JwtOperations jwtOperations;

    @Mock
    private AuthUserRepository authUserRepository;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final UUID TEST_USER_ID = UUID.randomUUID();
    private static final String VALID_TOKEN = "valid-token";
    private static final String AUTH_HEADER = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        TwoFactorController controller = new TwoFactorController(twoFactorService, jwtOperations, authUserRepository);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    private AuthUser createTestUser(boolean twoFactorEnabled, String twoFactorSecret) {
        Set<String> backupCodes = new HashSet<>();
        if (twoFactorEnabled) {
            backupCodes.add("1234-5678");
            backupCodes.add("8765-4321");
        }
        return AuthUser.builder()
                .id(TEST_USER_ID)
                .email("test@example.com")
                .twoFactorEnabled(twoFactorEnabled)
                .twoFactorSecret(twoFactorSecret)
                .backupCodes(backupCodes)
                .build();
    }

    @Nested
    @DisplayName("2FA Status Tests")
    class StatusTests {

        @Test
        @DisplayName("should get 2FA status when enabled")
        void shouldGet2FAStatusWhenEnabled() throws Exception {
            AuthUser user = createTestUser(true, "secret123");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/2fa/status")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.enabled").value(true))
                    .andExpect(jsonPath("$.hasBackupCodes").value(true))
                    .andExpect(jsonPath("$.backupCodesCount").value(2));
        }

        @Test
        @DisplayName("should get 2FA status when disabled")
        void shouldGet2FAStatusWhenDisabled() throws Exception {
            AuthUser user = createTestUser(false, null);

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/2fa/status")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.enabled").value(false))
                    .andExpect(jsonPath("$.hasBackupCodes").value(false));
        }

        @Test
        @DisplayName("should detect pending 2FA setup")
        void shouldDetectPendingSetup() throws Exception {
            AuthUser user = createTestUser(false, "pending-secret");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/2fa/status")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.enabled").value(false))
                    .andExpect(jsonPath("$.setupPending").value(true));
        }
    }

    @Nested
    @DisplayName("2FA Setup Tests")
    class SetupTests {

        @Test
        @DisplayName("should setup 2FA successfully")
        void shouldSetup2FASuccessfully() throws Exception {
            TwoFactorSetupResponse response = TwoFactorSetupResponse.builder()
                    .secret("ABCDEFGH123456")
                    .qrCodeUrl("data:image/png;base64,...")
                    .otpAuthUrl("otpauth://totp/QuckApp:test@example.com?secret=ABCDEFGH123456")
                    .build();

            when(twoFactorService.setupTwoFactor(VALID_TOKEN)).thenReturn(response);

            mockMvc.perform(post("/v1/2fa/setup")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.secret").value("ABCDEFGH123456"))
                    .andExpect(jsonPath("$.qrCodeUrl").exists())
                    .andExpect(jsonPath("$.otpAuthUrl").exists());

            verify(twoFactorService).setupTwoFactor(VALID_TOKEN);
        }

        @Test
        @DisplayName("should cancel 2FA setup")
        void shouldCancel2FASetup() throws Exception {
            AuthUser user = createTestUser(false, "pending-secret");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/2fa/setup/cancel")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("2FA setup cancelled"));

            verify(authUserRepository).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should reject cancel when 2FA already enabled")
        void shouldRejectCancelWhen2FAEnabled() throws Exception {
            AuthUser user = createTestUser(true, "secret");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/2fa/setup/cancel")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("2FA Enable/Disable Tests")
    class EnableDisableTests {

        @Test
        @DisplayName("should enable 2FA successfully")
        void shouldEnable2FASuccessfully() throws Exception {
            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("123456")
                    .build();

            Set<String> backupCodes = new HashSet<>();
            backupCodes.add("1111-2222");
            backupCodes.add("3333-4444");

            TwoFactorEnableResponse response = TwoFactorEnableResponse.builder()
                    .enabled(true)
                    .backupCodes(backupCodes)
                    .build();

            when(twoFactorService.enableTwoFactor(eq(VALID_TOKEN), any(TwoFactorEnableRequest.class), any(ClientInfo.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/2fa/enable")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.enabled").value(true))
                    .andExpect(jsonPath("$.backupCodes").isArray());

            verify(twoFactorService).enableTwoFactor(eq(VALID_TOKEN), any(TwoFactorEnableRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should disable 2FA successfully")
        void shouldDisable2FASuccessfully() throws Exception {
            TwoFactorDisableRequest request = TwoFactorDisableRequest.builder()
                    .code("123456")
                    .password("password123")
                    .build();

            mockMvc.perform(post("/v1/2fa/disable")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists());

            verify(twoFactorService).disableTwoFactor(eq(VALID_TOKEN), any(TwoFactorDisableRequest.class), any(ClientInfo.class));
        }
    }

    @Nested
    @DisplayName("Backup Codes Tests")
    class BackupCodesTests {

        @Test
        @DisplayName("should generate new backup codes")
        void shouldGenerateNewBackupCodes() throws Exception {
            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            Set<String> backupCodes = new HashSet<>();
            backupCodes.add("aaaa-bbbb");
            backupCodes.add("cccc-dddd");

            BackupCodesResponse response = BackupCodesResponse.builder()
                    .backupCodes(backupCodes)
                    .build();

            when(twoFactorService.generateBackupCodes(eq(VALID_TOKEN), any(TwoFactorVerifyRequest.class), any(ClientInfo.class)))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/2fa/backup-codes")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.backupCodes").isArray());

            verify(twoFactorService).generateBackupCodes(eq(VALID_TOKEN), any(TwoFactorVerifyRequest.class), any(ClientInfo.class));
        }

        @Test
        @DisplayName("should get backup codes count")
        void shouldGetBackupCodesCount() throws Exception {
            AuthUser user = createTestUser(true, "secret");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/2fa/backup-codes/count")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.remainingCodes").value(2))
                    .andExpect(jsonPath("$.lowCodesWarning").value(true));
        }

        @Test
        @DisplayName("should reject backup codes count when 2FA not enabled")
        void shouldRejectBackupCodesCountWhen2FANotEnabled() throws Exception {
            AuthUser user = createTestUser(false, null);

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/v1/2fa/backup-codes/count")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("2FA Verification Tests")
    class VerificationTests {

        @Test
        @DisplayName("should verify 2FA code successfully")
        void shouldVerify2FACodeSuccessfully() throws Exception {
            AuthUser user = createTestUser(true, "secret123");

            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/2fa/verify")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.valid").value(true));
        }

        @Test
        @DisplayName("should reject verification when 2FA not setup")
        void shouldRejectVerificationWhen2FANotSetup() throws Exception {
            AuthUser user = createTestUser(false, null);

            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/2fa/verify")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.valid").value(false));
        }
    }

    @Nested
    @DisplayName("Recovery Tests")
    class RecoveryTests {

        @Test
        @DisplayName("should use backup code successfully")
        void shouldUseBackupCodeSuccessfully() throws Exception {
            Set<String> backupCodes = new HashSet<>();
            backupCodes.add("1234-5678");
            backupCodes.add("8765-4321");

            AuthUser user = AuthUser.builder()
                    .id(TEST_USER_ID)
                    .email("test@example.com")
                    .twoFactorEnabled(true)
                    .twoFactorSecret("secret")
                    .backupCodes(backupCodes)
                    .build();

            TwoFactorController.BackupCodeRequest request = new TwoFactorController.BackupCodeRequest();
            request.setBackupCode("1234-5678");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/2fa/recover")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.remainingCodes").value(1));

            verify(authUserRepository).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should reject invalid backup code")
        void shouldRejectInvalidBackupCode() throws Exception {
            AuthUser user = createTestUser(true, "secret");

            TwoFactorController.BackupCodeRequest request = new TwoFactorController.BackupCodeRequest();
            request.setBackupCode("0000-0000");

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(authUserRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/v1/2fa/recover")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false));
        }
    }
}
