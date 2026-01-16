package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.quckapp.auth.dto.UserProfileDtos.*;
import com.quckapp.auth.service.MigrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for MigrationController
 */
@ExtendWith(MockitoExtension.class)
class MigrationControllerTest {

    @Mock
    private MigrationService migrationService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        MigrationController controller = new MigrationController(migrationService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("Import Users Batch Tests")
    class ImportUsersBatchTests {

        @Test
        @DisplayName("should import users batch successfully")
        void shouldImportUsersBatchSuccessfully() throws Exception {
            List<MigratedUserRequest> users = Arrays.asList(
                    MigratedUserRequest.builder()
                            .externalId("ext-1")
                            .email("user1@example.com")
                            .username("user1")
                            .displayName("User One")
                            .build(),
                    MigratedUserRequest.builder()
                            .externalId("ext-2")
                            .email("user2@example.com")
                            .username("user2")
                            .displayName("User Two")
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(2)
                    .successful(2)
                    .failed(0)
                    .errors(Collections.emptyList())
                    .build();

            when(migrationService.importUsersBatch(anyList(), any())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/users/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(users))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.total").value(2))
                    .andExpect(jsonPath("$.successful").value(2))
                    .andExpect(jsonPath("$.failed").value(0));

            verify(migrationService).importUsersBatch(anyList(), any());
        }

        @Test
        @DisplayName("should handle partial failures in batch import")
        void shouldHandlePartialFailuresInBatchImport() throws Exception {
            List<MigratedUserRequest> users = Arrays.asList(
                    MigratedUserRequest.builder()
                            .externalId("ext-1")
                            .email("user1@example.com")
                            .build(),
                    MigratedUserRequest.builder()
                            .externalId("ext-2")
                            .email("duplicate@example.com")
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(2)
                    .successful(1)
                    .failed(1)
                    .errors(Collections.singletonList(
                            MigrationError.builder()
                                    .externalId("ext-2")
                                    .error("Email already exists")
                                    .build()
                    ))
                    .build();

            when(migrationService.importUsersBatch(anyList(), any())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/users/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(users))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.total").value(2))
                    .andExpect(jsonPath("$.successful").value(1))
                    .andExpect(jsonPath("$.failed").value(1))
                    .andExpect(jsonPath("$.errors[0].externalId").value("ext-2"))
                    .andExpect(jsonPath("$.errors[0].error").value("Email already exists"));
        }

        @Test
        @DisplayName("should import users with OAuth providers")
        void shouldImportUsersWithOAuthProviders() throws Exception {
            List<MigratedUserRequest> users = Collections.singletonList(
                    MigratedUserRequest.builder()
                            .externalId("ext-oauth")
                            .email("oauth@example.com")
                            .oauthProviders(Arrays.asList(
                                    MigratedOAuthProvider.builder()
                                            .provider("google")
                                            .providerId("google-123")
                                            .email("oauth@gmail.com")
                                            .build(),
                                    MigratedOAuthProvider.builder()
                                            .provider("github")
                                            .providerId("github-456")
                                            .email("oauth@github.com")
                                            .build()
                            ))
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(1)
                    .successful(1)
                    .failed(0)
                    .errors(Collections.emptyList())
                    .build();

            when(migrationService.importUsersBatch(anyList(), any())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/users/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(users))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.successful").value(1));
        }

        @Test
        @DisplayName("should import users with 2FA enabled")
        void shouldImportUsersWith2FAEnabled() throws Exception {
            Set<String> backupCodes = new HashSet<>(Arrays.asList("1234-5678", "8765-4321"));

            List<MigratedUserRequest> users = Collections.singletonList(
                    MigratedUserRequest.builder()
                            .externalId("ext-2fa")
                            .email("2fa@example.com")
                            .twoFactorEnabled(true)
                            .twoFactorSecret("ABCDEFGHIJKLMNOP")
                            .backupCodes(backupCodes)
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(1)
                    .successful(1)
                    .failed(0)
                    .build();

            when(migrationService.importUsersBatch(anyList(), any())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/users/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(users))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.successful").value(1));
        }

        @Test
        @DisplayName("should import users with linked devices")
        void shouldImportUsersWithLinkedDevices() throws Exception {
            List<MigratedUserRequest> users = Collections.singletonList(
                    MigratedUserRequest.builder()
                            .externalId("ext-devices")
                            .email("devices@example.com")
                            .linkedDevices(Arrays.asList(
                                    MigratedLinkedDevice.builder()
                                            .deviceId("device-1")
                                            .deviceName("iPhone 15")
                                            .deviceType("MOBILE")
                                            .fcmToken("fcm-token-1")
                                            .build(),
                                    MigratedLinkedDevice.builder()
                                            .deviceId("device-2")
                                            .deviceName("Chrome Browser")
                                            .deviceType("WEB")
                                            .build()
                            ))
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(1)
                    .successful(1)
                    .failed(0)
                    .build();

            when(migrationService.importUsersBatch(anyList(), any())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/users/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(users))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.successful").value(1));
        }
    }

    @Nested
    @DisplayName("Import Settings Batch Tests")
    class ImportSettingsBatchTests {

        @Test
        @DisplayName("should import settings batch successfully")
        void shouldImportSettingsBatchSuccessfully() throws Exception {
            List<MigratedSettingsRequest> settings = Arrays.asList(
                    MigratedSettingsRequest.builder()
                            .externalId("ext-1")
                            .darkMode(true)
                            .pushNotifications(true)
                            .readReceipts(true)
                            .build(),
                    MigratedSettingsRequest.builder()
                            .externalId("ext-2")
                            .darkMode(false)
                            .pushNotifications(false)
                            .readReceipts(false)
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(2)
                    .successful(2)
                    .failed(0)
                    .errors(Collections.emptyList())
                    .build();

            when(migrationService.importSettingsBatch(anyList())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/settings/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(settings))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.total").value(2))
                    .andExpect(jsonPath("$.successful").value(2))
                    .andExpect(jsonPath("$.failed").value(0));

            verify(migrationService).importSettingsBatch(anyList());
        }

        @Test
        @DisplayName("should handle settings import with blocked users")
        void shouldHandleSettingsImportWithBlockedUsers() throws Exception {
            List<MigratedSettingsRequest> settings = Collections.singletonList(
                    MigratedSettingsRequest.builder()
                            .externalId("ext-1")
                            .blockedUserExternalIds(Arrays.asList("blocked-1", "blocked-2"))
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(1)
                    .successful(1)
                    .failed(0)
                    .build();

            when(migrationService.importSettingsBatch(anyList())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/settings/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(settings))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.successful").value(1));
        }

        @Test
        @DisplayName("should handle settings import failure for missing user")
        void shouldHandleSettingsImportFailureForMissingUser() throws Exception {
            List<MigratedSettingsRequest> settings = Collections.singletonList(
                    MigratedSettingsRequest.builder()
                            .externalId("non-existent")
                            .darkMode(true)
                            .build()
            );

            MigrationResult result = MigrationResult.builder()
                    .total(1)
                    .successful(0)
                    .failed(1)
                    .errors(Collections.singletonList(
                            MigrationError.builder()
                                    .externalId("non-existent")
                                    .error("User not found")
                                    .build()
                    ))
                    .build();

            when(migrationService.importSettingsBatch(anyList())).thenReturn(result);

            mockMvc.perform(post("/v1/migration/settings/batch")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(settings))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.failed").value(1))
                    .andExpect(jsonPath("$.errors[0].error").value("User not found"));
        }
    }

    @Nested
    @DisplayName("Get Migration Status Tests")
    class GetMigrationStatusTests {

        @Test
        @DisplayName("should return migration status")
        void shouldReturnMigrationStatus() throws Exception {
            Map<String, Object> status = new HashMap<>();
            status.put("totalUsers", 1000);
            status.put("migratedUsers", 750);
            status.put("pendingUsers", 250);
            status.put("startedAt", Instant.now().toString());
            status.put("status", "IN_PROGRESS");

            when(migrationService.getMigrationStatus()).thenReturn(status);

            mockMvc.perform(get("/v1/migration/status")
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalUsers").value(1000))
                    .andExpect(jsonPath("$.migratedUsers").value(750))
                    .andExpect(jsonPath("$.pendingUsers").value(250))
                    .andExpect(jsonPath("$.status").value("IN_PROGRESS"));

            verify(migrationService).getMigrationStatus();
        }

        @Test
        @DisplayName("should return completed migration status")
        void shouldReturnCompletedMigrationStatus() throws Exception {
            Map<String, Object> status = new HashMap<>();
            status.put("totalUsers", 500);
            status.put("migratedUsers", 500);
            status.put("pendingUsers", 0);
            status.put("status", "COMPLETED");
            status.put("completedAt", Instant.now().toString());

            when(migrationService.getMigrationStatus()).thenReturn(status);

            mockMvc.perform(get("/v1/migration/status")
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("COMPLETED"))
                    .andExpect(jsonPath("$.pendingUsers").value(0));
        }
    }

    @Nested
    @DisplayName("Validate Migration Tests")
    class ValidateMigrationTests {

        @Test
        @DisplayName("should validate migration for sample users")
        void shouldValidateMigrationForSampleUsers() throws Exception {
            List<String> sampleIds = Arrays.asList("ext-1", "ext-2", "ext-3");

            Map<String, Object> validationResult = new HashMap<>();
            validationResult.put("totalChecked", 3);
            validationResult.put("valid", 3);
            validationResult.put("invalid", 0);
            validationResult.put("missingUsers", Collections.emptyList());

            when(migrationService.validateMigration(anyList())).thenReturn(validationResult);

            mockMvc.perform(post("/v1/migration/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(sampleIds))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalChecked").value(3))
                    .andExpect(jsonPath("$.valid").value(3))
                    .andExpect(jsonPath("$.invalid").value(0));

            verify(migrationService).validateMigration(sampleIds);
        }

        @Test
        @DisplayName("should report missing users in validation")
        void shouldReportMissingUsersInValidation() throws Exception {
            List<String> sampleIds = Arrays.asList("ext-1", "ext-missing", "ext-3");

            Map<String, Object> validationResult = new HashMap<>();
            validationResult.put("totalChecked", 3);
            validationResult.put("valid", 2);
            validationResult.put("invalid", 1);
            validationResult.put("missingUsers", Collections.singletonList("ext-missing"));

            when(migrationService.validateMigration(anyList())).thenReturn(validationResult);

            mockMvc.perform(post("/v1/migration/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(sampleIds))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.invalid").value(1))
                    .andExpect(jsonPath("$.missingUsers[0]").value("ext-missing"));
        }

        @Test
        @DisplayName("should validate with data integrity checks")
        void shouldValidateWithDataIntegrityChecks() throws Exception {
            List<String> sampleIds = Arrays.asList("ext-1");

            Map<String, Object> validationResult = new HashMap<>();
            validationResult.put("totalChecked", 1);
            validationResult.put("valid", 1);
            validationResult.put("integrityPassed", true);
            validationResult.put("details", Map.of(
                    "ext-1", Map.of(
                            "profileMigrated", true,
                            "settingsMigrated", true,
                            "devicesMigrated", true,
                            "oauthMigrated", true
                    )
            ));

            when(migrationService.validateMigration(anyList())).thenReturn(validationResult);

            mockMvc.perform(post("/v1/migration/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(sampleIds))
                            .header("X-API-Key", "test-api-key"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.integrityPassed").value(true));
        }
    }
}
