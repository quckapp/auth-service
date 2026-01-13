package com.quckchat.auth.controller;

import com.quckchat.auth.dto.UserProfileDtos.*;
import com.quckchat.auth.service.MigrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST Controller for data migration from MongoDB to PostgreSQL
 * These endpoints should only be accessible with an internal API key
 */
@RestController
@RequestMapping("/v1/migration")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Migration", description = "Data migration endpoints (internal use only)")
@SecurityRequirement(name = "apiKey")
public class MigrationController {

    private final MigrationService migrationService;

    @PostMapping("/users/batch")
    @Operation(summary = "Batch import users from MongoDB migration")
    public ResponseEntity<MigrationResult> importUsersBatch(
            @Valid @RequestBody List<MigratedUserRequest> users,
            @RequestHeader("X-API-Key") String apiKey) {
        log.info("Received batch migration request for {} users", users.size());

        // API key validation should be done by security filter
        // For now, we just proceed

        MigrationResult result = migrationService.importUsersBatch(users, null); // AuthUserRepository injected in service

        log.info("Migration batch completed: {} successful, {} failed",
                result.getSuccessful(), result.getFailed());

        return ResponseEntity.ok(result);
    }

    @PostMapping("/settings/batch")
    @Operation(summary = "Batch import user settings from MongoDB migration")
    public ResponseEntity<MigrationResult> importSettingsBatch(
            @Valid @RequestBody List<MigratedSettingsRequest> settings,
            @RequestHeader("X-API-Key") String apiKey) {
        log.info("Received settings migration request for {} users", settings.size());

        MigrationResult result = migrationService.importSettingsBatch(settings);

        log.info("Settings migration completed: {} successful, {} failed",
                result.getSuccessful(), result.getFailed());

        return ResponseEntity.ok(result);
    }

    @GetMapping("/status")
    @Operation(summary = "Get current migration status")
    public ResponseEntity<Map<String, Object>> getMigrationStatus(
            @RequestHeader("X-API-Key") String apiKey) {
        return ResponseEntity.ok(migrationService.getMigrationStatus());
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate migration for sample users")
    public ResponseEntity<Map<String, Object>> validateMigration(
            @RequestBody List<String> sampleExternalIds,
            @RequestHeader("X-API-Key") String apiKey) {
        log.info("Validating migration for {} sample users", sampleExternalIds.size());
        return ResponseEntity.ok(migrationService.validateMigration(sampleExternalIds));
    }
}
