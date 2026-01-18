package com.quckapp.auth.controller;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.security.ratelimit.RateLimit;
import com.quckapp.auth.security.ratelimit.RateLimit.KeyType;
import com.quckapp.auth.service.TwoFactorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * REST Controller for Two-Factor Authentication
 * Provides endpoints for setting up, enabling, disabling, and managing 2FA
 */
@RestController
@RequestMapping("/v1/2fa")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Two-Factor Authentication", description = "2FA setup, verification, and backup code management")
@SecurityRequirement(name = "bearerAuth")
public class TwoFactorController {

    private final TwoFactorService twoFactorService;
    private final JwtOperations jwtOperations;
    private final AuthUserRepository authUserRepository;

    // ==================== 2FA Status ====================

    @GetMapping("/status")
    @Operation(summary = "Get 2FA status",
               description = "Check if two-factor authentication is enabled for the current user")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<TwoFactorStatusResponse> getStatus(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        AuthUser user = getUserFromToken(token);

        TwoFactorStatusResponse response = TwoFactorStatusResponse.builder()
                .enabled(user.isTwoFactorEnabled())
                .hasBackupCodes(user.getBackupCodes() != null && !user.getBackupCodes().isEmpty())
                .backupCodesCount(user.getBackupCodes() != null ? user.getBackupCodes().size() : 0)
                .setupPending(user.getTwoFactorSecret() != null && !user.isTwoFactorEnabled())
                .build();

        return ResponseEntity.ok(response);
    }

    // ==================== 2FA Setup ====================

    @PostMapping("/setup")
    @Operation(summary = "Setup 2FA - get QR code",
               description = "Initialize 2FA setup by generating a secret and QR code. User must scan the QR code with an authenticator app.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Setup initialized, QR code returned"),
        @ApiResponse(responseCode = "400", description = "2FA already enabled")
    })
    @RateLimit(requests = 10, window = 3600, key = KeyType.USER)
    public ResponseEntity<TwoFactorSetupResponse> setup2FA(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        log.info("2FA setup initiated");

        TwoFactorSetupResponse response = twoFactorService.setupTwoFactor(token);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/setup/cancel")
    @Operation(summary = "Cancel 2FA setup",
               description = "Cancel a pending 2FA setup before it's enabled")
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> cancelSetup(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        AuthUser user = getUserFromToken(token);

        if (user.isTwoFactorEnabled()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "2FA is already enabled. Use disable endpoint instead."));
        }

        // Clear the pending secret
        user.setTwoFactorSecret(null);
        authUserRepository.save(user);

        log.info("2FA setup cancelled for user: {}", user.getEmail());
        return ResponseEntity.ok(Map.of("message", "2FA setup cancelled"));
    }

    // ==================== 2FA Enable/Disable ====================

    @PostMapping("/enable")
    @Operation(summary = "Enable 2FA after verification",
               description = "Complete 2FA setup by verifying the TOTP code from the authenticator app. Returns backup codes on success.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "2FA enabled successfully, backup codes returned"),
        @ApiResponse(responseCode = "400", description = "Invalid code or setup not initiated")
    })
    @RateLimit(requests = 5, window = 300, key = KeyType.USER)
    public ResponseEntity<TwoFactorEnableResponse> enable2FA(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorEnableRequest request,
            HttpServletRequest httpRequest) {
        String token = extractToken(authHeader);
        log.info("2FA enable attempt");

        TwoFactorEnableResponse response = twoFactorService.enableTwoFactor(
                token, request, getClientInfo(httpRequest));

        return ResponseEntity.ok(response);
    }

    @PostMapping("/disable")
    @Operation(summary = "Disable 2FA",
               description = "Disable two-factor authentication. Requires current TOTP code and password for security.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "2FA disabled successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid code or password"),
        @ApiResponse(responseCode = "400", description = "2FA not enabled")
    })
    @RateLimit(requests = 3, window = 3600, key = KeyType.USER)
    public ResponseEntity<Map<String, String>> disable2FA(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorDisableRequest request,
            HttpServletRequest httpRequest) {
        String token = extractToken(authHeader);
        log.info("2FA disable attempt");

        twoFactorService.disableTwoFactor(token, request, getClientInfo(httpRequest));

        return ResponseEntity.ok(Map.of("message", "Two-factor authentication disabled successfully"));
    }

    // ==================== Backup Codes ====================

    @PostMapping("/backup-codes")
    @Operation(summary = "Generate new backup codes",
               description = "Generate a new set of backup codes. Requires TOTP verification. Old backup codes will be invalidated.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "New backup codes generated"),
        @ApiResponse(responseCode = "400", description = "Invalid code or 2FA not enabled")
    })
    @RateLimit(requests = 3, window = 3600, key = KeyType.USER)
    public ResponseEntity<BackupCodesResponse> generateBackupCodes(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorVerifyRequest request,
            HttpServletRequest httpRequest) {
        String token = extractToken(authHeader);
        log.info("Backup codes generation requested");

        BackupCodesResponse response = twoFactorService.generateBackupCodes(
                token, request, getClientInfo(httpRequest));

        return ResponseEntity.ok(response);
    }

    @GetMapping("/backup-codes/count")
    @Operation(summary = "Get remaining backup codes count",
               description = "Returns the number of unused backup codes remaining")
    @RateLimit(requests = 30, window = 60, key = KeyType.USER)
    public ResponseEntity<Map<String, Object>> getBackupCodesCount(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        AuthUser user = getUserFromToken(token);

        if (!user.isTwoFactorEnabled()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "2FA is not enabled"));
        }

        int count = user.getBackupCodes() != null ? user.getBackupCodes().size() : 0;
        boolean lowCodes = count < 3;

        return ResponseEntity.ok(Map.of(
                "remainingCodes", count,
                "lowCodesWarning", lowCodes,
                "message", lowCodes ? "Consider generating new backup codes" : "Backup codes available"
        ));
    }

    // ==================== 2FA Verification ====================

    @PostMapping("/verify")
    @Operation(summary = "Verify 2FA code",
               description = "Verify a TOTP code without performing any action. Useful for testing setup.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Verification result returned"),
        @ApiResponse(responseCode = "400", description = "2FA not enabled")
    })
    @RateLimit(requests = 10, window = 60, key = KeyType.USER)
    public ResponseEntity<VerificationResponse> verify2FACode(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody TwoFactorVerifyRequest request) {
        String token = extractToken(authHeader);
        AuthUser user = getUserFromToken(token);

        if (!user.isTwoFactorEnabled() && user.getTwoFactorSecret() == null) {
            return ResponseEntity.badRequest().body(
                    VerificationResponse.builder()
                            .valid(false)
                            .message("2FA is not set up")
                            .build()
            );
        }

        // Verify the code
        boolean isValid = verifyTotpCode(user.getTwoFactorSecret(), request.getCode());

        return ResponseEntity.ok(VerificationResponse.builder()
                .valid(isValid)
                .message(isValid ? "Code verified successfully" : "Invalid code")
                .build());
    }

    // ==================== Recovery ====================

    @PostMapping("/recover")
    @Operation(summary = "Use backup code for recovery",
               description = "Use a backup code when authenticator app is unavailable. Each backup code can only be used once.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Backup code accepted"),
        @ApiResponse(responseCode = "400", description = "Invalid backup code")
    })
    @RateLimit(requests = 5, window = 300, key = KeyType.IP)
    public ResponseEntity<RecoveryResponse> useBackupCode(
            @Parameter(hidden = true) @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody BackupCodeRequest request) {
        String token = extractToken(authHeader);
        AuthUser user = getUserFromToken(token);

        if (!user.isTwoFactorEnabled()) {
            return ResponseEntity.badRequest().body(
                    RecoveryResponse.builder()
                            .success(false)
                            .message("2FA is not enabled")
                            .build()
            );
        }

        String code = request.getBackupCode().replace("-", "").toUpperCase();
        String formattedCode = request.getBackupCode();

        // Check if backup code exists
        if (user.getBackupCodes() == null || !user.getBackupCodes().contains(formattedCode)) {
            log.warn("Invalid backup code attempt for user: {}", user.getEmail());
            return ResponseEntity.badRequest().body(
                    RecoveryResponse.builder()
                            .success(false)
                            .message("Invalid backup code")
                            .remainingCodes(user.getBackupCodes() != null ? user.getBackupCodes().size() : 0)
                            .build()
            );
        }

        // Remove the used backup code
        user.getBackupCodes().remove(formattedCode);
        authUserRepository.save(user);

        int remaining = user.getBackupCodes().size();
        log.info("Backup code used for user: {}. Remaining codes: {}", user.getEmail(), remaining);

        return ResponseEntity.ok(RecoveryResponse.builder()
                .success(true)
                .message("Backup code accepted")
                .remainingCodes(remaining)
                .build());
    }

    // ==================== Response DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TwoFactorStatusResponse {
        private boolean enabled;
        private boolean hasBackupCodes;
        private int backupCodesCount;
        private boolean setupPending;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class VerificationResponse {
        private boolean valid;
        private String message;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class RecoveryResponse {
        private boolean success;
        private String message;
        private int remainingCodes;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class BackupCodeRequest {
        @jakarta.validation.constraints.NotBlank
        @jakarta.validation.constraints.Pattern(regexp = "^\\d{4}-\\d{4}$", message = "Backup code must be in format XXXX-XXXX")
        private String backupCode;
    }

    // ==================== Helpers ====================

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }

    private AuthUser getUserFromToken(String token) {
        String userId = jwtOperations.extractUserId(token);
        return authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    private ClientInfo getClientInfo(HttpServletRequest request) {
        return ClientInfo.builder()
                .ipAddress(getClientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .deviceId(request.getHeader("X-Device-ID"))
                .build();
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    private boolean verifyTotpCode(String secret, String code) {
        // TODO: Implement proper TOTP verification using a library like GoogleAuth
        // For now, accept any 6-digit code for testing
        if (code == null || code.length() != 6) {
            return false;
        }
        try {
            Integer.parseInt(code);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
