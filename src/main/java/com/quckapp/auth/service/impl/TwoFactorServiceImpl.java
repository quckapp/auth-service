package com.quckapp.auth.service.impl;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.TwoFactorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class TwoFactorServiceImpl implements TwoFactorService {

    private final AuthUserRepository authUserRepository;
    private final JwtOperations jwtService;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int SECRET_SIZE = 20;
    private static final int BACKUP_CODE_COUNT = 10;
    private static final String ISSUER = "QuckApp";

    @Override
    public TwoFactorSetupResponse setupTwoFactor(String token) {
        AuthUser user = getUserFromToken(token);

        if (user.isTwoFactorEnabled()) {
            throw new RuntimeException("Two-factor authentication is already enabled");
        }

        // Generate a new secret
        byte[] secretBytes = new byte[SECRET_SIZE];
        SECURE_RANDOM.nextBytes(secretBytes);
        String secret = Base64.getEncoder().encodeToString(secretBytes);

        // Store the secret temporarily (will be confirmed when enabling)
        user.setTwoFactorSecret(secret);
        authUserRepository.save(user);

        // Generate OTP Auth URL for QR code
        String otpAuthUrl = String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                ISSUER, user.getEmail(), secret, ISSUER
        );

        // In production, generate actual QR code URL using a QR service
        String qrCodeUrl = "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=" +
                java.net.URLEncoder.encode(otpAuthUrl, java.nio.charset.StandardCharsets.UTF_8);

        return TwoFactorSetupResponse.builder()
                .secret(secret)
                .qrCodeUrl(qrCodeUrl)
                .otpAuthUrl(otpAuthUrl)
                .build();
    }

    @Override
    public TwoFactorEnableResponse enableTwoFactor(String token, TwoFactorEnableRequest request, ClientInfo clientInfo) {
        AuthUser user = getUserFromToken(token);

        if (user.isTwoFactorEnabled()) {
            throw new RuntimeException("Two-factor authentication is already enabled");
        }

        if (user.getTwoFactorSecret() == null) {
            throw new RuntimeException("Please setup 2FA first");
        }

        // Verify the TOTP code
        if (!verifyTotpCode(user.getTwoFactorSecret(), request.getCode())) {
            throw new RuntimeException("Invalid verification code");
        }

        // Generate backup codes
        Set<String> backupCodes = generateBackupCodes();

        user.setTwoFactorEnabled(true);
        user.setBackupCodes(backupCodes);
        authUserRepository.save(user);

        log.info("2FA enabled for user: {}", user.getEmail());

        return TwoFactorEnableResponse.builder()
                .enabled(true)
                .backupCodes(backupCodes)
                .build();
    }

    @Override
    public void disableTwoFactor(String token, TwoFactorDisableRequest request, ClientInfo clientInfo) {
        AuthUser user = getUserFromToken(token);

        if (!user.isTwoFactorEnabled()) {
            throw new RuntimeException("Two-factor authentication is not enabled");
        }

        // Verify the TOTP code before disabling
        if (!verifyTotpCode(user.getTwoFactorSecret(), request.getCode())) {
            throw new RuntimeException("Invalid verification code");
        }

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setBackupCodes(new HashSet<>());
        authUserRepository.save(user);

        log.info("2FA disabled for user: {}", user.getEmail());
    }

    @Override
    public BackupCodesResponse generateBackupCodes(String token, TwoFactorVerifyRequest request, ClientInfo clientInfo) {
        AuthUser user = getUserFromToken(token);

        if (!user.isTwoFactorEnabled()) {
            throw new RuntimeException("Two-factor authentication is not enabled");
        }

        // Verify the TOTP code before generating new backup codes
        if (!verifyTotpCode(user.getTwoFactorSecret(), request.getCode())) {
            throw new RuntimeException("Invalid verification code");
        }

        Set<String> backupCodes = generateBackupCodes();
        user.setBackupCodes(backupCodes);
        authUserRepository.save(user);

        log.info("New backup codes generated for user: {}", user.getEmail());

        return BackupCodesResponse.builder()
                .backupCodes(backupCodes)
                .build();
    }

    private AuthUser getUserFromToken(String token) {
        String userId = jwtService.extractUserId(token);
        return authUserRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    private Set<String> generateBackupCodes() {
        Set<String> codes = new HashSet<>();
        for (int i = 0; i < BACKUP_CODE_COUNT; i++) {
            codes.add(generateBackupCode());
        }
        return codes;
    }

    private String generateBackupCode() {
        int code = SECURE_RANDOM.nextInt(90000000) + 10000000; // 8-digit code
        String formatted = String.valueOf(code);
        return formatted.substring(0, 4) + "-" + formatted.substring(4); // Format: XXXX-XXXX
    }

    private boolean verifyTotpCode(String secret, String code) {
        // TODO: Implement proper TOTP verification using a library like GoogleAuth
        // For now, accept any 6-digit code for testing
        if (code == null || code.length() != 6) {
            return false;
        }
        try {
            Integer.parseInt(code);
            return true; // Accept any 6-digit number for testing
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
