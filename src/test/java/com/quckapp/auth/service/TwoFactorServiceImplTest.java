package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.dto.*;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.impl.TwoFactorServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TwoFactorServiceImpl
 */
@ExtendWith(MockitoExtension.class)
class TwoFactorServiceImplTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private JwtOperations jwtService;

    private TwoFactorServiceImpl twoFactorService;

    private AuthUser testUser;
    private ClientInfo testClientInfo;
    private String testToken;

    @BeforeEach
    void setUp() {
        twoFactorService = new TwoFactorServiceImpl(authUserRepository, jwtService);

        testUser = AuthUser.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .twoFactorEnabled(false)
                .build();

        testToken = "valid-jwt-token";

        testClientInfo = ClientInfo.builder()
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .deviceId("device-123")
                .build();
    }

    @Nested
    @DisplayName("2FA setup tests")
    class SetupTests {

        @Test
        @DisplayName("should setup 2FA successfully")
        void shouldSetup2FASuccessfully() {
            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            TwoFactorSetupResponse response = twoFactorService.setupTwoFactor(testToken);

            assertThat(response).isNotNull();
            assertThat(response.getSecret()).isNotNull();
            assertThat(response.getQrCodeUrl()).isNotNull();
            assertThat(response.getOtpAuthUrl()).contains("otpauth://totp/");
            assertThat(response.getOtpAuthUrl()).contains("QuckApp");
            assertThat(response.getOtpAuthUrl()).contains(testUser.getEmail());

            verify(authUserRepository).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should throw exception when 2FA already enabled")
        void shouldThrowWhen2FAAlreadyEnabled() {
            testUser.setTwoFactorEnabled(true);

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.setupTwoFactor(testToken))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("already enabled");
        }

        @Test
        @DisplayName("should throw exception when user not found")
        void shouldThrowWhenUserNotFound() {
            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> twoFactorService.setupTwoFactor(testToken))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("User not found");
        }

        @Test
        @DisplayName("should store secret temporarily during setup")
        void shouldStoreSecretTemporarily() {
            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            twoFactorService.setupTwoFactor(testToken);

            ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(captor.capture());
            assertThat(captor.getValue().getTwoFactorSecret()).isNotNull();
        }
    }

    @Nested
    @DisplayName("2FA enable tests")
    class EnableTests {

        @BeforeEach
        void setupForEnable() {
            testUser.setTwoFactorSecret("dGVzdC1zZWNyZXQ="); // Pre-set secret
        }

        @Test
        @DisplayName("should enable 2FA with valid code")
        void shouldEnable2FAWithValidCode() {
            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("123456") // Valid 6-digit code
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            TwoFactorEnableResponse response = twoFactorService.enableTwoFactor(testToken, request, testClientInfo);

            assertThat(response.isEnabled()).isTrue();
            assertThat(response.getBackupCodes()).hasSize(10);

            ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(captor.capture());
            assertThat(captor.getValue().isTwoFactorEnabled()).isTrue();
            assertThat(captor.getValue().getBackupCodes()).hasSize(10);
        }

        @Test
        @DisplayName("should throw exception when 2FA already enabled")
        void shouldThrowWhen2FAAlreadyEnabled() {
            testUser.setTwoFactorEnabled(true);

            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.enableTwoFactor(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("already enabled");
        }

        @Test
        @DisplayName("should throw exception when secret not set")
        void shouldThrowWhenSecretNotSet() {
            testUser.setTwoFactorSecret(null);

            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.enableTwoFactor(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("setup 2FA first");
        }

        @Test
        @DisplayName("should throw exception for invalid code")
        void shouldThrowForInvalidCode() {
            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("invalid")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.enableTwoFactor(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid verification code");
        }

        @Test
        @DisplayName("should generate unique backup codes")
        void shouldGenerateUniqueBackupCodes() {
            TwoFactorEnableRequest request = TwoFactorEnableRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            TwoFactorEnableResponse response = twoFactorService.enableTwoFactor(testToken, request, testClientInfo);

            Set<String> codes = response.getBackupCodes();
            assertThat(codes).hasSize(10);
            // All codes should be unique
            assertThat(new HashSet<>(codes)).hasSize(10);
            // All codes should be in format XXXX-XXXX
            codes.forEach(code -> assertThat(code).matches("\\d{4}-\\d{4}"));
        }
    }

    @Nested
    @DisplayName("2FA disable tests")
    class DisableTests {

        @BeforeEach
        void setupForDisable() {
            testUser.setTwoFactorEnabled(true);
            testUser.setTwoFactorSecret("dGVzdC1zZWNyZXQ=");
            testUser.setBackupCodes(new HashSet<>(Set.of("1234-5678", "8765-4321")));
        }

        @Test
        @DisplayName("should disable 2FA with valid code")
        void shouldDisable2FAWithValidCode() {
            TwoFactorDisableRequest request = TwoFactorDisableRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            twoFactorService.disableTwoFactor(testToken, request, testClientInfo);

            ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(captor.capture());
            assertThat(captor.getValue().isTwoFactorEnabled()).isFalse();
            assertThat(captor.getValue().getTwoFactorSecret()).isNull();
            assertThat(captor.getValue().getBackupCodes()).isEmpty();
        }

        @Test
        @DisplayName("should throw exception when 2FA not enabled")
        void shouldThrowWhen2FANotEnabled() {
            testUser.setTwoFactorEnabled(false);

            TwoFactorDisableRequest request = TwoFactorDisableRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.disableTwoFactor(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("not enabled");
        }

        @Test
        @DisplayName("should throw exception for invalid code")
        void shouldThrowForInvalidCode() {
            TwoFactorDisableRequest request = TwoFactorDisableRequest.builder()
                    .code("invalid")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.disableTwoFactor(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid verification code");
        }
    }

    @Nested
    @DisplayName("Backup codes generation tests")
    class BackupCodesTests {

        @BeforeEach
        void setupForBackupCodes() {
            testUser.setTwoFactorEnabled(true);
            testUser.setTwoFactorSecret("dGVzdC1zZWNyZXQ=");
        }

        @Test
        @DisplayName("should generate new backup codes with valid code")
        void shouldGenerateNewBackupCodes() {
            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            BackupCodesResponse response = twoFactorService.generateBackupCodes(testToken, request, testClientInfo);

            assertThat(response.getBackupCodes()).hasSize(10);

            ArgumentCaptor<AuthUser> captor = ArgumentCaptor.forClass(AuthUser.class);
            verify(authUserRepository).save(captor.capture());
            assertThat(captor.getValue().getBackupCodes()).hasSize(10);
        }

        @Test
        @DisplayName("should throw exception when 2FA not enabled")
        void shouldThrowWhen2FANotEnabled() {
            testUser.setTwoFactorEnabled(false);

            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.generateBackupCodes(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("not enabled");
        }

        @Test
        @DisplayName("should throw exception for invalid code")
        void shouldThrowForInvalidCode() {
            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("invalid")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() -> twoFactorService.generateBackupCodes(testToken, request, testClientInfo))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Invalid verification code");
        }

        @Test
        @DisplayName("should replace old backup codes with new ones")
        void shouldReplaceOldBackupCodes() {
            Set<String> oldCodes = new HashSet<>(Set.of("1111-1111", "2222-2222"));
            testUser.setBackupCodes(oldCodes);

            TwoFactorVerifyRequest request = TwoFactorVerifyRequest.builder()
                    .code("123456")
                    .build();

            when(jwtService.extractUserId(testToken)).thenReturn(testUser.getId().toString());
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            BackupCodesResponse response = twoFactorService.generateBackupCodes(testToken, request, testClientInfo);

            // New codes should be different from old ones
            assertThat(response.getBackupCodes()).doesNotContain("1111-1111", "2222-2222");
            assertThat(response.getBackupCodes()).hasSize(10);
        }
    }
}
