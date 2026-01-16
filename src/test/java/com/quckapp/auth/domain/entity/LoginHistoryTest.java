package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for LoginHistory entity
 */
@DisplayName("LoginHistory Entity Tests")
class LoginHistoryTest {

    private LoginHistory loginHistory;

    @BeforeEach
    void setUp() {
        loginHistory = LoginHistory.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .loginStatus(LoginStatus.SUCCESS)
                .loginMethod(LoginMethod.PASSWORD)
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .build();
    }

    @Nested
    @DisplayName("isSuccessful() Tests")
    class IsSuccessfulTests {

        @Test
        @DisplayName("should return true when login status is SUCCESS")
        void shouldReturnTrueWhenStatusIsSuccess() {
            loginHistory.setLoginStatus(LoginStatus.SUCCESS);

            assertThat(loginHistory.isSuccessful()).isTrue();
        }

        @Test
        @DisplayName("should return false when login status is FAILED")
        void shouldReturnFalseWhenStatusIsFailed() {
            loginHistory.setLoginStatus(LoginStatus.FAILED);

            assertThat(loginHistory.isSuccessful()).isFalse();
        }

        @Test
        @DisplayName("should return false when login status is BLOCKED")
        void shouldReturnFalseWhenStatusIsBlocked() {
            loginHistory.setLoginStatus(LoginStatus.BLOCKED);

            assertThat(loginHistory.isSuccessful()).isFalse();
        }

        @Test
        @DisplayName("should return false when login status is ACCOUNT_LOCKED")
        void shouldReturnFalseWhenStatusIsAccountLocked() {
            loginHistory.setLoginStatus(LoginStatus.ACCOUNT_LOCKED);

            assertThat(loginHistory.isSuccessful()).isFalse();
        }
    }

    @Nested
    @DisplayName("isSuspicious() Tests")
    class IsSuspiciousTests {

        @Test
        @DisplayName("should return true when risk score is above 50")
        void shouldReturnTrueWhenRiskScoreAbove50() {
            loginHistory.setRiskScore(51);
            loginHistory.setVpn(false);
            loginHistory.setTor(false);
            loginHistory.setProxy(false);

            assertThat(loginHistory.isSuspicious()).isTrue();
        }

        @Test
        @DisplayName("should return true when exactly at risk threshold")
        void shouldReturnFalseWhenExactlyAtRiskThreshold() {
            loginHistory.setRiskScore(50);
            loginHistory.setVpn(false);
            loginHistory.setTor(false);
            loginHistory.setProxy(false);

            assertThat(loginHistory.isSuspicious()).isFalse();
        }

        @Test
        @DisplayName("should return true when using VPN")
        void shouldReturnTrueWhenUsingVpn() {
            loginHistory.setRiskScore(0);
            loginHistory.setVpn(true);
            loginHistory.setTor(false);
            loginHistory.setProxy(false);

            assertThat(loginHistory.isSuspicious()).isTrue();
        }

        @Test
        @DisplayName("should return true when using Tor")
        void shouldReturnTrueWhenUsingTor() {
            loginHistory.setRiskScore(0);
            loginHistory.setVpn(false);
            loginHistory.setTor(true);
            loginHistory.setProxy(false);

            assertThat(loginHistory.isSuspicious()).isTrue();
        }

        @Test
        @DisplayName("should return true when using proxy")
        void shouldReturnTrueWhenUsingProxy() {
            loginHistory.setRiskScore(0);
            loginHistory.setVpn(false);
            loginHistory.setTor(false);
            loginHistory.setProxy(true);

            assertThat(loginHistory.isSuspicious()).isTrue();
        }

        @Test
        @DisplayName("should return false when all indicators are safe")
        void shouldReturnFalseWhenAllIndicatorsSafe() {
            loginHistory.setRiskScore(25);
            loginHistory.setVpn(false);
            loginHistory.setTor(false);
            loginHistory.setProxy(false);

            assertThat(loginHistory.isSuspicious()).isFalse();
        }

        @Test
        @DisplayName("should return true when multiple suspicious indicators")
        void shouldReturnTrueWhenMultipleSuspiciousIndicators() {
            loginHistory.setRiskScore(75);
            loginHistory.setVpn(true);
            loginHistory.setTor(true);
            loginHistory.setProxy(true);

            assertThat(loginHistory.isSuspicious()).isTrue();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create login history with default values")
        void shouldCreateLoginHistoryWithDefaultValues() {
            LoginHistory history = LoginHistory.builder()
                    .loginStatus(LoginStatus.SUCCESS)
                    .build();

            assertThat(history.getLoginMethod()).isEqualTo(LoginMethod.PASSWORD);
            assertThat(history.isVpn()).isFalse();
            assertThat(history.isTor()).isFalse();
            assertThat(history.isProxy()).isFalse();
            assertThat(history.getRiskScore()).isEqualTo(0);
            assertThat(history.isTwoFactorUsed()).isFalse();
        }

        @Test
        @DisplayName("should create login history with all fields")
        void shouldCreateLoginHistoryWithAllFields() {
            LoginHistory history = LoginHistory.builder()
                    .email("user@test.com")
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(LoginMethod.OAUTH_GOOGLE)
                    .ipAddress("10.0.0.1")
                    .userAgent("Chrome/100.0")
                    .deviceId("device-123")
                    .country("United States")
                    .countryCode("US")
                    .city("New York")
                    .twoFactorUsed(true)
                    .twoFactorMethod("TOTP")
                    .riskScore(10)
                    .build();

            assertThat(history.getEmail()).isEqualTo("user@test.com");
            assertThat(history.getLoginMethod()).isEqualTo(LoginMethod.OAUTH_GOOGLE);
            assertThat(history.getCountry()).isEqualTo("United States");
            assertThat(history.isTwoFactorUsed()).isTrue();
            assertThat(history.getTwoFactorMethod()).isEqualTo("TOTP");
        }
    }

    @Nested
    @DisplayName("LoginStatus Enum Tests")
    class LoginStatusEnumTests {

        @Test
        @DisplayName("should have all expected status values")
        void shouldHaveAllExpectedStatusValues() {
            LoginStatus[] statuses = LoginStatus.values();

            assertThat(statuses).contains(
                    LoginStatus.SUCCESS,
                    LoginStatus.FAILED,
                    LoginStatus.BLOCKED,
                    LoginStatus.ACCOUNT_LOCKED
            );
        }
    }

    @Nested
    @DisplayName("LoginMethod Enum Tests")
    class LoginMethodEnumTests {

        @Test
        @DisplayName("should have all expected method values")
        void shouldHaveAllExpectedMethodValues() {
            LoginMethod[] methods = LoginMethod.values();

            assertThat(methods).contains(
                    LoginMethod.PASSWORD,
                    LoginMethod.OAUTH_GOOGLE,
                    LoginMethod.OAUTH_GITHUB,
                    LoginMethod.OAUTH_APPLE,
                    LoginMethod.OAUTH_FACEBOOK
            );
        }
    }
}
