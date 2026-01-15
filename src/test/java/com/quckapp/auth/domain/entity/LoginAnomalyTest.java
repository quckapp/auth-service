package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for LoginAnomaly entity
 */
@DisplayName("LoginAnomaly Entity Tests")
class LoginAnomalyTest {

    private LoginAnomaly anomaly;

    @BeforeEach
    void setUp() {
        anomaly = LoginAnomaly.builder()
                .id(UUID.randomUUID())
                .anomalyType(AnomalyType.NEW_DEVICE)
                .severity(AnomalySeverity.MEDIUM)
                .description("Login from a new device detected")
                .isResolved(false)
                .build();
    }

    @Nested
    @DisplayName("resolve() Tests")
    class ResolveTests {

        @Test
        @DisplayName("should set isResolved to true")
        void shouldSetIsResolvedToTrue() {
            UUID adminId = UUID.randomUUID();

            anomaly.resolve(adminId, "Verified by user");

            assertThat(anomaly.isResolved()).isTrue();
        }

        @Test
        @DisplayName("should set resolvedAt timestamp")
        void shouldSetResolvedAtTimestamp() {
            UUID adminId = UUID.randomUUID();
            Instant before = Instant.now();

            anomaly.resolve(adminId, "Marked as false positive");

            assertThat(anomaly.getResolvedAt()).isNotNull();
            assertThat(anomaly.getResolvedAt()).isAfterOrEqualTo(before);
        }

        @Test
        @DisplayName("should set resolvedBy user ID")
        void shouldSetResolvedByUserId() {
            UUID adminId = UUID.randomUUID();

            anomaly.resolve(adminId, "User confirmed");

            assertThat(anomaly.getResolvedBy()).isEqualTo(adminId);
        }

        @Test
        @DisplayName("should set resolutionNotes")
        void shouldSetResolutionNotes() {
            UUID adminId = UUID.randomUUID();

            anomaly.resolve(adminId, "This was a legitimate login from a new laptop");

            assertThat(anomaly.getResolutionNotes()).isEqualTo("This was a legitimate login from a new laptop");
        }

        @Test
        @DisplayName("should handle null notes")
        void shouldHandleNullNotes() {
            UUID adminId = UUID.randomUUID();

            anomaly.resolve(adminId, null);

            assertThat(anomaly.isResolved()).isTrue();
            assertThat(anomaly.getResolutionNotes()).isNull();
        }
    }

    @Nested
    @DisplayName("isCritical() Tests")
    class IsCriticalTests {

        @Test
        @DisplayName("should return true when severity is CRITICAL")
        void shouldReturnTrueWhenSeverityIsCritical() {
            anomaly.setSeverity(AnomalySeverity.CRITICAL);

            assertThat(anomaly.isCritical()).isTrue();
        }

        @Test
        @DisplayName("should return false when severity is HIGH")
        void shouldReturnFalseWhenSeverityIsHigh() {
            anomaly.setSeverity(AnomalySeverity.HIGH);

            assertThat(anomaly.isCritical()).isFalse();
        }

        @Test
        @DisplayName("should return false when severity is MEDIUM")
        void shouldReturnFalseWhenSeverityIsMedium() {
            anomaly.setSeverity(AnomalySeverity.MEDIUM);

            assertThat(anomaly.isCritical()).isFalse();
        }

        @Test
        @DisplayName("should return false when severity is LOW")
        void shouldReturnFalseWhenSeverityIsLow() {
            anomaly.setSeverity(AnomalySeverity.LOW);

            assertThat(anomaly.isCritical()).isFalse();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create anomaly with default values")
        void shouldCreateAnomalyWithDefaultValues() {
            LoginAnomaly newAnomaly = LoginAnomaly.builder()
                    .anomalyType(AnomalyType.VPN_DETECTED)
                    .build();

            assertThat(newAnomaly.getSeverity()).isEqualTo(AnomalySeverity.MEDIUM);
            assertThat(newAnomaly.isResolved()).isFalse();
        }

        @Test
        @DisplayName("should create anomaly with all fields")
        void shouldCreateAnomalyWithAllFields() {
            LoginAnomaly newAnomaly = LoginAnomaly.builder()
                    .id(UUID.randomUUID())
                    .anomalyType(AnomalyType.BRUTE_FORCE_DETECTED)
                    .severity(AnomalySeverity.CRITICAL)
                    .description("Multiple failed login attempts detected")
                    .isResolved(false)
                    .build();

            assertThat(newAnomaly.getAnomalyType()).isEqualTo(AnomalyType.BRUTE_FORCE_DETECTED);
            assertThat(newAnomaly.getSeverity()).isEqualTo(AnomalySeverity.CRITICAL);
            assertThat(newAnomaly.getDescription()).isEqualTo("Multiple failed login attempts detected");
        }
    }

    @Nested
    @DisplayName("AnomalySeverity Enum Tests")
    class AnomalySeverityEnumTests {

        @Test
        @DisplayName("should have all expected severity levels")
        void shouldHaveAllExpectedSeverityLevels() {
            AnomalySeverity[] severities = AnomalySeverity.values();

            assertThat(severities).containsExactly(
                    AnomalySeverity.LOW,
                    AnomalySeverity.MEDIUM,
                    AnomalySeverity.HIGH,
                    AnomalySeverity.CRITICAL
            );
        }
    }

    @Nested
    @DisplayName("AnomalyType Enum Tests")
    class AnomalyTypeEnumTests {

        @Test
        @DisplayName("should have all expected anomaly types")
        void shouldHaveAllExpectedAnomalyTypes() {
            AnomalyType[] types = AnomalyType.values();

            assertThat(types).contains(
                    AnomalyType.NEW_DEVICE,
                    AnomalyType.NEW_LOCATION,
                    AnomalyType.NEW_COUNTRY,
                    AnomalyType.IMPOSSIBLE_TRAVEL,
                    AnomalyType.MULTIPLE_FAILED_ATTEMPTS,
                    AnomalyType.BRUTE_FORCE_DETECTED,
                    AnomalyType.VPN_DETECTED,
                    AnomalyType.TOR_DETECTED,
                    AnomalyType.PROXY_DETECTED,
                    AnomalyType.SUSPICIOUS_USER_AGENT,
                    AnomalyType.UNUSUAL_TIME,
                    AnomalyType.HIGH_RISK_IP,
                    AnomalyType.CREDENTIAL_STUFFING,
                    AnomalyType.BOT_DETECTED,
                    AnomalyType.SESSION_HIJACKING,
                    AnomalyType.CONCURRENT_SESSIONS_EXCEEDED,
                    AnomalyType.IP_REPUTATION_LOW,
                    AnomalyType.DEVICE_FINGERPRINT_MISMATCH
            );
        }
    }
}
