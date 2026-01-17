package com.quckapp.auth.integration.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.entity.AuthUser.AuthStatus;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.LoginAnomalyRepository;
import com.quckapp.auth.domain.repository.LoginHistoryRepository;
import com.quckapp.auth.dto.LoginHistoryDtos.*;
import com.quckapp.auth.service.LoginHistoryService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.*;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for LoginHistoryService.
 * Tests login recording, anomaly detection, and history retrieval
 * using real MySQL database from docker-compose.
 */
@DisplayName("LoginHistoryService Integration Tests")
class LoginHistoryServiceIntegrationTest extends BaseServiceIntegrationTest {

    @Autowired
    private LoginHistoryService loginHistoryService;

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;

    @Autowired
    private LoginAnomalyRepository anomalyRepository;

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private EntityManager entityManager;

    private AuthUser testUser;
    private UUID resolverUserId;

    @BeforeEach
    void setUp() {
        resolverUserId = UUID.randomUUID();
    }

    @AfterEach
    void tearDown() {
        // Clean up test data
        if (testUser != null) {
            anomalyRepository.findByUserIdOrderByCreatedAtDesc(testUser.getId())
                    .forEach(anomalyRepository::delete);
            loginHistoryRepository.findByUserId(testUser.getId())
                    .forEach(loginHistoryRepository::delete);
            authUserRepository.delete(testUser);
            testUser = null;
        }
    }

    @Nested
    @DisplayName("Login Recording Operations")
    class LoginRecordingOperations {

        @Test
        @DisplayName("Should record successful login")
        @Transactional
        void shouldRecordSuccessfulLogin() {
            // Given
            testUser = createTestUser("login_success_" + System.currentTimeMillis() + "@test.com");

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(LoginMethod.PASSWORD)
                    .ipAddress("192.168.1.100")
                    .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                    .deviceId("device-123")
                    .deviceName("Test Device")
                    .deviceType("DESKTOP")
                    .osName("Windows")
                    .osVersion("10")
                    .browserName("Chrome")
                    .browserVersion("120.0")
                    .country("United States")
                    .countryCode("US")
                    .city("New York")
                    .riskScore(10)
                    .build();

            // When
            LoginHistoryDto recorded = loginHistoryService.recordLogin(request);

            // Then
            assertThat(recorded).isNotNull();
            assertThat(recorded.getId()).isNotNull();
            assertThat(recorded.getUserId()).isEqualTo(testUser.getId());
            assertThat(recorded.getEmail()).isEqualTo(testUser.getEmail());
            assertThat(recorded.getLoginStatus()).isEqualTo(LoginStatus.SUCCESS);
            assertThat(recorded.getLoginMethod()).isEqualTo(LoginMethod.PASSWORD);
            assertThat(recorded.getIpAddress()).isEqualTo("192.168.1.100");
            assertThat(recorded.getCountry()).isEqualTo("United States");
        }

        @Test
        @DisplayName("Should record failed login with failure reason")
        @Transactional
        void shouldRecordFailedLogin() {
            // Given
            String email = "failed_login_" + System.currentTimeMillis() + "@test.com";

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .email(email)
                    .loginStatus(LoginStatus.FAILED)
                    .loginMethod(LoginMethod.PASSWORD)
                    .ipAddress("192.168.1.200")
                    .failureReason("Invalid password")
                    .riskScore(30)
                    .build();

            // When
            LoginHistoryDto recorded = loginHistoryService.recordLogin(request);

            // Then
            assertThat(recorded).isNotNull();
            assertThat(recorded.getLoginStatus()).isEqualTo(LoginStatus.FAILED);
            assertThat(recorded.getFailureReason()).isEqualTo("Invalid password");
            assertThat(recorded.getUserId()).isNull();

            // Cleanup
            loginHistoryRepository.deleteById(recorded.getId());
        }

        @Test
        @DisplayName("Should record login with 2FA")
        @Transactional
        void shouldRecordLoginWith2FA() {
            // Given
            testUser = createTestUser("login_2fa_" + System.currentTimeMillis() + "@test.com");

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(LoginMethod.PASSWORD)
                    .ipAddress("10.0.0.1")
                    .twoFactorUsed(true)
                    .twoFactorMethod("TOTP")
                    .build();

            // When
            LoginHistoryDto recorded = loginHistoryService.recordLogin(request);

            // Then
            assertThat(recorded.isTwoFactorUsed()).isTrue();
            assertThat(recorded.getTwoFactorMethod()).isEqualTo("TOTP");
        }

        @Test
        @DisplayName("Should record OAuth login")
        @Transactional
        void shouldRecordOAuthLogin() {
            // Given
            testUser = createTestUser("oauth_login_" + System.currentTimeMillis() + "@test.com");

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(LoginMethod.OAUTH_GOOGLE)
                    .ipAddress("172.16.0.1")
                    .build();

            // When
            LoginHistoryDto recorded = loginHistoryService.recordLogin(request);

            // Then
            assertThat(recorded.getLoginMethod()).isEqualTo(LoginMethod.OAUTH_GOOGLE);
        }
    }

    @Nested
    @DisplayName("Login History Retrieval Operations")
    class LoginHistoryRetrievalOperations {

        @Test
        @DisplayName("Should get login history by ID")
        @Transactional
        void shouldGetLoginHistoryById() {
            // Given
            testUser = createTestUser("get_history_" + System.currentTimeMillis() + "@test.com");
            LoginHistoryDto created = recordTestLogin(testUser, LoginStatus.SUCCESS);

            // When
            LoginHistoryDto retrieved = loginHistoryService.getLoginHistory(created.getId());

            // Then
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getId()).isEqualTo(created.getId());
        }

        @Test
        @DisplayName("Should get user login history with pagination")
        @Transactional
        void shouldGetUserLoginHistoryPaginated() {
            // Given
            testUser = createTestUser("paginated_" + System.currentTimeMillis() + "@test.com");
            for (int i = 0; i < 5; i++) {
                recordTestLogin(testUser, LoginStatus.SUCCESS);
            }

            // When
            Page<LoginHistoryDto> page = loginHistoryService.getUserLoginHistory(
                    testUser.getId(), PageRequest.of(0, 3));

            // Then
            assertThat(page.getContent()).hasSize(3);
            assertThat(page.getTotalElements()).isEqualTo(5);
            assertThat(page.getTotalPages()).isEqualTo(2);
        }

        @Test
        @DisplayName("Should get recent logins within time window")
        @Transactional
        void shouldGetRecentLogins() {
            // Given
            testUser = createTestUser("recent_" + System.currentTimeMillis() + "@test.com");
            recordTestLogin(testUser, LoginStatus.SUCCESS);
            recordTestLogin(testUser, LoginStatus.FAILED);

            // When
            List<LoginHistoryDto> recentLogins = loginHistoryService.getRecentLogins(testUser.getId(), 1);

            // Then
            assertThat(recentLogins).hasSize(2);
        }

        @Test
        @DisplayName("Should get last successful login")
        @Transactional
        void shouldGetLastSuccessfulLogin() {
            // Given
            testUser = createTestUser("last_success_" + System.currentTimeMillis() + "@test.com");
            recordTestLogin(testUser, LoginStatus.FAILED);
            LoginHistoryDto successfulLogin = recordTestLogin(testUser, LoginStatus.SUCCESS);
            recordTestLogin(testUser, LoginStatus.FAILED);

            // When
            Optional<LoginHistoryDto> lastSuccess = loginHistoryService.getLastSuccessfulLogin(testUser.getId());

            // Then
            assertThat(lastSuccess).isPresent();
            assertThat(lastSuccess.get().getLoginStatus()).isEqualTo(LoginStatus.SUCCESS);
        }

        @Test
        @DisplayName("Should get logins by IP address")
        @Transactional
        void shouldGetLoginsByIpAddress() {
            // Given
            testUser = createTestUser("ip_search_" + System.currentTimeMillis() + "@test.com");
            String specificIp = "203.0.113." + (System.currentTimeMillis() % 255);

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress(specificIp)
                    .build();
            loginHistoryService.recordLogin(request);

            // When
            Page<LoginHistoryDto> page = loginHistoryService.getLoginsByIp(
                    specificIp, PageRequest.of(0, 10));

            // Then
            assertThat(page.getContent()).isNotEmpty();
            assertThat(page.getContent()).allMatch(l -> l.getIpAddress().equals(specificIp));
        }
    }

    @Nested
    @DisplayName("Failed Attempt Tracking Operations")
    class FailedAttemptTrackingOperations {

        @Test
        @DisplayName("Should count recent failed attempts by email")
        @Transactional
        void shouldCountRecentFailedAttempts() {
            // Given
            String email = "failed_count_" + System.currentTimeMillis() + "@test.com";
            for (int i = 0; i < 3; i++) {
                RecordLoginRequest request = RecordLoginRequest.builder()
                        .email(email)
                        .loginStatus(LoginStatus.FAILED)
                        .ipAddress("192.168.1.100")
                        .failureReason("Invalid password")
                        .build();
                loginHistoryService.recordLogin(request);
            }

            // When
            int failedCount = loginHistoryService.countRecentFailedAttempts(email);

            // Then
            assertThat(failedCount).isEqualTo(3);

            // Cleanup
            loginHistoryRepository.findAll().stream()
                    .filter(h -> email.equals(h.getEmail()))
                    .forEach(loginHistoryRepository::delete);
        }

        @Test
        @DisplayName("Should count recent failed attempts from IP")
        @Transactional
        void shouldCountRecentFailedAttemptsFromIp() {
            // Given
            String ip = "10.0.0." + (System.currentTimeMillis() % 255);
            for (int i = 0; i < 4; i++) {
                RecordLoginRequest request = RecordLoginRequest.builder()
                        .email("user" + i + "@test.com")
                        .loginStatus(LoginStatus.FAILED)
                        .ipAddress(ip)
                        .failureReason("Invalid credentials")
                        .build();
                loginHistoryService.recordLogin(request);
            }

            // When
            int failedCount = loginHistoryService.countRecentFailedAttemptsFromIp(ip);

            // Then
            assertThat(failedCount).isEqualTo(4);

            // Cleanup
            loginHistoryRepository.findAll().stream()
                    .filter(h -> ip.equals(h.getIpAddress()))
                    .forEach(loginHistoryRepository::delete);
        }

        @Test
        @DisplayName("Should determine account lockout requirement")
        @Transactional
        void shouldDetermineAccountLockoutRequired() {
            // Given
            String email = "lockout_" + System.currentTimeMillis() + "@test.com";
            // Record 5 failed attempts (threshold)
            for (int i = 0; i < 5; i++) {
                RecordLoginRequest request = RecordLoginRequest.builder()
                        .email(email)
                        .loginStatus(LoginStatus.FAILED)
                        .ipAddress("192.168.1.50")
                        .failureReason("Invalid password")
                        .build();
                loginHistoryService.recordLogin(request);
            }

            // When/Then
            assertThat(loginHistoryService.isAccountLockoutRequired(email)).isTrue();

            // Cleanup
            loginHistoryRepository.findAll().stream()
                    .filter(h -> email.equals(h.getEmail()))
                    .forEach(loginHistoryRepository::delete);
        }
    }

    @Nested
    @DisplayName("Anomaly Detection Operations")
    class AnomalyDetectionOperations {

        @Test
        @DisplayName("Should detect VPN anomaly on login")
        @Transactional
        void shouldDetectVpnAnomaly() {
            // Given
            testUser = createTestUser("vpn_detect_" + System.currentTimeMillis() + "@test.com");

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.1")
                    .vpn(true)
                    .build();

            // When
            loginHistoryService.recordLogin(request);

            // Then
            List<LoginAnomalyDto> anomalies = loginHistoryService.getUserAnomalies(testUser.getId());
            assertThat(anomalies).anyMatch(a -> a.getAnomalyType() == AnomalyType.VPN_DETECTED);
        }

        @Test
        @DisplayName("Should detect Tor anomaly on login")
        @Transactional
        void shouldDetectTorAnomaly() {
            // Given
            testUser = createTestUser("tor_detect_" + System.currentTimeMillis() + "@test.com");

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.2")
                    .tor(true)
                    .build();

            // When
            loginHistoryService.recordLogin(request);

            // Then
            List<LoginAnomalyDto> anomalies = loginHistoryService.getUserAnomalies(testUser.getId());
            assertThat(anomalies).anyMatch(a -> a.getAnomalyType() == AnomalyType.TOR_DETECTED);
            // Verify Tor is HIGH severity
            assertThat(anomalies.stream()
                    .filter(a -> a.getAnomalyType() == AnomalyType.TOR_DETECTED)
                    .findFirst()
                    .get()
                    .getSeverity())
                    .isEqualTo(AnomalySeverity.HIGH);
        }

        @Test
        @DisplayName("Should detect high risk IP anomaly")
        @Transactional
        void shouldDetectHighRiskIpAnomaly() {
            // Given
            testUser = createTestUser("high_risk_" + System.currentTimeMillis() + "@test.com");

            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.3")
                    .riskScore(85) // High risk score (threshold is 70)
                    .build();

            // When
            loginHistoryService.recordLogin(request);

            // Then
            List<LoginAnomalyDto> anomalies = loginHistoryService.getUserAnomalies(testUser.getId());
            assertThat(anomalies).anyMatch(a -> a.getAnomalyType() == AnomalyType.HIGH_RISK_IP);
        }

        @Test
        @DisplayName("Should detect new country anomaly")
        @Transactional
        void shouldDetectNewCountryAnomaly() {
            // Given
            testUser = createTestUser("new_country_" + System.currentTimeMillis() + "@test.com");

            // First login from USA
            RecordLoginRequest firstLogin = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.4")
                    .country("United States")
                    .countryCode("US")
                    .build();
            loginHistoryService.recordLogin(firstLogin);

            // Flush to ensure first login is visible in subsequent queries
            entityManager.flush();
            entityManager.clear();

            // Second login from different country
            RecordLoginRequest secondLogin = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.5")
                    .country("Germany")
                    .countryCode("DE")
                    .build();

            // When
            loginHistoryService.recordLogin(secondLogin);

            // Flush to ensure anomaly is persisted
            entityManager.flush();

            // Then
            List<LoginAnomalyDto> anomalies = loginHistoryService.getUserAnomalies(testUser.getId());
            assertThat(anomalies).anyMatch(a ->
                    a.getAnomalyType() == AnomalyType.NEW_COUNTRY &&
                    a.getDescription().contains("Germany"));
        }

        @Test
        @DisplayName("Should detect new device anomaly")
        @Transactional
        void shouldDetectNewDeviceAnomaly() {
            // Given
            testUser = createTestUser("new_device_" + System.currentTimeMillis() + "@test.com");

            // First login from device A
            RecordLoginRequest firstLogin = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.6")
                    .deviceId("device-A")
                    .deviceName("First Device")
                    .build();
            loginHistoryService.recordLogin(firstLogin);

            // Flush to ensure first login is visible in subsequent queries
            entityManager.flush();
            entityManager.clear();

            // Second login from different device
            RecordLoginRequest secondLogin = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.1.7")
                    .deviceId("device-B")
                    .deviceName("Second Device")
                    .build();

            // When
            loginHistoryService.recordLogin(secondLogin);

            // Flush to ensure anomaly is persisted
            entityManager.flush();

            // Then
            List<LoginAnomalyDto> anomalies = loginHistoryService.getUserAnomalies(testUser.getId());
            assertThat(anomalies).anyMatch(a -> a.getAnomalyType() == AnomalyType.NEW_DEVICE);
        }
    }

    @Nested
    @DisplayName("Anomaly Management Operations")
    class AnomalyManagementOperations {

        @Test
        @DisplayName("Should create anomaly manually")
        @Transactional
        void shouldCreateAnomalyManually() {
            // Given
            testUser = createTestUser("manual_anomaly_" + System.currentTimeMillis() + "@test.com");

            CreateAnomalyRequest request = CreateAnomalyRequest.builder()
                    .userId(testUser.getId())
                    .anomalyType(AnomalyType.CREDENTIAL_STUFFING)
                    .severity(AnomalySeverity.HIGH)
                    .description("Suspicious behavior detected by admin")
                    .build();

            // When
            LoginAnomalyDto created = loginHistoryService.createAnomaly(request);

            // Then
            assertThat(created).isNotNull();
            assertThat(created.getId()).isNotNull();
            assertThat(created.getAnomalyType()).isEqualTo(AnomalyType.CREDENTIAL_STUFFING);
            assertThat(created.getSeverity()).isEqualTo(AnomalySeverity.HIGH);
            assertThat(created.isResolved()).isFalse();
        }

        @Test
        @DisplayName("Should resolve anomaly")
        @Transactional
        void shouldResolveAnomaly() {
            // Given
            testUser = createTestUser("resolve_anomaly_" + System.currentTimeMillis() + "@test.com");

            CreateAnomalyRequest createRequest = CreateAnomalyRequest.builder()
                    .userId(testUser.getId())
                    .anomalyType(AnomalyType.VPN_DETECTED)
                    .severity(AnomalySeverity.LOW)
                    .description("VPN usage detected")
                    .build();
            LoginAnomalyDto created = loginHistoryService.createAnomaly(createRequest);

            // When
            LoginAnomalyDto resolved = loginHistoryService.resolveAnomaly(
                    created.getId(),
                    resolverUserId,
                    "User confirmed legitimate VPN usage"
            );

            // Then
            assertThat(resolved.isResolved()).isTrue();
            assertThat(resolved.getResolvedAt()).isNotNull();
            assertThat(resolved.getResolvedBy()).isEqualTo(resolverUserId);
            assertThat(resolved.getResolutionNotes()).isEqualTo("User confirmed legitimate VPN usage");
        }

        @Test
        @DisplayName("Should get unresolved anomalies for user")
        @Transactional
        void shouldGetUnresolvedAnomalies() {
            // Given
            testUser = createTestUser("unresolved_" + System.currentTimeMillis() + "@test.com");

            // Create multiple anomalies
            loginHistoryService.createAnomaly(CreateAnomalyRequest.builder()
                    .userId(testUser.getId())
                    .anomalyType(AnomalyType.VPN_DETECTED)
                    .description("VPN 1")
                    .build());
            LoginAnomalyDto toResolve = loginHistoryService.createAnomaly(CreateAnomalyRequest.builder()
                    .userId(testUser.getId())
                    .anomalyType(AnomalyType.PROXY_DETECTED)
                    .description("Proxy 1")
                    .build());
            loginHistoryService.createAnomaly(CreateAnomalyRequest.builder()
                    .userId(testUser.getId())
                    .anomalyType(AnomalyType.NEW_DEVICE)
                    .description("Device 1")
                    .build());

            // Resolve one
            loginHistoryService.resolveAnomaly(toResolve.getId(), resolverUserId, "Resolved");

            // When
            List<LoginAnomalyDto> unresolved = loginHistoryService.getUnresolvedAnomalies(testUser.getId());

            // Then
            assertThat(unresolved).hasSize(2);
            assertThat(unresolved).allMatch(a -> !a.isResolved());
        }

        @Test
        @DisplayName("Should resolve all user anomalies")
        @Transactional
        void shouldResolveAllUserAnomalies() {
            // Given
            testUser = createTestUser("resolve_all_" + System.currentTimeMillis() + "@test.com");

            for (int i = 0; i < 3; i++) {
                loginHistoryService.createAnomaly(CreateAnomalyRequest.builder()
                        .userId(testUser.getId())
                        .anomalyType(AnomalyType.CREDENTIAL_STUFFING)
                        .description("Anomaly " + i)
                        .build());
            }

            // When
            loginHistoryService.resolveAllUserAnomalies(testUser.getId(), resolverUserId);

            // Then
            List<LoginAnomalyDto> unresolved = loginHistoryService.getUnresolvedAnomalies(testUser.getId());
            assertThat(unresolved).isEmpty();
        }
    }

    @Nested
    @DisplayName("User Summary Operations")
    class UserSummaryOperations {

        @Test
        @DisplayName("Should get user login summary")
        @Transactional
        void shouldGetUserLoginSummary() {
            // Given
            testUser = createTestUser("summary_" + System.currentTimeMillis() + "@test.com");

            // Record various logins
            recordTestLogin(testUser, LoginStatus.SUCCESS);
            recordTestLogin(testUser, LoginStatus.SUCCESS);
            recordTestLogin(testUser, LoginStatus.FAILED);

            // Create an anomaly
            loginHistoryService.createAnomaly(CreateAnomalyRequest.builder()
                    .userId(testUser.getId())
                    .anomalyType(AnomalyType.VPN_DETECTED)
                    .description("Test anomaly")
                    .build());

            // When
            UserLoginSummaryDto summary = loginHistoryService.getUserLoginSummary(testUser.getId());

            // Then
            assertThat(summary).isNotNull();
            assertThat(summary.getUserId()).isEqualTo(testUser.getId());
            assertThat(summary.getTotalLogins()).isEqualTo(3);
            assertThat(summary.getSuccessfulLogins()).isEqualTo(2);
            assertThat(summary.getFailedLogins()).isEqualTo(1);
            assertThat(summary.getUnresolvedAnomalies()).isGreaterThanOrEqualTo(1);
        }
    }

    @Nested
    @DisplayName("High Risk Login Operations")
    class HighRiskLoginOperations {

        @Test
        @DisplayName("Should get high risk logins")
        @Transactional
        void shouldGetHighRiskLogins() {
            // Given
            testUser = createTestUser("high_risk_query_" + System.currentTimeMillis() + "@test.com");

            // Record a high risk login
            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.100.1")
                    .riskScore(90)
                    .build();
            loginHistoryService.recordLogin(request);

            // When
            Page<LoginHistoryDto> highRiskLogins = loginHistoryService.getHighRiskLogins(
                    80, PageRequest.of(0, 10));

            // Then
            assertThat(highRiskLogins.getContent()).isNotEmpty();
            assertThat(highRiskLogins.getContent()).allMatch(l -> l.getRiskScore() >= 80);
        }

        @Test
        @DisplayName("Should get suspicious logins for user")
        @Transactional
        void shouldGetSuspiciousLogins() {
            // Given
            testUser = createTestUser("suspicious_" + System.currentTimeMillis() + "@test.com");

            // Record suspicious login (high risk score, VPN, etc.)
            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUser.getId())
                    .email(testUser.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .ipAddress("192.168.100.2")
                    .riskScore(75)
                    .vpn(true)
                    .tor(false)
                    .build();
            loginHistoryService.recordLogin(request);

            // When
            List<LoginHistoryDto> suspiciousLogins = loginHistoryService.getSuspiciousLogins(testUser.getId());

            // Then
            assertThat(suspiciousLogins).isNotEmpty();
        }
    }

    // ==================== Helper Methods ====================

    private AuthUser createTestUser(String email) {
        AuthUser user = AuthUser.builder()
                .email(email)
                .passwordHash("$2a$10$test.password.hash")
                .status(AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();
        return authUserRepository.save(user);
    }

    private LoginHistoryDto recordTestLogin(AuthUser user, LoginStatus status) {
        RecordLoginRequest request = RecordLoginRequest.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .loginStatus(status)
                .loginMethod(LoginMethod.PASSWORD)
                .ipAddress("192.168.1." + (int)(Math.random() * 255))
                .deviceId("test-device-" + System.currentTimeMillis())
                .deviceName("Test Device")
                .country("United States")
                .countryCode("US")
                .riskScore(10)
                .build();
        return loginHistoryService.recordLogin(request);
    }
}
