package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.LoginHistoryDtos.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for LoginHistoryService
 */
@ExtendWith(MockitoExtension.class)
class LoginHistoryServiceTest {

    @Mock
    private LoginHistoryRepository loginHistoryRepository;

    @Mock
    private LoginAnomalyRepository anomalyRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    private LoginHistoryService loginHistoryService;

    private AuthUser testUser;
    private UUID testUserId;
    private LoginHistory testLoginHistory;

    @BeforeEach
    void setUp() {
        loginHistoryService = new LoginHistoryService(
                loginHistoryRepository,
                anomalyRepository,
                authUserRepository
        );

        testUserId = UUID.randomUUID();
        testUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .build();

        testLoginHistory = LoginHistory.builder()
                .id(UUID.randomUUID())
                .user(testUser)
                .email("test@example.com")
                .loginStatus(LoginStatus.SUCCESS)
                .loginMethod(LoginMethod.PASSWORD)
                .ipAddress("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .createdAt(Instant.now())
                .build();
    }

    @Nested
    @DisplayName("Login recording tests")
    class LoginRecordingTests {

        @Test
        @DisplayName("should record successful login")
        void shouldRecordSuccessfulLogin() {
            RecordLoginRequest request = RecordLoginRequest.builder()
                    .userId(testUserId)
                    .email("test@example.com")
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(LoginMethod.PASSWORD)
                    .ipAddress("192.168.1.1")
                    .userAgent("Mozilla/5.0")
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(loginHistoryRepository.save(any(LoginHistory.class))).thenAnswer(invocation -> {
                LoginHistory history = invocation.getArgument(0);
                history.setId(UUID.randomUUID());
                return history;
            });
            when(loginHistoryRepository.findDistinctCountriesByUserId(testUserId)).thenReturn(Collections.emptyList());
            when(loginHistoryRepository.findDistinctDeviceIdsByUserId(testUserId)).thenReturn(Collections.emptyList());

            LoginHistoryDto result = loginHistoryService.recordLogin(request);

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo("test@example.com");
            assertThat(result.getLoginStatus()).isEqualTo(LoginStatus.SUCCESS);

            verify(loginHistoryRepository).save(any(LoginHistory.class));
        }

        @Test
        @DisplayName("should record failed login")
        void shouldRecordFailedLogin() {
            RecordLoginRequest request = RecordLoginRequest.builder()
                    .email("test@example.com")
                    .loginStatus(LoginStatus.FAILED)
                    .loginMethod(LoginMethod.PASSWORD)
                    .ipAddress("192.168.1.1")
                    .failureReason("Invalid password")
                    .build();

            when(loginHistoryRepository.save(any(LoginHistory.class))).thenAnswer(invocation -> {
                LoginHistory history = invocation.getArgument(0);
                history.setId(UUID.randomUUID());
                return history;
            });

            LoginHistoryDto result = loginHistoryService.recordLogin(request);

            assertThat(result).isNotNull();
            assertThat(result.getLoginStatus()).isEqualTo(LoginStatus.FAILED);
            assertThat(result.getFailureReason()).isEqualTo("Invalid password");

            // No user lookup for failed login without userId
            verify(authUserRepository, never()).findById(any());
        }

        @Test
        @DisplayName("should use PASSWORD as default login method")
        void shouldUsePasswordAsDefaultMethod() {
            RecordLoginRequest request = RecordLoginRequest.builder()
                    .email("test@example.com")
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(null)
                    .ipAddress("192.168.1.1")
                    .build();

            when(loginHistoryRepository.save(any(LoginHistory.class))).thenAnswer(invocation -> {
                LoginHistory history = invocation.getArgument(0);
                history.setId(UUID.randomUUID());
                return history;
            });

            loginHistoryService.recordLogin(request);

            ArgumentCaptor<LoginHistory> captor = ArgumentCaptor.forClass(LoginHistory.class);
            verify(loginHistoryRepository).save(captor.capture());
            assertThat(captor.getValue().getLoginMethod()).isEqualTo(LoginMethod.PASSWORD);
        }
    }

    @Nested
    @DisplayName("Login history retrieval tests")
    class LoginHistoryRetrievalTests {

        @Test
        @DisplayName("should get login history by ID")
        void shouldGetLoginHistoryById() {
            UUID loginId = testLoginHistory.getId();
            when(loginHistoryRepository.findById(loginId)).thenReturn(Optional.of(testLoginHistory));

            LoginHistoryDto result = loginHistoryService.getLoginHistory(loginId);

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("should throw when login history not found")
        void shouldThrowWhenNotFound() {
            UUID loginId = UUID.randomUUID();
            when(loginHistoryRepository.findById(loginId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> loginHistoryService.getLoginHistory(loginId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Login history not found");
        }

        @Test
        @DisplayName("should get user login history with pagination")
        void shouldGetUserLoginHistoryWithPagination() {
            Pageable pageable = PageRequest.of(0, 10);
            Page<LoginHistory> page = new PageImpl<>(Collections.singletonList(testLoginHistory));

            when(loginHistoryRepository.findByUserIdOrderByCreatedAtDesc(testUserId, pageable)).thenReturn(page);

            Page<LoginHistoryDto> result = loginHistoryService.getUserLoginHistory(testUserId, pageable);

            assertThat(result.getContent()).hasSize(1);
            assertThat(result.getContent().get(0).getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("should get recent logins")
        void shouldGetRecentLogins() {
            when(loginHistoryRepository.findRecentByUserId(eq(testUserId), any(Instant.class)))
                    .thenReturn(Collections.singletonList(testLoginHistory));

            List<LoginHistoryDto> result = loginHistoryService.getRecentLogins(testUserId, 24);

            assertThat(result).hasSize(1);
        }

        @Test
        @DisplayName("should get last successful login")
        void shouldGetLastSuccessfulLogin() {
            when(loginHistoryRepository.findLastSuccessfulLoginByUserId(testUserId))
                    .thenReturn(Optional.of(testLoginHistory));

            Optional<LoginHistoryDto> result = loginHistoryService.getLastSuccessfulLogin(testUserId);

            assertThat(result).isPresent();
            assertThat(result.get().getLoginStatus()).isEqualTo(LoginStatus.SUCCESS);
        }

        @Test
        @DisplayName("should get logins by IP")
        void shouldGetLoginsByIp() {
            Pageable pageable = PageRequest.of(0, 10);
            Page<LoginHistory> page = new PageImpl<>(Collections.singletonList(testLoginHistory));

            when(loginHistoryRepository.findByIpAddressOrderByCreatedAtDesc("192.168.1.1", pageable))
                    .thenReturn(page);

            Page<LoginHistoryDto> result = loginHistoryService.getLoginsByIp("192.168.1.1", pageable);

            assertThat(result.getContent()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Failed attempt tracking tests")
    class FailedAttemptTrackingTests {

        @Test
        @DisplayName("should count recent failed attempts")
        void shouldCountRecentFailedAttempts() {
            when(loginHistoryRepository.countFailedAttemptsSince(eq("test@example.com"), any(Instant.class)))
                    .thenReturn(3);

            int result = loginHistoryService.countRecentFailedAttempts("test@example.com");

            assertThat(result).isEqualTo(3);
        }

        @Test
        @DisplayName("should count recent failed attempts from IP")
        void shouldCountRecentFailedAttemptsFromIp() {
            when(loginHistoryRepository.countFailedAttemptsFromIpSince(eq("192.168.1.1"), any(Instant.class)))
                    .thenReturn(5);

            int result = loginHistoryService.countRecentFailedAttemptsFromIp("192.168.1.1");

            assertThat(result).isEqualTo(5);
        }

        @Test
        @DisplayName("should require lockout when threshold exceeded")
        void shouldRequireLockoutWhenThresholdExceeded() {
            when(loginHistoryRepository.countFailedAttemptsSince(eq("test@example.com"), any(Instant.class)))
                    .thenReturn(5);

            boolean result = loginHistoryService.isAccountLockoutRequired("test@example.com");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should not require lockout when under threshold")
        void shouldNotRequireLockoutWhenUnderThreshold() {
            when(loginHistoryRepository.countFailedAttemptsSince(eq("test@example.com"), any(Instant.class)))
                    .thenReturn(3);

            boolean result = loginHistoryService.isAccountLockoutRequired("test@example.com");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should block IP when threshold exceeded")
        void shouldBlockIpWhenThresholdExceeded() {
            when(loginHistoryRepository.countFailedAttemptsFromIpSince(eq("192.168.1.1"), any(Instant.class)))
                    .thenReturn(15);

            boolean result = loginHistoryService.isIpBlocked("192.168.1.1");

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Anomaly management tests")
    class AnomalyManagementTests {

        @Test
        @DisplayName("should create anomaly")
        void shouldCreateAnomaly() {
            CreateAnomalyRequest request = CreateAnomalyRequest.builder()
                    .userId(testUserId)
                    .anomalyType(AnomalyType.NEW_COUNTRY)
                    .severity(AnomalySeverity.MEDIUM)
                    .description("Login from new country")
                    .build();

            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(anomalyRepository.save(any(LoginAnomaly.class))).thenAnswer(invocation -> {
                LoginAnomaly anomaly = invocation.getArgument(0);
                anomaly.setId(UUID.randomUUID());
                anomaly.setCreatedAt(Instant.now());
                return anomaly;
            });

            LoginAnomalyDto result = loginHistoryService.createAnomaly(request);

            assertThat(result).isNotNull();
            assertThat(result.getAnomalyType()).isEqualTo(AnomalyType.NEW_COUNTRY);
            assertThat(result.getSeverity()).isEqualTo(AnomalySeverity.MEDIUM);
        }

        @Test
        @DisplayName("should get user anomalies")
        void shouldGetUserAnomalies() {
            LoginAnomaly anomaly = LoginAnomaly.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .anomalyType(AnomalyType.VPN_DETECTED)
                    .severity(AnomalySeverity.LOW)
                    .createdAt(Instant.now())
                    .build();

            when(anomalyRepository.findByUserIdOrderByCreatedAtDesc(testUserId))
                    .thenReturn(Collections.singletonList(anomaly));

            List<LoginAnomalyDto> result = loginHistoryService.getUserAnomalies(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getAnomalyType()).isEqualTo(AnomalyType.VPN_DETECTED);
        }

        @Test
        @DisplayName("should get unresolved anomalies")
        void shouldGetUnresolvedAnomalies() {
            LoginAnomaly anomaly = LoginAnomaly.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .anomalyType(AnomalyType.HIGH_RISK_IP)
                    .severity(AnomalySeverity.HIGH)
                    .isResolved(false)
                    .createdAt(Instant.now())
                    .build();

            when(anomalyRepository.findByUserIdAndIsResolvedFalse(testUserId))
                    .thenReturn(Collections.singletonList(anomaly));

            List<LoginAnomalyDto> result = loginHistoryService.getUnresolvedAnomalies(testUserId);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).isResolved()).isFalse();
        }

        @Test
        @DisplayName("should resolve anomaly")
        void shouldResolveAnomaly() {
            UUID anomalyId = UUID.randomUUID();
            UUID resolvedBy = UUID.randomUUID();
            LoginAnomaly anomaly = LoginAnomaly.builder()
                    .id(anomalyId)
                    .user(testUser)
                    .anomalyType(AnomalyType.TOR_DETECTED)
                    .severity(AnomalySeverity.HIGH)
                    .isResolved(false)
                    .createdAt(Instant.now())
                    .build();

            when(anomalyRepository.findById(anomalyId)).thenReturn(Optional.of(anomaly));
            when(anomalyRepository.save(any(LoginAnomaly.class))).thenReturn(anomaly);

            LoginAnomalyDto result = loginHistoryService.resolveAnomaly(anomalyId, resolvedBy, "Verified as legitimate");

            verify(anomalyRepository).save(any(LoginAnomaly.class));
        }

        @Test
        @DisplayName("should throw when resolving non-existent anomaly")
        void shouldThrowWhenResolvingNonExistentAnomaly() {
            UUID anomalyId = UUID.randomUUID();
            when(anomalyRepository.findById(anomalyId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> loginHistoryService.resolveAnomaly(anomalyId, UUID.randomUUID(), "notes"))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Anomaly not found");
        }

        @Test
        @DisplayName("should resolve all user anomalies")
        void shouldResolveAllUserAnomalies() {
            UUID resolvedBy = UUID.randomUUID();

            loginHistoryService.resolveAllUserAnomalies(testUserId, resolvedBy);

            verify(anomalyRepository).resolveAllForUser(eq(testUserId), any(Instant.class), eq(resolvedBy));
        }
    }

    @Nested
    @DisplayName("User summary tests")
    class UserSummaryTests {

        @Test
        @DisplayName("should get user login summary")
        void shouldGetUserLoginSummary() {
            List<LoginHistory> logins = Arrays.asList(
                    LoginHistory.builder().loginStatus(LoginStatus.SUCCESS).build(),
                    LoginHistory.builder().loginStatus(LoginStatus.SUCCESS).build(),
                    LoginHistory.builder().loginStatus(LoginStatus.FAILED).build()
            );

            when(loginHistoryRepository.countByUserId(testUserId)).thenReturn(3L);
            when(loginHistoryRepository.findByUserId(testUserId)).thenReturn(logins);
            when(loginHistoryRepository.findLastSuccessfulLoginByUserId(testUserId))
                    .thenReturn(Optional.of(testLoginHistory));
            when(loginHistoryRepository.findDistinctDeviceIdsByUserId(testUserId))
                    .thenReturn(Arrays.asList("device-1", "device-2"));
            when(loginHistoryRepository.findDistinctCountriesByUserId(testUserId))
                    .thenReturn(Collections.singletonList("US"));
            when(anomalyRepository.countUnresolvedByUserId(testUserId)).thenReturn(1);

            UserLoginSummaryDto result = loginHistoryService.getUserLoginSummary(testUserId);

            assertThat(result.getTotalLogins()).isEqualTo(3);
            assertThat(result.getSuccessfulLogins()).isEqualTo(2);
            assertThat(result.getFailedLogins()).isEqualTo(1);
            assertThat(result.getKnownDevices()).hasSize(2);
            assertThat(result.getKnownCountries()).hasSize(1);
            assertThat(result.getUnresolvedAnomalies()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Cleanup tests")
    class CleanupTests {

        @Test
        @DisplayName("should delete old login history")
        void shouldDeleteOldLoginHistory() {
            when(loginHistoryRepository.deleteOlderThan(any(Instant.class))).thenReturn(100);

            int result = loginHistoryService.deleteOldLoginHistory(90);

            assertThat(result).isEqualTo(100);
            verify(loginHistoryRepository).deleteOlderThan(any(Instant.class));
        }

        @Test
        @DisplayName("should delete resolved anomalies")
        void shouldDeleteResolvedAnomalies() {
            when(anomalyRepository.deleteResolvedOlderThan(any(Instant.class))).thenReturn(50);

            int result = loginHistoryService.deleteResolvedAnomalies(90);

            assertThat(result).isEqualTo(50);
            verify(anomalyRepository).deleteResolvedOlderThan(any(Instant.class));
        }
    }
}
