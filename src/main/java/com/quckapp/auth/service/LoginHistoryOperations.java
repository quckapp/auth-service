package com.quckapp.auth.service;

import com.quckapp.auth.dto.LoginHistoryDtos.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Interface for login history operations.
 * Extracted for testability with Java 25+ Mockito compatibility.
 */
public interface LoginHistoryOperations {

    // ==================== Login Recording ====================

    LoginHistoryDto recordLogin(RecordLoginRequest request);

    // ==================== Login History Retrieval ====================

    LoginHistoryDto getLoginHistory(UUID loginId);

    Page<LoginHistoryDto> getUserLoginHistory(UUID userId, Pageable pageable);

    List<LoginHistoryDto> getRecentLogins(UUID userId, int hours);

    Optional<LoginHistoryDto> getLastSuccessfulLogin(UUID userId);

    Page<LoginHistoryDto> getLoginsByIp(String ipAddress, Pageable pageable);

    Page<LoginHistoryDto> getHighRiskLogins(int threshold, Pageable pageable);

    List<LoginHistoryDto> getSuspiciousLogins(UUID userId);

    // ==================== Failed Attempt Tracking ====================

    int countRecentFailedAttempts(String email);

    int countRecentFailedAttemptsFromIp(String ipAddress);

    boolean isAccountLockoutRequired(String email);

    boolean isIpBlocked(String ipAddress);

    // ==================== Anomaly Management ====================

    LoginAnomalyDto createAnomaly(CreateAnomalyRequest request);

    LoginAnomalyDto getAnomaly(UUID anomalyId);

    List<LoginAnomalyDto> getUserAnomalies(UUID userId);

    List<LoginAnomalyDto> getUnresolvedAnomalies(UUID userId);

    Page<LoginAnomalyDto> getAllUnresolvedAnomalies(Pageable pageable);

    List<LoginAnomalyDto> getCriticalAnomalies();

    LoginAnomalyDto resolveAnomaly(UUID anomalyId, UUID resolvedBy, String notes);

    void resolveAllUserAnomalies(UUID userId, UUID resolvedBy);

    // ==================== User Summary ====================

    UserLoginSummaryDto getUserLoginSummary(UUID userId);

    // ==================== Statistics ====================

    LoginStatisticsDto getLoginStatistics(int days);

    AnomalyStatisticsDto getAnomalyStatistics(int days);

    // ==================== Cleanup ====================

    int deleteOldLoginHistory(int daysOld);

    int deleteResolvedAnomalies(int daysOld);
}
