package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.*;
import com.quckapp.auth.dto.LoginHistoryDtos.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for Login History and Anomaly management
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class LoginHistoryService implements LoginHistoryOperations {

    private final LoginHistoryRepository loginHistoryRepository;
    private final LoginAnomalyRepository anomalyRepository;
    private final AuthUserRepository authUserRepository;

    private static final int FAILED_ATTEMPTS_THRESHOLD = 5;
    private static final int FAILED_ATTEMPTS_WINDOW_MINUTES = 15;
    private static final int HIGH_RISK_THRESHOLD = 70;

    // ==================== Login Recording ====================

    public LoginHistoryDto recordLogin(RecordLoginRequest request) {
        log.info("Recording login attempt for: {}", request.getEmail());

        AuthUser user = null;
        if (request.getUserId() != null) {
            user = authUserRepository.findById(request.getUserId()).orElse(null);
        }

        LoginHistory history = LoginHistory.builder()
                .user(user)
                .email(request.getEmail())
                .loginStatus(request.getLoginStatus())
                .loginMethod(request.getLoginMethod() != null ? request.getLoginMethod() : LoginMethod.PASSWORD)
                .ipAddress(request.getIpAddress())
                .userAgent(request.getUserAgent())
                .deviceId(request.getDeviceId())
                .deviceName(request.getDeviceName())
                .deviceType(request.getDeviceType())
                .osName(request.getOsName())
                .osVersion(request.getOsVersion())
                .browserName(request.getBrowserName())
                .browserVersion(request.getBrowserVersion())
                .country(request.getCountry())
                .countryCode(request.getCountryCode())
                .region(request.getRegion())
                .city(request.getCity())
                .postalCode(request.getPostalCode())
                .latitude(request.getLatitude())
                .longitude(request.getLongitude())
                .isp(request.getIsp())
                .isVpn(request.isVpn())
                .isTor(request.isTor())
                .isProxy(request.isProxy())
                .riskScore(request.getRiskScore())
                .failureReason(request.getFailureReason())
                .twoFactorUsed(request.isTwoFactorUsed())
                .twoFactorMethod(request.getTwoFactorMethod())
                .sessionId(request.getSessionId())
                .build();

        // Pre-compute new country/device BEFORE saving (so the current login isn't included in the query)
        boolean isNewCountry = false;
        boolean isNewDevice = false;
        if (user != null && request.getLoginStatus() == LoginStatus.SUCCESS) {
            if (request.getCountryCode() != null) {
                List<String> knownCountries = loginHistoryRepository.findDistinctCountriesByUserId(user.getId());
                isNewCountry = !knownCountries.contains(request.getCountryCode());
            }
            if (request.getDeviceId() != null) {
                List<String> knownDevices = loginHistoryRepository.findDistinctDeviceIdsByUserId(user.getId());
                isNewDevice = !knownDevices.contains(request.getDeviceId());
            }
        }

        history = loginHistoryRepository.save(history);

        // Check for anomalies if login was successful and user exists
        if (user != null && request.getLoginStatus() == LoginStatus.SUCCESS) {
            detectAnomalies(user, history, isNewCountry, isNewDevice);
        }

        log.info("Login recorded: {} - {}", request.getEmail(), request.getLoginStatus());
        return LoginHistoryDto.from(history);
    }

    // ==================== Login History Retrieval ====================

    @Transactional(readOnly = true)
    public LoginHistoryDto getLoginHistory(UUID loginId) {
        LoginHistory history = findLoginHistoryOrThrow(loginId);
        return LoginHistoryDto.from(history);
    }

    @Transactional(readOnly = true)
    public Page<LoginHistoryDto> getUserLoginHistory(UUID userId, Pageable pageable) {
        return loginHistoryRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable)
                .map(LoginHistoryDto::from);
    }

    @Transactional(readOnly = true)
    public List<LoginHistoryDto> getRecentLogins(UUID userId, int hours) {
        Instant since = Instant.now().minus(hours, ChronoUnit.HOURS);
        return loginHistoryRepository.findRecentByUserId(userId, since).stream()
                .map(LoginHistoryDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Optional<LoginHistoryDto> getLastSuccessfulLogin(UUID userId) {
        return loginHistoryRepository.findLastSuccessfulLoginByUserId(userId)
                .map(LoginHistoryDto::from);
    }

    @Transactional(readOnly = true)
    public Page<LoginHistoryDto> getLoginsByIp(String ipAddress, Pageable pageable) {
        return loginHistoryRepository.findByIpAddressOrderByCreatedAtDesc(ipAddress, pageable)
                .map(LoginHistoryDto::from);
    }

    @Transactional(readOnly = true)
    public Page<LoginHistoryDto> getHighRiskLogins(int threshold, Pageable pageable) {
        return loginHistoryRepository.findHighRiskLogins(threshold, pageable)
                .map(LoginHistoryDto::from);
    }

    @Transactional(readOnly = true)
    public List<LoginHistoryDto> getSuspiciousLogins(UUID userId) {
        return loginHistoryRepository.findSuspiciousLoginsByUserId(userId, HIGH_RISK_THRESHOLD).stream()
                .map(LoginHistoryDto::from)
                .collect(Collectors.toList());
    }

    // ==================== Failed Attempt Tracking ====================

    @Transactional(readOnly = true)
    public int countRecentFailedAttempts(String email) {
        Instant since = Instant.now().minus(FAILED_ATTEMPTS_WINDOW_MINUTES, ChronoUnit.MINUTES);
        return loginHistoryRepository.countFailedAttemptsSince(email, since);
    }

    @Transactional(readOnly = true)
    public int countRecentFailedAttemptsFromIp(String ipAddress) {
        Instant since = Instant.now().minus(FAILED_ATTEMPTS_WINDOW_MINUTES, ChronoUnit.MINUTES);
        return loginHistoryRepository.countFailedAttemptsFromIpSince(ipAddress, since);
    }

    @Transactional(readOnly = true)
    public boolean isAccountLockoutRequired(String email) {
        return countRecentFailedAttempts(email) >= FAILED_ATTEMPTS_THRESHOLD;
    }

    @Transactional(readOnly = true)
    public boolean isIpBlocked(String ipAddress) {
        return countRecentFailedAttemptsFromIp(ipAddress) >= FAILED_ATTEMPTS_THRESHOLD * 3;
    }

    // ==================== Anomaly Detection ====================

    private void detectAnomalies(AuthUser user, LoginHistory history, boolean isNewCountry, boolean isNewDevice) {
        List<CreateAnomalyRequest> anomalies = new ArrayList<>();

        // Check for VPN/Tor/Proxy
        if (history.isVpn()) {
            anomalies.add(createAnomalyRequest(user.getId(), history.getId(),
                    AnomalyType.VPN_DETECTED, AnomalySeverity.LOW, "VPN detected during login"));
        }
        if (history.isTor()) {
            anomalies.add(createAnomalyRequest(user.getId(), history.getId(),
                    AnomalyType.TOR_DETECTED, AnomalySeverity.HIGH, "Tor network detected during login"));
        }
        if (history.isProxy()) {
            anomalies.add(createAnomalyRequest(user.getId(), history.getId(),
                    AnomalyType.PROXY_DETECTED, AnomalySeverity.MEDIUM, "Proxy detected during login"));
        }

        // Check for high risk score
        if (history.getRiskScore() > HIGH_RISK_THRESHOLD) {
            anomalies.add(createAnomalyRequest(user.getId(), history.getId(),
                    AnomalyType.HIGH_RISK_IP, AnomalySeverity.HIGH,
                    "High risk score: " + history.getRiskScore()));
        }

        // Check for new country (pre-computed before save)
        if (isNewCountry) {
            anomalies.add(createAnomalyRequest(user.getId(), history.getId(),
                    AnomalyType.NEW_COUNTRY, AnomalySeverity.MEDIUM,
                    "Login from new country: " + history.getCountry()));
        }

        // Check for new device (pre-computed before save)
        if (isNewDevice) {
            anomalies.add(createAnomalyRequest(user.getId(), history.getId(),
                    AnomalyType.NEW_DEVICE, AnomalySeverity.LOW,
                    "Login from new device: " + history.getDeviceName()));
        }

        // Record all detected anomalies
        for (CreateAnomalyRequest anomaly : anomalies) {
            createAnomaly(anomaly);
        }
    }

    private CreateAnomalyRequest createAnomalyRequest(UUID userId, UUID loginHistoryId,
                                                      AnomalyType type, AnomalySeverity severity, String description) {
        return CreateAnomalyRequest.builder()
                .userId(userId)
                .loginHistoryId(loginHistoryId)
                .anomalyType(type)
                .severity(severity)
                .description(description)
                .build();
    }

    // ==================== Anomaly Management ====================

    public LoginAnomalyDto createAnomaly(CreateAnomalyRequest request) {
        log.info("Creating anomaly for user {}: {}", request.getUserId(), request.getAnomalyType());

        AuthUser user = authUserRepository.findById(request.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found: " + request.getUserId()));

        LoginHistory loginHistory = null;
        if (request.getLoginHistoryId() != null) {
            loginHistory = loginHistoryRepository.findById(request.getLoginHistoryId()).orElse(null);
        }

        LoginAnomaly anomaly = LoginAnomaly.builder()
                .user(user)
                .loginHistory(loginHistory)
                .anomalyType(request.getAnomalyType())
                .severity(request.getSeverity() != null ? request.getSeverity() : AnomalySeverity.MEDIUM)
                .description(request.getDescription())
                .isResolved(false)
                .build();

        anomaly = anomalyRepository.save(anomaly);
        log.info("Anomaly created: {}", anomaly.getId());
        return LoginAnomalyDto.from(anomaly);
    }

    @Transactional(readOnly = true)
    public LoginAnomalyDto getAnomaly(UUID anomalyId) {
        LoginAnomaly anomaly = findAnomalyOrThrow(anomalyId);
        return LoginAnomalyDto.from(anomaly);
    }

    @Transactional(readOnly = true)
    public List<LoginAnomalyDto> getUserAnomalies(UUID userId) {
        return anomalyRepository.findByUserIdOrderByCreatedAtDesc(userId).stream()
                .map(LoginAnomalyDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<LoginAnomalyDto> getUnresolvedAnomalies(UUID userId) {
        return anomalyRepository.findByUserIdAndIsResolvedFalse(userId).stream()
                .map(LoginAnomalyDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Page<LoginAnomalyDto> getAllUnresolvedAnomalies(Pageable pageable) {
        return anomalyRepository.findByIsResolvedFalseOrderByCreatedAtDesc(pageable)
                .map(LoginAnomalyDto::from);
    }

    @Transactional(readOnly = true)
    public List<LoginAnomalyDto> getCriticalAnomalies() {
        return anomalyRepository.findCriticalUnresolved().stream()
                .map(LoginAnomalyDto::from)
                .collect(Collectors.toList());
    }

    public LoginAnomalyDto resolveAnomaly(UUID anomalyId, UUID resolvedBy, String notes) {
        log.info("Resolving anomaly: {}", anomalyId);
        LoginAnomaly anomaly = findAnomalyOrThrow(anomalyId);

        anomaly.resolve(resolvedBy, notes);
        anomaly = anomalyRepository.save(anomaly);

        log.info("Anomaly resolved: {}", anomalyId);
        return LoginAnomalyDto.from(anomaly);
    }

    public void resolveAllUserAnomalies(UUID userId, UUID resolvedBy) {
        log.info("Resolving all anomalies for user: {}", userId);
        anomalyRepository.resolveAllForUser(userId, Instant.now(), resolvedBy);
        log.info("All anomalies resolved for user: {}", userId);
    }

    // ==================== User Summary ====================

    @Transactional(readOnly = true)
    public UserLoginSummaryDto getUserLoginSummary(UUID userId) {
        long totalLogins = loginHistoryRepository.countByUserId(userId);

        List<LoginHistory> userLogins = loginHistoryRepository.findByUserId(userId);
        long successfulLogins = userLogins.stream()
                .filter(l -> l.getLoginStatus() == LoginStatus.SUCCESS)
                .count();

        Optional<LoginHistoryDto> lastSuccessful = getLastSuccessfulLogin(userId);
        List<String> knownDevices = loginHistoryRepository.findDistinctDeviceIdsByUserId(userId);
        List<String> knownCountries = loginHistoryRepository.findDistinctCountriesByUserId(userId);
        int unresolvedAnomalies = anomalyRepository.countUnresolvedByUserId(userId);

        return UserLoginSummaryDto.builder()
                .userId(userId)
                .totalLogins(totalLogins)
                .successfulLogins(successfulLogins)
                .failedLogins(totalLogins - successfulLogins)
                .lastSuccessfulLogin(lastSuccessful.orElse(null))
                .knownDevices(knownDevices)
                .knownCountries(knownCountries)
                .unresolvedAnomalies(unresolvedAnomalies)
                .build();
    }

    // ==================== Statistics ====================

    @Transactional(readOnly = true)
    public LoginStatisticsDto getLoginStatistics(int days) {
        Instant since = Instant.now().minus(days, ChronoUnit.DAYS);

        Map<String, Long> byStatus = loginHistoryRepository.countByLoginStatusSince(since).stream()
                .collect(Collectors.toMap(
                        arr -> ((LoginStatus) arr[0]).name(),
                        arr -> (Long) arr[1]
                ));

        Map<String, Long> byMethod = loginHistoryRepository.countSuccessfulByLoginMethodSince(since).stream()
                .collect(Collectors.toMap(
                        arr -> ((LoginMethod) arr[0]).name(),
                        arr -> (Long) arr[1]
                ));

        Map<String, Long> byCountry = loginHistoryRepository.countByCountrySince(since).stream()
                .limit(10)
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));

        List<DailyLoginCount> dailyLogins = loginHistoryRepository.countDailyLoginsSince(since).stream()
                .map(arr -> DailyLoginCount.builder()
                        .date(arr[0].toString())
                        .count((Long) arr[1])
                        .build())
                .collect(Collectors.toList());

        long successful = byStatus.getOrDefault(LoginStatus.SUCCESS.name(), 0L);
        long total = byStatus.values().stream().mapToLong(Long::longValue).sum();

        return LoginStatisticsDto.builder()
                .totalLogins(total)
                .successfulLogins(successful)
                .failedLogins(total - successful)
                .loginsByStatus(byStatus)
                .loginsByMethod(byMethod)
                .loginsByCountry(byCountry)
                .dailyLogins(dailyLogins)
                .build();
    }

    @Transactional(readOnly = true)
    public AnomalyStatisticsDto getAnomalyStatistics(int days) {
        Instant since = Instant.now().minus(days, ChronoUnit.DAYS);

        Map<String, Long> byType = anomalyRepository.countByTypeSince(since).stream()
                .collect(Collectors.toMap(
                        arr -> ((AnomalyType) arr[0]).name(),
                        arr -> (Long) arr[1]
                ));

        Map<String, Long> unresolvedBySeverity = anomalyRepository.countUnresolvedBySeverity().stream()
                .collect(Collectors.toMap(
                        arr -> ((AnomalySeverity) arr[0]).name(),
                        arr -> (Long) arr[1]
                ));

        List<DailyAnomalyCount> dailyAnomalies = anomalyRepository.countDailyAnomaliesSince(since).stream()
                .map(arr -> DailyAnomalyCount.builder()
                        .date(arr[0].toString())
                        .count((Long) arr[1])
                        .build())
                .collect(Collectors.toList());

        return AnomalyStatisticsDto.builder()
                .totalAnomalies(byType.values().stream().mapToLong(Long::longValue).sum())
                .unresolvedAnomalies(anomalyRepository.countAllUnresolved())
                .anomaliesByType(byType)
                .unresolvedBySeverity(unresolvedBySeverity)
                .dailyAnomalies(dailyAnomalies)
                .build();
    }

    // ==================== Cleanup ====================

    public int deleteOldLoginHistory(int daysOld) {
        Instant threshold = Instant.now().minus(daysOld, ChronoUnit.DAYS);
        log.info("Deleting login history older than {} days", daysOld);
        int deleted = loginHistoryRepository.deleteOlderThan(threshold);
        log.info("Deleted {} old login history records", deleted);
        return deleted;
    }

    public int deleteResolvedAnomalies(int daysOld) {
        Instant threshold = Instant.now().minus(daysOld, ChronoUnit.DAYS);
        log.info("Deleting resolved anomalies older than {} days", daysOld);
        int deleted = anomalyRepository.deleteResolvedOlderThan(threshold);
        log.info("Deleted {} old resolved anomalies", deleted);
        return deleted;
    }

    // ==================== Helper Methods ====================

    private LoginHistory findLoginHistoryOrThrow(UUID loginId) {
        return loginHistoryRepository.findById(loginId)
                .orElseThrow(() -> new RuntimeException("Login history not found: " + loginId));
    }

    private LoginAnomaly findAnomalyOrThrow(UUID anomalyId) {
        return anomalyRepository.findById(anomalyId)
                .orElseThrow(() -> new RuntimeException("Anomaly not found: " + anomalyId));
    }
}
