package com.quckapp.auth.dto;

import com.quckapp.auth.domain.entity.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * DTOs for Login History and Anomaly operations
 */
public class LoginHistoryDtos {

    // ==================== Login History DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginHistoryDto {
        private UUID id;
        private UUID userId;
        private String email;
        private LoginStatus loginStatus;
        private LoginMethod loginMethod;
        private String ipAddress;
        private String deviceId;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String browserName;
        private String country;
        private String countryCode;
        private String city;
        private boolean vpn;
        private boolean tor;
        private boolean proxy;
        private int riskScore;
        private String failureReason;
        private boolean twoFactorUsed;
        private String twoFactorMethod;
        private Instant createdAt;

        public static LoginHistoryDto from(LoginHistory history) {
            return LoginHistoryDto.builder()
                    .id(history.getId())
                    .userId(history.getUser() != null ? history.getUser().getId() : null)
                    .email(history.getEmail())
                    .loginStatus(history.getLoginStatus())
                    .loginMethod(history.getLoginMethod())
                    .ipAddress(history.getIpAddress())
                    .deviceId(history.getDeviceId())
                    .deviceName(history.getDeviceName())
                    .deviceType(history.getDeviceType())
                    .osName(history.getOsName())
                    .browserName(history.getBrowserName())
                    .country(history.getCountry())
                    .countryCode(history.getCountryCode())
                    .city(history.getCity())
                    .vpn(history.isVpn())
                    .tor(history.isTor())
                    .proxy(history.isProxy())
                    .riskScore(history.getRiskScore())
                    .failureReason(history.getFailureReason())
                    .twoFactorUsed(history.isTwoFactorUsed())
                    .twoFactorMethod(history.getTwoFactorMethod())
                    .createdAt(history.getCreatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RecordLoginRequest {
        private UUID userId;
        private String email;
        private LoginStatus loginStatus;
        private LoginMethod loginMethod;
        private String ipAddress;
        private String userAgent;
        private String deviceId;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String osVersion;
        private String browserName;
        private String browserVersion;
        private String country;
        private String countryCode;
        private String region;
        private String city;
        private String postalCode;
        private BigDecimal latitude;
        private BigDecimal longitude;
        private String isp;
        private boolean vpn;
        private boolean tor;
        private boolean proxy;
        private int riskScore;
        private String failureReason;
        private boolean twoFactorUsed;
        private String twoFactorMethod;
        private UUID sessionId;
    }

    // ==================== Login Anomaly DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginAnomalyDto {
        private UUID id;
        private UUID userId;
        private UUID loginHistoryId;
        private AnomalyType anomalyType;
        private AnomalySeverity severity;
        private String description;
        private boolean resolved;
        private Instant resolvedAt;
        private UUID resolvedBy;
        private String resolutionNotes;
        private Instant createdAt;

        public static LoginAnomalyDto from(LoginAnomaly anomaly) {
            return LoginAnomalyDto.builder()
                    .id(anomaly.getId())
                    .userId(anomaly.getUser().getId())
                    .loginHistoryId(anomaly.getLoginHistory() != null ? anomaly.getLoginHistory().getId() : null)
                    .anomalyType(anomaly.getAnomalyType())
                    .severity(anomaly.getSeverity())
                    .description(anomaly.getDescription())
                    .resolved(anomaly.isResolved())
                    .resolvedAt(anomaly.getResolvedAt())
                    .resolvedBy(anomaly.getResolvedBy())
                    .resolutionNotes(anomaly.getResolutionNotes())
                    .createdAt(anomaly.getCreatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CreateAnomalyRequest {
        private UUID userId;
        private UUID loginHistoryId;
        private AnomalyType anomalyType;
        private AnomalySeverity severity;
        private String description;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResolveAnomalyRequest {
        private String notes;
    }

    // ==================== Statistics DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginStatisticsDto {
        private long totalLogins;
        private long successfulLogins;
        private long failedLogins;
        private Map<String, Long> loginsByStatus;
        private Map<String, Long> loginsByMethod;
        private Map<String, Long> loginsByCountry;
        private List<DailyLoginCount> dailyLogins;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DailyLoginCount {
        private String date;
        private long count;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AnomalyStatisticsDto {
        private long totalAnomalies;
        private long unresolvedAnomalies;
        private Map<String, Long> anomaliesByType;
        private Map<String, Long> unresolvedBySeverity;
        private List<DailyAnomalyCount> dailyAnomalies;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DailyAnomalyCount {
        private String date;
        private long count;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserLoginSummaryDto {
        private UUID userId;
        private long totalLogins;
        private long successfulLogins;
        private long failedLogins;
        private LoginHistoryDto lastSuccessfulLogin;
        private List<String> knownDevices;
        private List<String> knownCountries;
        private int unresolvedAnomalies;
    }
}
