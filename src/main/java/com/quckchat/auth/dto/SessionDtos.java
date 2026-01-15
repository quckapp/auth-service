package com.quckapp.auth.dto;

import com.quckapp.auth.domain.entity.ActiveSession;
import com.quckapp.auth.domain.entity.SessionActivity;
import com.quckapp.auth.domain.entity.SessionActivityType;
import lombok.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * DTOs for Session management operations
 */
public class SessionDtos {

    // ==================== Active Session DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ActiveSessionDto {
        private UUID id;
        private UUID userId;
        private String deviceId;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String osVersion;
        private String browserName;
        private String browserVersion;
        private String ipAddress;
        private String country;
        private String city;
        private BigDecimal latitude;
        private BigDecimal longitude;
        private boolean active;
        private boolean trusted;
        private Instant lastActivityAt;
        private Instant expiresAt;
        private Instant createdAt;
        private boolean current;

        public static ActiveSessionDto from(ActiveSession session) {
            return ActiveSessionDto.builder()
                    .id(session.getId())
                    .userId(session.getUser().getId())
                    .deviceId(session.getDeviceId())
                    .deviceName(session.getDeviceName())
                    .deviceType(session.getDeviceType())
                    .osName(session.getOsName())
                    .osVersion(session.getOsVersion())
                    .browserName(session.getBrowserName())
                    .browserVersion(session.getBrowserVersion())
                    .ipAddress(session.getIpAddress())
                    .country(session.getCountry())
                    .city(session.getCity())
                    .latitude(session.getLatitude())
                    .longitude(session.getLongitude())
                    .active(session.isActive())
                    .trusted(session.isTrusted())
                    .lastActivityAt(session.getLastActivityAt())
                    .expiresAt(session.getExpiresAt())
                    .createdAt(session.getCreatedAt())
                    .current(false)
                    .build();
        }

        public ActiveSessionDto markAsCurrent() {
            this.current = true;
            return this;
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionSummaryDto {
        private UUID userId;
        private int activeSessionCount;
        private Instant lastActivity;
        private List<String> deviceTypes;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CreateSessionRequest {
        private String sessionToken;
        private String deviceId;
        private String deviceName;
        private String deviceType;
        private String osName;
        private String osVersion;
        private String browserName;
        private String browserVersion;
        private String ipAddress;
        private String userAgent;
        private String country;
        private String city;
        private BigDecimal latitude;
        private BigDecimal longitude;
        private int expiryMinutes;
    }

    // ==================== Session Activity DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionActivityDto {
        private UUID id;
        private UUID sessionId;
        private SessionActivityType activityType;
        private String ipAddress;
        private String userAgent;
        private String details;
        private Instant createdAt;

        public static SessionActivityDto from(SessionActivity activity) {
            return SessionActivityDto.builder()
                    .id(activity.getId())
                    .sessionId(activity.getSession().getId())
                    .activityType(activity.getActivityType())
                    .ipAddress(activity.getIpAddress())
                    .userAgent(activity.getUserAgent())
                    .details(activity.getDetails())
                    .createdAt(activity.getCreatedAt())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserSessionsResponse {
        private UUID userId;
        private int totalSessions;
        private int activeSessions;
        private List<ActiveSessionDto> sessions;
        private UUID currentSessionId;
    }

    // ==================== Statistics DTOs ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionStatisticsDto {
        private long totalActiveSessions;
        private long activeUsersLast24h;
        private java.util.Map<String, Long> sessionsByDeviceType;
        private java.util.Map<String, Long> sessionsByCountry;
    }
}
