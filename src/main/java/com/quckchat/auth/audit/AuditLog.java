package com.quckchat.auth.audit;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Audit Log - Tracks all authentication events
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_logs_user_id", columnList = "userId"),
    @Index(name = "idx_audit_logs_event_type", columnList = "eventType"),
    @Index(name = "idx_audit_logs_created_at", columnList = "createdAt"),
    @Index(name = "idx_audit_logs_ip", columnList = "ipAddress")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private UUID userId;

    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditStatus status;

    private String ipAddress;

    private String userAgent;

    private String deviceId;

    // Geolocation
    private String country;
    private String city;

    // Additional context
    @Column(columnDefinition = "TEXT")
    private String details;

    // For failed attempts
    private String failureReason;

    // Request metadata
    private String requestId;

    private String sessionId;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    public enum AuditEventType {
        // Authentication
        LOGIN_SUCCESS,
        LOGIN_FAILED,
        LOGOUT,
        TOKEN_REFRESH,
        TOKEN_REVOKED,

        // 2FA
        TWO_FACTOR_ENABLED,
        TWO_FACTOR_DISABLED,
        TWO_FACTOR_VERIFIED,
        TWO_FACTOR_FAILED,

        // Password
        PASSWORD_CHANGED,
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_COMPLETED,

        // OAuth
        OAUTH_LINKED,
        OAUTH_UNLINKED,
        OAUTH_LOGIN,

        // Account
        ACCOUNT_CREATED,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        ACCOUNT_SUSPENDED,

        // API Keys
        API_KEY_CREATED,
        API_KEY_REVOKED,
        API_KEY_USED,

        // Sessions
        SESSION_CREATED,
        SESSION_TERMINATED,
        ALL_SESSIONS_TERMINATED,

        // Security
        SUSPICIOUS_ACTIVITY,
        IP_BLOCKED,
        RATE_LIMITED
    }

    public enum AuditStatus {
        SUCCESS,
        FAILURE,
        WARNING
    }
}
