package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Active Session Entity - Tracks user sessions across devices
 */
@Entity
@Table(name = "active_sessions", indexes = {
    @Index(name = "idx_active_sessions_user_id", columnList = "user_id"),
    @Index(name = "idx_active_sessions_device_id", columnList = "deviceId"),
    @Index(name = "idx_active_sessions_is_active", columnList = "isActive"),
    @Index(name = "idx_active_sessions_expires_at", columnList = "expiresAt"),
    @Index(name = "idx_active_sessions_last_activity", columnList = "lastActivityAt")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ActiveSession {

    @Id
    private UUID id;

    /**
     * Generate UUID if not already set (allows pre-setting ID from JWT sessionId)
     */
    @PrePersist
    public void ensureId() {
        if (this.id == null) {
            this.id = UUID.randomUUID();
        }
    }

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AuthUser user;

    @Column(nullable = false, unique = true)
    private String sessionTokenHash;

    private String deviceId;

    private String deviceName;

    @Column(length = 50)
    @Builder.Default
    private String deviceType = "UNKNOWN";

    @Column(length = 100)
    private String osName;

    @Column(length = 50)
    private String osVersion;

    @Column(length = 100)
    private String browserName;

    @Column(length = 50)
    private String browserVersion;

    @Column(length = 45)
    private String ipAddress;

    @Column(length = 100)
    private String country;

    @Column(length = 100)
    private String city;

    @Column(precision = 10, scale = 8)
    private BigDecimal latitude;

    @Column(precision = 11, scale = 8)
    private BigDecimal longitude;

    @Builder.Default
    private boolean isActive = true;

    @Builder.Default
    private boolean isTrusted = false;

    @Builder.Default
    private Instant lastActivityAt = Instant.now();

    @Column(nullable = false)
    private Instant expiresAt;

    @OneToMany(mappedBy = "session", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<SessionActivity> activities = new HashSet<>();

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    // Helper methods
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return isActive && !isExpired();
    }

    public void updateActivity() {
        this.lastActivityAt = Instant.now();
    }

    public void terminate() {
        this.isActive = false;
    }

    public void addActivity(SessionActivityType activityType, String ipAddress, String userAgent, String details) {
        SessionActivity activity = SessionActivity.builder()
            .session(this)
            .activityType(activityType)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .details(details)
            .build();
        activities.add(activity);
    }
}
