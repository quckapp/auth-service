package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Login Anomaly Entity - Tracks suspicious login activities
 */
@Entity
@Table(name = "login_anomalies", indexes = {
    @Index(name = "idx_login_anomalies_user_id", columnList = "user_id"),
    @Index(name = "idx_login_anomalies_type", columnList = "anomalyType"),
    @Index(name = "idx_login_anomalies_severity", columnList = "severity"),
    @Index(name = "idx_login_anomalies_is_resolved", columnList = "isResolved")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginAnomaly {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AuthUser user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "login_history_id")
    private LoginHistory loginHistory;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private AnomalyType anomalyType;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private AnomalySeverity severity = AnomalySeverity.MEDIUM;

    @Column(length = 500)
    private String description;

    @Builder.Default
    private boolean isResolved = false;

    private Instant resolvedAt;

    private UUID resolvedBy;

    @Column(columnDefinition = "TEXT")
    private String resolutionNotes;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    // Helper methods
    public void resolve(UUID resolvedByUserId, String notes) {
        this.isResolved = true;
        this.resolvedAt = Instant.now();
        this.resolvedBy = resolvedByUserId;
        this.resolutionNotes = notes;
    }

    public boolean isCritical() {
        return severity == AnomalySeverity.CRITICAL;
    }
}
