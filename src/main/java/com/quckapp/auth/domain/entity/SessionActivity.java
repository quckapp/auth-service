package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Session Activity Entity - Logs activities within a session
 */
@Entity
@Table(name = "session_activities", indexes = {
    @Index(name = "idx_session_activities_session_id", columnList = "session_id"),
    @Index(name = "idx_session_activities_type", columnList = "activityType"),
    @Index(name = "idx_session_activities_created_at", columnList = "createdAt")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SessionActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private ActiveSession session;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private SessionActivityType activityType;

    @Column(length = 45)
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String userAgent;

    @Column(columnDefinition = "TEXT")
    private String details;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;
}
