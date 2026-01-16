package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.time.LocalTime;
import java.util.UUID;

/**
 * User Notification Preferences Entity
 */
@Entity
@Table(name = "user_notification_preferences")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserNotificationPreferences {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private AuthUser user;

    // Email Notifications
    @Builder.Default
    private boolean emailMarketing = false;

    @Builder.Default
    private boolean emailSecurityAlerts = true;

    @Builder.Default
    private boolean emailLoginAlerts = true;

    @Builder.Default
    private boolean emailWeeklyDigest = false;

    @Builder.Default
    private boolean emailProductUpdates = false;

    // Push Notification Categories
    @Builder.Default
    private boolean pushDirectMessages = true;

    @Builder.Default
    private boolean pushMentions = true;

    @Builder.Default
    private boolean pushReplies = true;

    @Builder.Default
    private boolean pushLikes = true;

    @Builder.Default
    private boolean pushFollows = true;

    @Builder.Default
    private boolean pushSystemAlerts = true;

    // Quiet Hours
    @Builder.Default
    private boolean quietHoursEnabled = false;

    private LocalTime quietHoursStart;

    private LocalTime quietHoursEnd;

    @Column(length = 50)
    @Builder.Default
    private String quietHoursTimezone = "UTC";

    // SMS Notifications
    @Builder.Default
    private boolean smsEnabled = false;

    @Builder.Default
    private boolean smsSecurityOnly = true;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Helper methods
    public boolean isInQuietHours(LocalTime currentTime) {
        if (!quietHoursEnabled || quietHoursStart == null || quietHoursEnd == null) {
            return false;
        }

        if (quietHoursStart.isBefore(quietHoursEnd)) {
            return !currentTime.isBefore(quietHoursStart) && currentTime.isBefore(quietHoursEnd);
        } else {
            // Overnight quiet hours (e.g., 22:00 to 07:00)
            return !currentTime.isBefore(quietHoursStart) || currentTime.isBefore(quietHoursEnd);
        }
    }
}
