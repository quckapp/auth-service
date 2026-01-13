package com.quckchat.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * User Settings Entity - User preferences and privacy settings
 * Has a One-to-One relationship with UserProfile (shared primary key)
 */
@Entity
@Table(name = "user_settings")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSettings {

    @Id
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "id")
    private UserProfile userProfile;

    // Appearance settings
    @Builder.Default
    private boolean darkMode = false;

    // Media & Storage settings
    @Builder.Default
    private boolean autoDownloadMedia = true;

    @Builder.Default
    private boolean saveToGallery = false;

    // Notification settings
    @Builder.Default
    private boolean pushNotifications = true;

    @Builder.Default
    private boolean messageNotifications = true;

    @Builder.Default
    private boolean groupNotifications = true;

    @Builder.Default
    private boolean callNotifications = true;

    @Builder.Default
    private boolean soundEnabled = true;

    @Builder.Default
    private boolean vibrationEnabled = true;

    @Builder.Default
    private boolean showPreview = true;

    @Builder.Default
    private boolean inAppNotifications = true;

    @Builder.Default
    private boolean notificationLight = true;

    // Privacy settings
    @Builder.Default
    private boolean readReceipts = true;

    @Builder.Default
    private boolean lastSeenVisible = true;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private VisibilityLevel profilePhotoVisibility = VisibilityLevel.EVERYONE;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private VisibilityLevel statusVisibility = VisibilityLevel.EVERYONE;

    // Security settings (complementing AuthUser 2FA)
    @Builder.Default
    private boolean fingerprintLock = false;

    // Blocked users
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "blocked_users", joinColumns = @JoinColumn(name = "user_settings_id"))
    @Column(name = "blocked_user_id")
    @Builder.Default
    private Set<UUID> blockedUserIds = new HashSet<>();

    // Audit timestamps
    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Helper methods
    public void blockUser(UUID userId) {
        if (blockedUserIds == null) {
            blockedUserIds = new HashSet<>();
        }
        blockedUserIds.add(userId);
    }

    public void unblockUser(UUID userId) {
        if (blockedUserIds != null) {
            blockedUserIds.remove(userId);
        }
    }

    public boolean isBlocked(UUID userId) {
        return blockedUserIds != null && blockedUserIds.contains(userId);
    }

    public static UserSettings createDefault(UserProfile userProfile) {
        return UserSettings.builder()
                .userProfile(userProfile)
                .darkMode(false)
                .autoDownloadMedia(true)
                .saveToGallery(false)
                .pushNotifications(true)
                .messageNotifications(true)
                .groupNotifications(true)
                .callNotifications(true)
                .soundEnabled(true)
                .vibrationEnabled(true)
                .showPreview(true)
                .inAppNotifications(true)
                .notificationLight(true)
                .readReceipts(true)
                .lastSeenVisible(true)
                .profilePhotoVisibility(VisibilityLevel.EVERYONE)
                .statusVisibility(VisibilityLevel.EVERYONE)
                .fingerprintLock(false)
                .blockedUserIds(new HashSet<>())
                .build();
    }
}
