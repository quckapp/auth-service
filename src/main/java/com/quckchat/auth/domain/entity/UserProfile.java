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
 * User Profile Entity - Full user profile data
 * Has a One-to-One relationship with AuthUser (shared primary key)
 */
@Entity
@Table(name = "user_profiles", indexes = {
    @Index(name = "idx_user_profiles_phone", columnList = "phoneNumber"),
    @Index(name = "idx_user_profiles_username", columnList = "username"),
    @Index(name = "idx_user_profiles_email", columnList = "email"),
    @Index(name = "idx_user_profiles_status", columnList = "status")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserProfile {

    @Id
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "id")
    private AuthUser authUser;

    // Core profile fields
    @Column(unique = true)
    private String phoneNumber;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, length = 100)
    private String displayName;

    @Column(length = 255)
    private String email;

    @Column(columnDefinition = "TEXT")
    private String avatar;

    @Column(length = 500)
    private String bio;

    @Column(columnDefinition = "TEXT")
    private String publicKey;

    // Status fields
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private UserStatus status = UserStatus.OFFLINE;

    private Instant lastSeen;

    @Builder.Default
    private boolean isActive = true;

    @Builder.Default
    private boolean isVerified = false;

    // Role and permissions
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private UserRole role = UserRole.USER;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_permissions", joinColumns = @JoinColumn(name = "user_profile_id"))
    @Column(name = "permission", length = 50)
    @Builder.Default
    private Set<String> permissions = new HashSet<>();

    // Moderation fields
    @Builder.Default
    private boolean isBanned = false;

    @Column(length = 500)
    private String banReason;

    private Instant bannedAt;

    private UUID bannedBy;

    // Linked devices relationship
    @OneToMany(mappedBy = "userProfile", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<LinkedDevice> linkedDevices = new HashSet<>();

    // User settings relationship
    @OneToOne(mappedBy = "userProfile", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private UserSettings settings;

    // Audit timestamps
    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Helper methods
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    public boolean hasAdminAccess() {
        return role != null && role.hasAdminAccess();
    }

    public boolean hasModeratorAccess() {
        return role != null && role.hasModeratorAccess();
    }

    public void ban(UUID bannedBy, String reason) {
        this.isBanned = true;
        this.banReason = reason;
        this.bannedAt = Instant.now();
        this.bannedBy = bannedBy;
    }

    public void unban() {
        this.isBanned = false;
        this.banReason = null;
        this.bannedAt = null;
        this.bannedBy = null;
    }

    public void goOnline() {
        this.status = UserStatus.ONLINE;
        this.lastSeen = Instant.now();
    }

    public void goOffline() {
        this.status = UserStatus.OFFLINE;
        this.lastSeen = Instant.now();
    }

    public void updateLastSeen() {
        this.lastSeen = Instant.now();
    }
}
