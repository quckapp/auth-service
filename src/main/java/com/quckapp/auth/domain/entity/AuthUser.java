package com.quckapp.auth.domain.entity;

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
 * Auth User Entity - Core authentication record
 * Stores only auth-related data, not full user profile
 */
@Entity
@Table(name = "auth_users", indexes = {
    @Index(name = "idx_auth_users_email", columnList = "email"),
    @Index(name = "idx_auth_users_external_id", columnList = "externalId")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Builder.Default
    private boolean emailVerified = false;

    // Nullable for OAuth-only users
    private String passwordHash;

    // External user ID from main user service (NestJS)
    @Column(unique = true)
    private String externalId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AuthStatus status = AuthStatus.ACTIVE;

    // 2FA
    @Builder.Default
    private boolean twoFactorEnabled = false;

    private String twoFactorSecret;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "auth_user_backup_codes", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "backup_code")
    @Builder.Default
    private Set<String> backupCodes = new HashSet<>();

    // OAuth2 providers
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<OAuthConnection> oauthConnections = new HashSet<>();

    // RBAC - User Role Assignments
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<UserRoleAssignment> roleAssignments = new HashSet<>();

    // Active Sessions
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<ActiveSession> activeSessions = new HashSet<>();

    // Login History
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @Builder.Default
    private Set<LoginHistory> loginHistory = new HashSet<>();

    // Trusted Devices
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<TrustedDevice> trustedDevices = new HashSet<>();

    // Notification Preferences
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private UserNotificationPreferences notificationPreferences;

    // Security Preferences
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private UserSecurityPreferences securityPreferences;

    // Security
    @Builder.Default
    private int failedLoginAttempts = 0;

    private Instant lockedUntil;

    private Instant lastLoginAt;

    private String lastLoginIp;

    private Instant passwordChangedAt;

    @Builder.Default
    private boolean forcePasswordChange = false;

    // Audit
    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Helpers
    public boolean isLocked() {
        return lockedUntil != null && Instant.now().isBefore(lockedUntil);
    }

    public boolean isActive() {
        return status == AuthStatus.ACTIVE && !isLocked();
    }

    public void incrementFailedAttempts() {
        this.failedLoginAttempts++;
    }

    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }

    public enum AuthStatus {
        ACTIVE,
        INACTIVE,
        SUSPENDED,
        PENDING_VERIFICATION
    }
}
