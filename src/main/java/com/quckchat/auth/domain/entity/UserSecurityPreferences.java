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
 * User Security Preferences Entity
 */
@Entity
@Table(name = "user_security_preferences")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSecurityPreferences {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private AuthUser user;

    // Login Security
    @Builder.Default
    private boolean require2faForSensitiveActions = false;

    @Builder.Default
    private boolean loginNotificationEnabled = true;

    @Builder.Default
    private boolean newDeviceNotification = true;

    @Builder.Default
    private boolean suspiciousActivityNotification = true;

    // Session Preferences
    @Builder.Default
    private int sessionTimeoutMinutes = 1440; // 24 hours

    @Builder.Default
    private int maxConcurrentSessions = 5;

    @Builder.Default
    private boolean rememberTrustedDevices = true;

    @Builder.Default
    private int trustedDeviceExpiryDays = 30;

    // Password Preferences
    @Builder.Default
    private int passwordExpiryDays = 0; // 0 means no expiry

    @Builder.Default
    private boolean requirePasswordChangeOnNextLogin = false;

    // IP Restrictions
    @Builder.Default
    private boolean ipWhitelistEnabled = false;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "user_ip_whitelist", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "ip_address")
    @Builder.Default
    private Set<String> ipWhitelist = new HashSet<>();

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Helper methods
    public boolean isIpAllowed(String ipAddress) {
        if (!ipWhitelistEnabled || ipWhitelist.isEmpty()) {
            return true;
        }
        return ipWhitelist.contains(ipAddress);
    }

    public boolean isPasswordExpired(Instant passwordChangedAt) {
        if (passwordExpiryDays <= 0 || passwordChangedAt == null) {
            return false;
        }
        Instant expiryDate = passwordChangedAt.plusSeconds(passwordExpiryDays * 24L * 60 * 60);
        return Instant.now().isAfter(expiryDate);
    }
}
