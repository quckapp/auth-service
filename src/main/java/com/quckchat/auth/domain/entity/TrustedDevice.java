package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Trusted Device Entity - Stores devices that users have marked as trusted
 */
@Entity
@Table(name = "trusted_devices", indexes = {
    @Index(name = "idx_trusted_devices_user_id", columnList = "user_id"),
    @Index(name = "idx_trusted_devices_expires_at", columnList = "expiresAt")
}, uniqueConstraints = {
    @UniqueConstraint(name = "uk_user_device_fingerprint", columnNames = {"user_id", "deviceFingerprint"})
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TrustedDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AuthUser user;

    @Column(nullable = false, length = 255)
    private String deviceFingerprint;

    @Column(length = 255)
    private String deviceName;

    @Column(length = 50)
    private String deviceType;

    @Column(length = 100)
    private String osName;

    @Column(length = 100)
    private String browserName;

    @Builder.Default
    private boolean isTrusted = true;

    @Builder.Default
    private Instant trustedAt = Instant.now();

    @Builder.Default
    private Instant lastUsedAt = Instant.now();

    private Instant expiresAt;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    // Helper methods
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return isTrusted && !isExpired();
    }

    public void updateLastUsed() {
        this.lastUsedAt = Instant.now();
    }

    public void revokeTrust() {
        this.isTrusted = false;
    }
}
