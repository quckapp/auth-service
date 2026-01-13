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
 * API Key - For service-to-service authentication
 */
@Entity
@Table(name = "api_keys", indexes = {
    @Index(name = "idx_api_keys_key_hash", columnList = "keyHash"),
    @Index(name = "idx_api_keys_user_id", columnList = "user_id")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    // Only store hash, never plain text
    @Column(nullable = false, unique = true)
    private String keyHash;

    // Prefix for identification (e.g., "qc_live_" or "qc_test_")
    @Column(nullable = false)
    private String keyPrefix;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private AuthUser user;

    // For service API keys (not user-owned)
    private String serviceName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "api_key_permissions", joinColumns = @JoinColumn(name = "api_key_id"))
    @Column(name = "permission")
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Set<ApiPermission> permissions = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "api_key_ip_whitelist", joinColumns = @JoinColumn(name = "api_key_id"))
    @Column(name = "ip_address")
    @Builder.Default
    private Set<String> ipWhitelist = new HashSet<>();

    @Builder.Default
    private boolean active = true;

    private Instant expiresAt;

    private Instant lastUsedAt;

    private String lastUsedIp;

    @Builder.Default
    private long usageCount = 0;

    // Rate limiting
    private Integer rateLimitPerMinute;

    private Integer rateLimitPerHour;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    public boolean isValid() {
        if (!active) return false;
        if (expiresAt != null && Instant.now().isAfter(expiresAt)) return false;
        return true;
    }

    public boolean hasPermission(ApiPermission permission) {
        return permissions.contains(permission) || permissions.contains(ApiPermission.ADMIN);
    }

    public boolean isIpAllowed(String ip) {
        if (ipWhitelist.isEmpty()) return true;
        return ipWhitelist.contains(ip);
    }

    public void recordUsage(String ip) {
        this.lastUsedAt = Instant.now();
        this.lastUsedIp = ip;
        this.usageCount++;
    }

    public enum ApiPermission {
        ADMIN,           // Full access
        READ_USER,       // Read user data
        WRITE_USER,      // Modify user data
        VALIDATE_TOKEN,  // Validate JWT tokens
        REVOKE_TOKEN,    // Revoke tokens
        READ_AUDIT,      // Read audit logs
        MANAGE_SESSIONS  // Manage user sessions
    }
}
