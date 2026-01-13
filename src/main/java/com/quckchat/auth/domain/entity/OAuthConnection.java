package com.quckchat.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * OAuth Connection - Links external OAuth providers to auth users
 */
@Entity
@Table(name = "oauth_connections", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"provider", "providerUserId"})
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuthConnection {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AuthUser user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OAuthProvider provider;

    @Column(nullable = false)
    private String providerUserId;

    private String accessToken;

    private String refreshToken;

    private Instant tokenExpiresAt;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    private Instant lastUsedAt;

    public enum OAuthProvider {
        GOOGLE,
        APPLE,
        FACEBOOK,
        GITHUB,
        MICROSOFT
    }
}
