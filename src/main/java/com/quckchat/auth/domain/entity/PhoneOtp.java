package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Phone OTP - Stores OTP codes for phone-based authentication
 */
@Entity
@Table(name = "phone_otps", indexes = {
    @Index(name = "idx_phone_otps_phone_number", columnList = "phoneNumber"),
    @Index(name = "idx_phone_otps_expires_at", columnList = "expiresAt"),
    @Index(name = "idx_phone_otps_verified", columnList = "verified")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PhoneOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 20)
    private String phoneNumber;

    @Column(nullable = false)
    private String otpHash;

    @Column(nullable = false)
    private Instant expiresAt;

    @Builder.Default
    private boolean verified = false;

    private Instant verifiedAt;

    @Builder.Default
    private int attemptCount = 0;

    private String ipAddress;

    private String userAgent;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !verified && !isExpired();
    }

    public void incrementAttempt() {
        this.attemptCount++;
    }

    public void markVerified() {
        this.verified = true;
        this.verifiedAt = Instant.now();
    }
}
