package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Login History Entity - Records all login attempts with detailed information
 */
@Entity
@Table(name = "login_history", indexes = {
    @Index(name = "idx_login_history_user_id", columnList = "user_id"),
    @Index(name = "idx_login_history_email", columnList = "email"),
    @Index(name = "idx_login_history_status", columnList = "loginStatus"),
    @Index(name = "idx_login_history_ip", columnList = "ipAddress"),
    @Index(name = "idx_login_history_created_at", columnList = "createdAt"),
    @Index(name = "idx_login_history_device_id", columnList = "deviceId"),
    @Index(name = "idx_login_history_country", columnList = "countryCode"),
    @Index(name = "idx_login_history_method", columnList = "loginMethod")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private AuthUser user;

    @Column(length = 255)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private LoginStatus loginStatus;

    @Enumerated(EnumType.STRING)
    @Column(length = 50)
    @Builder.Default
    private LoginMethod loginMethod = LoginMethod.PASSWORD;

    @Column(length = 45)
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String userAgent;

    @Column(length = 255)
    private String deviceId;

    @Column(length = 255)
    private String deviceName;

    @Column(length = 50)
    private String deviceType;

    @Column(length = 100)
    private String osName;

    @Column(length = 50)
    private String osVersion;

    @Column(length = 100)
    private String browserName;

    @Column(length = 50)
    private String browserVersion;

    // Geolocation
    @Column(length = 100)
    private String country;

    @Column(length = 10)
    private String countryCode;

    @Column(length = 100)
    private String region;

    @Column(length = 100)
    private String city;

    @Column(length = 20)
    private String postalCode;

    @Column(precision = 10, scale = 8)
    private BigDecimal latitude;

    @Column(precision = 11, scale = 8)
    private BigDecimal longitude;

    @Column(length = 255)
    private String isp;

    // Security flags
    @Builder.Default
    private boolean isVpn = false;

    @Builder.Default
    private boolean isTor = false;

    @Builder.Default
    private boolean isProxy = false;

    @Builder.Default
    private int riskScore = 0;

    @Column(length = 255)
    private String failureReason;

    // 2FA info
    @Builder.Default
    private boolean twoFactorUsed = false;

    @Column(length = 50)
    private String twoFactorMethod;

    // Link to session if login was successful
    private UUID sessionId;

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    // Helper methods
    public boolean isSuccessful() {
        return loginStatus == LoginStatus.SUCCESS;
    }

    public boolean isSuspicious() {
        return riskScore > 50 || isVpn || isTor || isProxy;
    }
}
