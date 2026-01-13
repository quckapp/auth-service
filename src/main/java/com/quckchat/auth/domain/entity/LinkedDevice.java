package com.quckchat.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Linked Device Entity - User's connected devices with FCM tokens
 */
@Entity
@Table(name = "linked_devices", indexes = {
    @Index(name = "idx_linked_devices_user_id", columnList = "user_id"),
    @Index(name = "idx_linked_devices_device_id", columnList = "deviceId"),
    @Index(name = "idx_linked_devices_fcm", columnList = "fcmToken")
}, uniqueConstraints = {
    @UniqueConstraint(name = "uk_linked_devices_user_device", columnNames = {"user_id", "deviceId"})
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LinkedDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserProfile userProfile;

    @Column(nullable = false, length = 255)
    private String deviceId;

    @Column(length = 255)
    private String deviceName;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private DeviceType deviceType = DeviceType.MOBILE;

    @Column(columnDefinition = "TEXT")
    private String fcmToken;

    private Instant lastActive;

    @CreatedDate
    @Column(updatable = false)
    private Instant linkedAt;

    // Helper methods
    public void updateActivity() {
        this.lastActive = Instant.now();
    }

    public boolean hasFcmToken() {
        return fcmToken != null && !fcmToken.isBlank();
    }

    public static LinkedDevice create(UserProfile userProfile, String deviceId, String deviceName, DeviceType deviceType, String fcmToken) {
        return LinkedDevice.builder()
                .userProfile(userProfile)
                .deviceId(deviceId)
                .deviceName(deviceName)
                .deviceType(deviceType)
                .fcmToken(fcmToken)
                .lastActive(Instant.now())
                .build();
    }
}
