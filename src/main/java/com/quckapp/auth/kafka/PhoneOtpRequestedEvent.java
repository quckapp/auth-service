package com.quckapp.auth.kafka;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Kafka event published when an OTP is requested.
 * The notification-service consumes this event and sends SMS via Twilio/SNS.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PhoneOtpRequestedEvent {

    private String eventId;
    private String phoneNumber;
    private String otpCode;  // Plain OTP code (only in Kafka event, hashed in DB)
    private Instant expiresAt;
    private Instant requestedAt;
    private String ipAddress;
    private String userAgent;

    // Metadata for notification service
    private String locale;  // For localized SMS message
    private String appName;
}
