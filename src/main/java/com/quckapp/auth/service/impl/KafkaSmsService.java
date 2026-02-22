package com.quckapp.auth.service.impl;

import com.quckapp.auth.kafka.PhoneOtpRequestedEvent;
import com.quckapp.auth.service.SmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaOperations;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * SMS Service implementation that publishes events to Kafka.
 * The notification-service consumes these events and sends SMS via Twilio/AWS SNS.
 * Only active when sms.mock.enabled=false
 */
@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "sms.mock.enabled", havingValue = "false")
public class KafkaSmsService implements SmsService {

    private final KafkaOperations<String, Object> kafkaOperations;

    @Value("${sms.kafka.topic:notification.sms.otp}")
    private String otpTopic;

    @Value("${sms.kafka.generic-topic:notification.sms.generic}")
    private String genericSmsTopic;

    @Value("${spring.application.name:auth-service}")
    private String appName;

    @Override
    public void sendOtp(String phoneNumber, String code, int expiryMinutes) {
        PhoneOtpRequestedEvent event = PhoneOtpRequestedEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .phoneNumber(phoneNumber)
                .otpCode(code)
                .expiresAt(Instant.now().plusSeconds(expiryMinutes * 60L))
                .requestedAt(Instant.now())
                .appName(appName)
                .locale("en")
                .build();

        log.info("Publishing OTP event for phone: {}", maskPhoneNumber(phoneNumber));
        kafkaOperations.send(otpTopic, phoneNumber, event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish OTP event for phone: {}",
                                maskPhoneNumber(phoneNumber), ex);
                    } else {
                        log.debug("OTP event published successfully for phone: {}",
                                maskPhoneNumber(phoneNumber));
                    }
                });
    }

    @Override
    public void sendSms(String phoneNumber, String message) {
        var event = new GenericSmsEvent(
                UUID.randomUUID().toString(),
                phoneNumber,
                message,
                Instant.now(),
                appName
        );

        log.info("Publishing generic SMS event for phone: {}", maskPhoneNumber(phoneNumber));
        kafkaOperations.send(genericSmsTopic, phoneNumber, event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish SMS event for phone: {}",
                                maskPhoneNumber(phoneNumber), ex);
                    }
                });
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "****";
        }
        return phoneNumber.substring(0, phoneNumber.length() - 4).replaceAll(".", "*")
                + phoneNumber.substring(phoneNumber.length() - 4);
    }

    // Inner class for generic SMS events
    public record GenericSmsEvent(
            String eventId,
            String phoneNumber,
            String message,
            Instant requestedAt,
            String appName
    ) {}
}
