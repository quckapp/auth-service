package com.quckapp.auth.service.impl;

import com.quckapp.auth.service.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

/**
 * Mock Email Service for development/testing.
 * Logs OTP to console instead of sending email.
 * Enable with: email.mock.enabled=true
 */
@Service
@Primary
@ConditionalOnProperty(name = "email.mock.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class MockEmailService implements EmailService {

    @Override
    public void sendOtp(String email, String code, int expiryMinutes) {
        log.info("========================================");
        log.info("MOCK EMAIL - OTP for {}: {}", email, code);
        log.info("OTP expires in {} minutes", expiryMinutes);
        log.info("========================================");
    }

    @Override
    public void sendEmail(String email, String subject, String message) {
        log.info("========================================");
        log.info("MOCK EMAIL to {}", email);
        log.info("Subject: {}", subject);
        log.info("Message: {}", message);
        log.info("========================================");
    }
}
