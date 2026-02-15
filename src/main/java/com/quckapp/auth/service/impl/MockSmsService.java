package com.quckapp.auth.service.impl;

import com.quckapp.auth.service.SmsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

/**
 * Mock SMS Service for development/testing.
 * Logs OTP to console instead of sending SMS.
 * Enable with: sms.mock.enabled=true
 */
@Service
@Primary
@ConditionalOnProperty(name = "sms.mock.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class MockSmsService implements SmsService {

    @Override
    public void sendOtp(String phoneNumber, String code, int expiryMinutes) {
        log.info("========================================");
        log.info("MOCK SMS - OTP for {}: {}", phoneNumber, code);
        log.info("OTP expires in {} minutes", expiryMinutes);
        log.info("========================================");
    }

    @Override
    public void sendSms(String phoneNumber, String message) {
        log.info("========================================");
        log.info("MOCK SMS to {}: {}", phoneNumber, message);
        log.info("========================================");
    }
}
