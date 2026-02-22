package com.quckapp.auth.service;

/**
 * Interface for Email delivery service.
 * Implementations can use Kafka events, SMTP, AWS SES, etc.
 */
public interface EmailService {

    /**
     * Send an OTP code to the specified email address.
     *
     * @param email         the email address
     * @param code          the OTP code to send
     * @param expiryMinutes how many minutes until the OTP expires
     */
    void sendOtp(String email, String code, int expiryMinutes);

    /**
     * Send a generic email message.
     *
     * @param email   the email address
     * @param subject the email subject
     * @param message the message body
     */
    void sendEmail(String email, String subject, String message);
}
