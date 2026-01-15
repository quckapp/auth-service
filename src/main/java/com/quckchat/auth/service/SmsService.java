package com.quckapp.auth.service;

/**
 * Interface for SMS delivery service.
 * Implementations can use Kafka events, Twilio, AWS SNS, etc.
 */
public interface SmsService {

    /**
     * Send an OTP code to the specified phone number.
     *
     * @param phoneNumber the phone number in E.164 format
     * @param code        the OTP code to send
     * @param expiryMinutes how many minutes until the OTP expires
     */
    void sendOtp(String phoneNumber, String code, int expiryMinutes);

    /**
     * Send a generic SMS message.
     *
     * @param phoneNumber the phone number in E.164 format
     * @param message     the message to send
     */
    void sendSms(String phoneNumber, String message);
}
