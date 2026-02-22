package com.quckapp.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EmailOtpResponse {

    private boolean success;
    private String message;
    private String maskedEmail;
    private Integer expiresInSeconds;
    private Integer resendCooldownSeconds;
    private Integer remainingAttempts;

    // For verification response
    private Boolean verified;
    private String userId;

    public static EmailOtpResponse otpSent(String maskedEmail, int expiresInSeconds, int resendCooldown) {
        return EmailOtpResponse.builder()
                .success(true)
                .message("OTP sent successfully")
                .maskedEmail(maskedEmail)
                .expiresInSeconds(expiresInSeconds)
                .resendCooldownSeconds(resendCooldown)
                .build();
    }

    public static EmailOtpResponse verified(String userId) {
        return EmailOtpResponse.builder()
                .success(true)
                .message("Email verified successfully")
                .verified(true)
                .userId(userId)
                .build();
    }

    public static EmailOtpResponse error(String message) {
        return EmailOtpResponse.builder()
                .success(false)
                .message(message)
                .build();
    }

    public static EmailOtpResponse error(String message, int remainingAttempts) {
        return EmailOtpResponse.builder()
                .success(false)
                .message(message)
                .remainingAttempts(remainingAttempts)
                .build();
    }
}
