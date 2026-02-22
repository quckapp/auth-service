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
public class OtpResponse {

    private boolean success;
    private String message;
    private String maskedPhone;
    private Integer expiresInSeconds;
    private Integer resendCooldownSeconds;
    private Integer remainingAttempts;

    // For development/testing - OTP code (only included when sms.mock.enabled=true)
    private String testOtp;

    // For verification response
    private Boolean verified;
    private String userId;

    // For login response
    private String accessToken;
    private String refreshToken;
    private UserDto user;

    public static OtpResponse otpSent(String maskedPhone, int expiresInSeconds, int resendCooldown) {
        return otpSent(maskedPhone, expiresInSeconds, resendCooldown, null);
    }

    public static OtpResponse otpSent(String maskedPhone, int expiresInSeconds, int resendCooldown, String testOtp) {
        return OtpResponse.builder()
                .success(true)
                .message("OTP sent successfully")
                .maskedPhone(maskedPhone)
                .expiresInSeconds(expiresInSeconds)
                .resendCooldownSeconds(resendCooldown)
                .testOtp(testOtp)
                .build();
    }

    public static OtpResponse verified(String userId) {
        return OtpResponse.builder()
                .success(true)
                .message("Phone verified successfully")
                .verified(true)
                .userId(userId)
                .build();
    }

    public static OtpResponse loginSuccess(String accessToken, String refreshToken, UserDto user) {
        return OtpResponse.builder()
                .success(true)
                .message("Login successful")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(user)
                .build();
    }

    public static OtpResponse error(String message) {
        return OtpResponse.builder()
                .success(false)
                .message(message)
                .build();
    }

    public static OtpResponse error(String message, int remainingAttempts) {
        return OtpResponse.builder()
                .success(false)
                .message(message)
                .remainingAttempts(remainingAttempts)
                .build();
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class UserDto {
        private String id;
        private String phoneNumber;
        private String username;
        private String displayName;
        private String email;
        private String avatar;
        private boolean phoneVerified;
        private boolean newUser;
    }
}
