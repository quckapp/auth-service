package com.quckchat.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

import java.time.Instant;
import java.util.List;
import java.util.Set;

// ============================================
// Request DTOs
// ============================================

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class RegisterRequest {
    @NotBlank @Email
    private String email;

    @NotBlank @Size(min = 8, max = 100)
    private String password;

    private String externalId; // From NestJS user service
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class LoginRequest {
    @NotBlank @Email
    private String email;

    @NotBlank
    private String password;

    private String deviceId;
    private String deviceName;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TwoFactorLoginRequest {
    @NotBlank
    private String tempToken;

    @NotBlank @Size(min = 6, max = 6)
    private String code;

    private String deviceId;
    private String deviceName;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class RefreshTokenRequest {
    @NotBlank
    private String refreshToken;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TokenValidationRequest {
    @NotBlank
    private String token;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class RevokeTokenRequest {
    @NotBlank
    private String token;

    private String reason;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class ForgotPasswordRequest {
    @NotBlank @Email
    private String email;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class ResetPasswordRequest {
    @NotBlank
    private String token;

    @NotBlank @Size(min = 8, max = 100)
    private String newPassword;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class ChangePasswordRequest {
    @NotBlank
    private String currentPassword;

    @NotBlank @Size(min = 8, max = 100)
    private String newPassword;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TwoFactorEnableRequest {
    @NotBlank @Size(min = 6, max = 6)
    private String code;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TwoFactorDisableRequest {
    @NotBlank @Size(min = 6, max = 6)
    private String code;

    @NotBlank
    private String password;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TwoFactorVerifyRequest {
    @NotBlank @Size(min = 6, max = 6)
    private String code;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class OAuthRequest {
    @NotBlank
    private String accessToken;

    private String idToken;
}

// ============================================
// Response DTOs
// ============================================

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private String tokenType;
    private UserInfo user;
    private boolean requiresTwoFactor;
    private String tempToken; // If 2FA required
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private String tokenType;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TokenValidationResponse {
    private boolean valid;
    private String userId;
    private String externalId;
    private String email;
    private Instant expiresAt;
    private String tokenType;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class MessageResponse {
    private String message;

    public MessageResponse(String message) {
        this.message = message;
    }
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TwoFactorSetupResponse {
    private String secret;
    private String qrCodeUrl;
    private String otpAuthUrl;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class TwoFactorEnableResponse {
    private boolean enabled;
    private Set<String> backupCodes;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class BackupCodesResponse {
    private Set<String> backupCodes;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class SessionsResponse {
    private List<SessionInfo> sessions;
    private String currentSessionId;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class SessionInfo {
    private String sessionId;
    private String deviceName;
    private String deviceId;
    private String ipAddress;
    private String location;
    private Instant createdAt;
    private Instant lastActiveAt;
    private boolean current;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class UserInfo {
    private String id;
    private String externalId;
    private String email;
    private boolean twoFactorEnabled;
    private List<String> oauthProviders;
}

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
class ClientInfo {
    private String ipAddress;
    private String userAgent;
    private String deviceId;
}
