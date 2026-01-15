package com.quckapp.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthRequest {
    @NotBlank
    private String providerUserId;

    @NotBlank
    private String accessToken;

    private String refreshToken;

    private String idToken;

    private String email;

    private String name;

    private String avatarUrl;

    private Instant tokenExpiresAt;
}
