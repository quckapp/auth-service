package com.quckapp.auth.dto;

import lombok.*;
import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {
    private boolean valid;
    private String userId;
    private String externalId;
    private String email;
    private Instant expiresAt;
    private String tokenType;
}
