package com.quckapp.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokeTokenRequest {
    @NotBlank
    private String token;

    private String reason;
}
