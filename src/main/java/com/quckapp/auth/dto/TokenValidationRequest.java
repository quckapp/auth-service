package com.quckapp.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationRequest {
    @NotBlank
    private String token;
}
