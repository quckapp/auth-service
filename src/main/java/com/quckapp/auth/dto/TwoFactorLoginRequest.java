package com.quckapp.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorLoginRequest {
    @NotBlank
    private String tempToken;

    @NotBlank @Size(min = 6, max = 6)
    private String code;

    private String deviceId;
    private String deviceName;
}
