package com.quckapp.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorEnableRequest {
    @NotBlank @Size(min = 6, max = 6)
    private String code;
}
