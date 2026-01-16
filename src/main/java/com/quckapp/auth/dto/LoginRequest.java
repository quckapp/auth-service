package com.quckapp.auth.dto;

import jakarta.validation.constraints.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    @NotBlank @Email
    private String email;

    @NotBlank
    private String password;

    private String deviceId;
    private String deviceName;
}
