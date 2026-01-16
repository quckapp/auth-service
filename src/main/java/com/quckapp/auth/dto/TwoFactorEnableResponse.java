package com.quckapp.auth.dto;

import lombok.*;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorEnableResponse {
    private boolean enabled;
    private Set<String> backupCodes;
}
