package com.quckapp.auth.dto;

import lombok.*;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BackupCodesResponse {
    private Set<String> backupCodes;
}
