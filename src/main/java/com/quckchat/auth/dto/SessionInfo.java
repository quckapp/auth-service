package com.quckapp.auth.dto;

import lombok.*;
import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionInfo {
    private String sessionId;
    private String deviceName;
    private String deviceId;
    private String deviceType;
    private String ipAddress;
    private String location;
    private Instant createdAt;
    private Instant lastActiveAt;
    private boolean current;
}
