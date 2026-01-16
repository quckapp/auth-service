package com.quckapp.auth.dto;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientInfo {
    private String ipAddress;
    private String userAgent;
    private String deviceId;
    private String deviceName;
    private String deviceType;
    private String country;
    private String city;
}
