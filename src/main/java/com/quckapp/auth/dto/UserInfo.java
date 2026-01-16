package com.quckapp.auth.dto;

import lombok.*;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo {
    private String id;
    private String externalId;
    private String email;
    private boolean twoFactorEnabled;
    private List<String> oauthProviders;
}
