package com.quckapp.auth.dto;

import lombok.*;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionsResponse {
    private List<SessionInfo> sessions;
    private String currentSessionId;
}
