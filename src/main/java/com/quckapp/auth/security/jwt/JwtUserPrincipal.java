package com.quckapp.auth.security.jwt;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.util.UUID;

/**
 * JWT User Principal
 *
 * Holds the authenticated user details extracted from the JWT token.
 * Used as the principal in the SecurityContext.
 */
@Data
@Builder
public class JwtUserPrincipal implements Serializable {

    private static final long serialVersionUID = 1L;

    private UUID userId;
    private String email;
    private String externalId;
    private String sessionId;
}
