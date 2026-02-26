package com.quckapp.auth.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * JWT Authentication Filter
 *
 * Extracts JWT from Authorization header, validates it, and sets the
 * SecurityContext with the authenticated user principal.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Public paths that should skip JWT authentication.
     * These paths are handled by Spring Security's permitAll() configuration.
     */
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/v1/login",
            "/v1/login/2fa",
            "/v1/register",
            "/v1/token/refresh",
            "/v1/token/validate",
            "/v1/password/forgot",
            "/v1/password/reset",
            "/v1/auth/phone/**",
            "/v1/oauth/**",
            "/oauth2/**",
            "/login/oauth2/**",
            "/actuator/**",
            "/health",
            "/v1/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    );

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final JwtService jwtService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        boolean shouldSkip = PUBLIC_PATHS.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
        if (shouldSkip) {
            log.debug("Skipping JWT filter for public path: {}", path);
        }
        return shouldSkip;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtService.validateToken(jwt)) {
                String tokenType = jwtService.extractTokenType(jwt);

                // Only allow access tokens for API authentication
                if (!"access".equals(tokenType)) {
                    log.debug("Token type '{}' is not valid for API authentication", tokenType);
                    filterChain.doFilter(request, response);
                    return;
                }

                String userId = jwtService.extractUserId(jwt);
                String email = jwtService.extractEmail(jwt);
                String externalId = jwtService.extractExternalId(jwt);
                String sessionId = jwtService.extractSessionId(jwt);

                // Create authentication principal with user details
                JwtUserPrincipal principal = JwtUserPrincipal.builder()
                        .userId(UUID.fromString(userId))
                        .email(email)
                        .externalId(externalId)
                        .sessionId(sessionId)
                        .build();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                principal,
                                null,
                                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
                        );

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("Authenticated user '{}' from JWT", email);
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from the Authorization header
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
