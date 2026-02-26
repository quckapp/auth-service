package com.quckapp.auth.security.apikey;

import com.quckapp.auth.domain.entity.ApiKey;
import com.quckapp.auth.domain.repository.ApiKeyRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Filter to authenticate requests using API Key header.
 * Used for internal service-to-service communication.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private static final String API_KEY_HEADER = "X-API-Key";
    private static final List<String> API_KEY_PROTECTED_PATHS = List.of(
            "/v1/internal/",
            "/v1/migration/",
            "/v1/users/internal/",
            "/api/v1/auth/internal/",
            "/api/v1/auth/migration/",
            "/api/v1/auth/users/internal/"
    );

    private final ApiKeyRepository apiKeyRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Use servlet path (without context path) for matching
        String requestPath = request.getServletPath();
        if (requestPath == null || requestPath.isEmpty()) {
            requestPath = request.getRequestURI();
            // Remove context path if present
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isEmpty() && requestPath.startsWith(contextPath)) {
                requestPath = requestPath.substring(contextPath.length());
            }
        }

        log.debug("API Key filter checking path: {} (URI: {})", requestPath, request.getRequestURI());

        // Only process API key protected paths
        if (!isApiKeyProtectedPath(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        String apiKeyHeader = request.getHeader(API_KEY_HEADER);

        if (apiKeyHeader == null || apiKeyHeader.isBlank()) {
            log.debug("No API key provided for protected path: {}", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Hash the provided API key
            String keyHash = hashApiKey(apiKeyHeader);

            // Look up the API key in the database
            Optional<ApiKey> apiKeyOpt = apiKeyRepository.findByKeyHash(keyHash);

            if (apiKeyOpt.isEmpty()) {
                log.warn("Invalid API key provided for path: {}", requestPath);
                filterChain.doFilter(request, response);
                return;
            }

            ApiKey apiKey = apiKeyOpt.get();

            // Validate the API key
            if (!apiKey.isValid()) {
                log.warn("API key is not valid (inactive or expired): {}", apiKey.getName());
                filterChain.doFilter(request, response);
                return;
            }

            // Check IP whitelist
            String clientIp = getClientIp(request);
            if (!apiKey.isIpAllowed(clientIp)) {
                log.warn("API key IP not allowed. Key: {}, IP: {}", apiKey.getName(), clientIp);
                filterChain.doFilter(request, response);
                return;
            }

            // Record usage
            apiKey.recordUsage(clientIp);
            apiKeyRepository.save(apiKey);

            // Create authentication token with API key permissions as authorities
            List<SimpleGrantedAuthority> authorities = apiKey.getPermissions().stream()
                    .map(p -> new SimpleGrantedAuthority("ROLE_" + p.name()))
                    .toList();

            // Add a special authority to identify this as API key authentication
            authorities = new java.util.ArrayList<>(authorities);
            authorities.add(new SimpleGrantedAuthority("ROLE_API_KEY"));

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    new ApiKeyPrincipal(apiKey),
                    null,
                    authorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("API key authenticated successfully: {} for path: {}", apiKey.getName(), requestPath);

        } catch (Exception e) {
            log.error("Error processing API key authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private boolean isApiKeyProtectedPath(String path) {
        return API_KEY_PROTECTED_PATHS.stream().anyMatch(path::startsWith);
    }

    private String hashApiKey(String apiKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(apiKey.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    /**
     * Principal representing an authenticated API key
     */
    public record ApiKeyPrincipal(ApiKey apiKey) {
        public String getName() {
            return apiKey.getName();
        }

        public String getServiceName() {
            return apiKey.getServiceName();
        }
    }
}
