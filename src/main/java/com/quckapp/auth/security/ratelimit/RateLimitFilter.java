package com.quckapp.auth.security.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Servlet Filter for global IP-based rate limiting
 * Applied to all requests before reaching controllers
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
@RequiredArgsConstructor
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitOperations rateLimitService;
    private final RateLimitConfig config;
    private final ObjectMapper objectMapper;

    /**
     * Paths to exclude from rate limiting
     */
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/actuator/health",
            "/actuator/info",
            "/health",
            "/v3/api-docs",
            "/swagger-ui"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Skip if rate limiting is disabled
        if (!config.isEnabled() || !config.getIp().isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Skip excluded paths
        String path = request.getRequestURI();
        if (isExcludedPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Get client IP
        String clientIp = getClientIp(request);

        // Check rate limit
        RateLimitResult result = rateLimitService.checkIpRateLimit(clientIp);

        // Add rate limit headers
        addRateLimitHeaders(response, result, config.getIp().getRequestsPerMinute());

        if (result.isDenied()) {
            log.warn("IP rate limit exceeded for: {} on path: {}", clientIp, path);
            sendRateLimitResponse(response, result);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Check if path should be excluded from rate limiting
     */
    private boolean isExcludedPath(String path) {
        return EXCLUDED_PATHS.stream().anyMatch(path::startsWith);
    }

    /**
     * Get client IP address
     */
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
     * Add rate limit headers to response
     */
    private void addRateLimitHeaders(HttpServletResponse response, RateLimitResult result, int limit) {
        response.setHeader("X-RateLimit-Limit", String.valueOf(limit));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(result.getRemaining()));

        if (result.isDenied()) {
            response.setHeader("X-RateLimit-Reset", String.valueOf(result.getRetryAfterSeconds()));
            response.setHeader("Retry-After", String.valueOf(result.getRetryAfterSeconds()));
        }
    }

    /**
     * Send rate limit exceeded response
     */
    private void sendRateLimitResponse(HttpServletResponse response, RateLimitResult result) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new HashMap<>();
        body.put("error", "rate_limit_exceeded");
        body.put("message", "Too many requests. Please try again later.");
        body.put("retryAfter", result.getRetryAfterSeconds());

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
