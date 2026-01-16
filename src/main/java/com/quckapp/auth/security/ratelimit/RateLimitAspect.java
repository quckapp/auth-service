package com.quckapp.auth.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;

/**
 * AOP Aspect for enforcing @RateLimit annotation
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitAspect {

    private final RateLimitOperations rateLimitService;
    private final RateLimitConfig config;

    @Around("@annotation(com.quckapp.auth.security.ratelimit.RateLimit)")
    public Object enforceRateLimit(ProceedingJoinPoint joinPoint) throws Throwable {
        if (!config.isEnabled()) {
            return joinPoint.proceed();
        }

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        RateLimit rateLimit = method.getAnnotation(RateLimit.class);

        if (rateLimit == null) {
            return joinPoint.proceed();
        }

        // Skip for authenticated users if configured
        if (rateLimit.skipAuthenticated() && isAuthenticated()) {
            return joinPoint.proceed();
        }

        // Build rate limit key
        String key = buildKey(rateLimit, method);

        // Check rate limit
        RateLimitResult result = rateLimitService.checkRateLimit(
                key,
                rateLimit.requests(),
                rateLimit.window()
        );

        if (result.isDenied()) {
            log.warn("Rate limit exceeded for key: {} on method: {}", key, method.getName());
            throw new RateLimitExceededException(
                    rateLimit.message(),
                    result.getRetryAfterSeconds()
            );
        }

        return joinPoint.proceed();
    }

    /**
     * Build the rate limit key based on annotation configuration
     */
    private String buildKey(RateLimit rateLimit, Method method) {
        StringBuilder keyBuilder = new StringBuilder();

        // Add custom prefix if provided
        if (!rateLimit.keyPrefix().isEmpty()) {
            keyBuilder.append(rateLimit.keyPrefix()).append(":");
        }

        // Add key type specific part
        switch (rateLimit.key()) {
            case IP -> keyBuilder.append("ip:").append(getClientIp());

            case USER -> {
                String userId = getCurrentUserId();
                if (userId != null) {
                    keyBuilder.append("user:").append(userId);
                } else {
                    keyBuilder.append("ip:").append(getClientIp());
                }
            }

            case API_KEY -> {
                String apiKey = getApiKey();
                if (apiKey != null) {
                    keyBuilder.append("apikey:").append(apiKey);
                } else {
                    keyBuilder.append("ip:").append(getClientIp());
                }
            }

            case IP_ENDPOINT -> keyBuilder.append("ip:")
                    .append(getClientIp())
                    .append(":")
                    .append(method.getDeclaringClass().getSimpleName())
                    .append(".")
                    .append(method.getName());

            case USER_ENDPOINT -> {
                String userId = getCurrentUserId();
                if (userId != null) {
                    keyBuilder.append("user:").append(userId);
                } else {
                    keyBuilder.append("ip:").append(getClientIp());
                }
                keyBuilder.append(":")
                        .append(method.getDeclaringClass().getSimpleName())
                        .append(".")
                        .append(method.getName());
            }

            case GLOBAL -> keyBuilder.append("global:")
                    .append(method.getDeclaringClass().getSimpleName())
                    .append(".")
                    .append(method.getName());
        }

        return keyBuilder.toString();
    }

    /**
     * Check if current request is authenticated
     */
    private boolean isAuthenticated() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    /**
     * Get current authenticated user ID
     */
    private String getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            return auth.getName();
        }
        return null;
    }

    /**
     * Get API key from request header
     */
    private String getApiKey() {
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            String apiKey = request.getHeader("X-API-Key");
            if (apiKey != null && !apiKey.isEmpty()) {
                // Return hash of API key for privacy
                return String.valueOf(apiKey.hashCode());
            }
        }
        return null;
    }

    /**
     * Get client IP address
     */
    private String getClientIp() {
        HttpServletRequest request = getCurrentRequest();
        if (request == null) {
            return "unknown";
        }

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
     * Get current HTTP request
     */
    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
    }
}
