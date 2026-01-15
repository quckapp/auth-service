package com.quckapp.auth.security.ratelimit;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Rate Limiting Configuration Properties
 */
@Configuration
@ConfigurationProperties(prefix = "security.rate-limit")
@Getter
@Setter
public class RateLimitConfig {

    private boolean enabled = true;

    /**
     * Login rate limiting
     */
    private LoginRateLimit login = new LoginRateLimit();

    /**
     * API rate limiting
     */
    private ApiRateLimit api = new ApiRateLimit();

    /**
     * IP-based rate limiting
     */
    private IpRateLimit ip = new IpRateLimit();

    /**
     * Endpoint-specific rate limits (path -> limit config)
     */
    private Map<String, EndpointLimit> endpoints = new HashMap<>();

    @Getter
    @Setter
    public static class LoginRateLimit {
        private int maxAttempts = 5;
        private int windowSeconds = 300; // 5 minutes
        private int blockDurationSeconds = 900; // 15 minutes
    }

    @Getter
    @Setter
    public static class ApiRateLimit {
        private int requestsPerMinute = 100;
        private int requestsPerHour = 1000;
        private int requestsPerDay = 10000;
    }

    @Getter
    @Setter
    public static class IpRateLimit {
        private boolean enabled = true;
        private int requestsPerMinute = 60;
        private int requestsPerHour = 600;
        private int burstSize = 20; // Allow burst of requests
    }

    @Getter
    @Setter
    public static class EndpointLimit {
        private int maxRequests;
        private int windowSeconds;
        private String key; // Optional custom key (e.g., "user", "ip", "api-key")
    }
}
