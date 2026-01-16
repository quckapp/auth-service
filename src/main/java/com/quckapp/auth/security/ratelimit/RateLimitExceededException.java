package com.quckapp.auth.security.ratelimit;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when rate limit is exceeded
 */
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
@Getter
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;
    private final String limitType;
    private final boolean blocked;

    public RateLimitExceededException(String message, long retryAfterSeconds) {
        this(message, retryAfterSeconds, "api", false);
    }

    public RateLimitExceededException(String message, long retryAfterSeconds, String limitType, boolean blocked) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
        this.limitType = limitType;
        this.blocked = blocked;
    }

    public static RateLimitExceededException apiLimit(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "API rate limit exceeded. Please try again later.",
                retryAfterSeconds,
                "api",
                false
        );
    }

    public static RateLimitExceededException loginLimit(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Too many login attempts. Please try again later.",
                retryAfterSeconds,
                "login",
                false
        );
    }

    public static RateLimitExceededException loginBlocked(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Account temporarily locked due to too many failed login attempts.",
                retryAfterSeconds,
                "login",
                true
        );
    }

    public static RateLimitExceededException ipLimit(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Too many requests from this IP address.",
                retryAfterSeconds,
                "ip",
                false
        );
    }
}
