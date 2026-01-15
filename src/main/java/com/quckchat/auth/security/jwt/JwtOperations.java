package com.quckapp.auth.security.jwt;

import com.quckapp.auth.domain.entity.AuthUser;
import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.function.Function;

/**
 * Interface for JWT operations to support mocking in tests
 */
public interface JwtOperations {

    /**
     * Generate access token for user
     */
    String generateAccessToken(AuthUser user);

    /**
     * Generate refresh token for user
     */
    String generateRefreshToken(AuthUser user);

    /**
     * Generate password reset token
     */
    String generatePasswordResetToken(AuthUser user);

    /**
     * Generate email verification token
     */
    String generateEmailVerificationToken(AuthUser user);

    /**
     * Generate temporary token for 2FA verification
     */
    String generateTempToken(AuthUser user);

    /**
     * Extract user ID from token
     */
    String extractUserId(String token);

    /**
     * Extract email from token
     */
    String extractEmail(String token);

    /**
     * Extract token type
     */
    String extractTokenType(String token);

    /**
     * Extract external ID
     */
    String extractExternalId(String token);

    /**
     * Extract session ID from token
     */
    String extractSessionId(String token);

    /**
     * Extract issued at date
     */
    Date extractIssuedAt(String token);

    /**
     * Check if token is valid for user
     */
    boolean isTokenValid(String token, AuthUser user);

    /**
     * Check if token is expired
     */
    boolean isTokenExpired(String token);

    /**
     * Extract expiration date
     */
    Date extractExpiration(String token);

    /**
     * Extract a specific claim
     */
    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    /**
     * Extract all claims from token
     */
    Claims extractAllClaims(String token);

    /**
     * Validate token without user context
     */
    boolean validateToken(String token);

    /**
     * Get access token expiration in milliseconds
     */
    long getAccessTokenExpiration();

    /**
     * Get refresh token expiration in milliseconds
     */
    long getRefreshTokenExpiration();
}
