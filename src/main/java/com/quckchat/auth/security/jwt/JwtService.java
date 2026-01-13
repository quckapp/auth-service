package com.quckchat.auth.security.jwt;

import com.quckchat.auth.domain.entity.AuthUser;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * JWT Service - Token generation and validation
 */
@Service
@Slf4j
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${jwt.issuer}")
    private String issuer;

    /**
     * Generate access token
     */
    public String generateAccessToken(AuthUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "access");
        claims.put("email", user.getEmail());
        claims.put("externalId", user.getExternalId());
        claims.put("2fa", user.isTwoFactorEnabled());

        return buildToken(claims, user.getId().toString(), accessTokenExpiration);
    }

    /**
     * Generate refresh token
     */
    public String generateRefreshToken(AuthUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        claims.put("tokenId", UUID.randomUUID().toString());

        return buildToken(claims, user.getId().toString(), refreshTokenExpiration);
    }

    /**
     * Generate password reset token
     */
    public String generatePasswordResetToken(AuthUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "password_reset");
        claims.put("email", user.getEmail());

        return buildToken(claims, user.getId().toString(), 3600000); // 1 hour
    }

    /**
     * Generate email verification token
     */
    public String generateEmailVerificationToken(AuthUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "email_verification");
        claims.put("email", user.getEmail());

        return buildToken(claims, user.getId().toString(), 86400000); // 24 hours
    }

    /**
     * Build JWT token
     */
    private String buildToken(Map<String, Object> claims, String subject, long expiration) {
        Instant now = Instant.now();
        Instant expiryDate = now.plusMillis(expiration);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiryDate))
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extract user ID from token
     */
    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract email from token
     */
    public String extractEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }

    /**
     * Extract token type
     */
    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("type", String.class));
    }

    /**
     * Extract external ID
     */
    public String extractExternalId(String token) {
        return extractClaim(token, claims -> claims.get("externalId", String.class));
    }

    /**
     * Check if token is valid
     */
    public boolean isTokenValid(String token, AuthUser user) {
        try {
            final String userId = extractUserId(token);
            return userId.equals(user.getId().toString()) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extract expiration date
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract a specific claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from token
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Validate token without user context
     */
    public boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token is expired: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("JWT token is unsupported: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.warn("JWT token is malformed: {}", e.getMessage());
            return false;
        } catch (SecurityException e) {
            log.warn("JWT signature validation failed: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Get signing key
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Get access token expiration in milliseconds
     */
    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    /**
     * Get refresh token expiration in milliseconds
     */
    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }
}
