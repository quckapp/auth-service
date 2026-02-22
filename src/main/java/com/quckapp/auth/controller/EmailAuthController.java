package com.quckapp.auth.controller;

import com.quckapp.auth.dto.EmailOtpRequest;
import com.quckapp.auth.dto.EmailOtpResponse;
import com.quckapp.auth.dto.EmailVerifyRequest;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.EmailOtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/v1/auth/email")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Email Authentication", description = "Email-based OTP verification endpoints")
public class EmailAuthController {

    private final EmailOtpService emailOtpService;
    private final JwtOperations jwtOperations;

    @PostMapping("/request-otp")
    @Operation(summary = "Request Email OTP", description = "Request a one-time password sent via Email")
    public ResponseEntity<EmailOtpResponse> requestOtp(
            @Valid @RequestBody EmailOtpRequest request,
            HttpServletRequest httpRequest
    ) {
        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Email OTP request received from IP: {}", ipAddress);

        EmailOtpResponse response = emailOtpService.requestOtp(
                request.getEmail(),
                ipAddress,
                userAgent
        );

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/verify-otp")
    @Operation(summary = "Verify Email OTP", description = "Verify the OTP code sent to email")
    public ResponseEntity<EmailOtpResponse> verifyOtp(
            @Valid @RequestBody EmailVerifyRequest request,
            HttpServletRequest httpRequest
    ) {
        String ipAddress = getClientIp(httpRequest);

        log.info("Email OTP verification request from IP: {}", ipAddress);

        EmailOtpResponse response = emailOtpService.verifyOtp(
                request.getEmail(),
                request.getCode(),
                ipAddress
        );

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/request-otp/authenticated")
    @Operation(summary = "Request Email OTP for authenticated user",
               description = "Request OTP for email verification after login",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<EmailOtpResponse> requestOtpAuthenticated(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody EmailOtpRequest request,
            HttpServletRequest httpRequest
    ) {
        UUID userId = getUserId(authHeader);
        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Email OTP request for authenticated user: {}", userId);

        EmailOtpResponse response = emailOtpService.requestOtpForUser(
                userId,
                request.getEmail(),
                ipAddress,
                userAgent
        );

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/verify-otp/authenticated")
    @Operation(summary = "Verify Email OTP for authenticated user",
               description = "Verify OTP and link email to user account",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<EmailOtpResponse> verifyOtpAuthenticated(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody EmailVerifyRequest request,
            HttpServletRequest httpRequest
    ) {
        UUID userId = getUserId(authHeader);
        String ipAddress = getClientIp(httpRequest);

        log.info("Email OTP verification for authenticated user: {}", userId);

        EmailOtpResponse response = emailOtpService.verifyOtpForUser(
                userId,
                request.getEmail(),
                request.getCode(),
                ipAddress
        );

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/resend-otp")
    @Operation(summary = "Resend Email OTP", description = "Resend OTP to the same email")
    public ResponseEntity<EmailOtpResponse> resendOtp(
            @Valid @RequestBody EmailOtpRequest request,
            HttpServletRequest httpRequest
    ) {
        // Resend is the same as request, rate limiting handles cooldown
        return requestOtp(request, httpRequest);
    }

    @PostMapping("/resend-otp/authenticated")
    @Operation(summary = "Resend Email OTP for authenticated user",
               security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<EmailOtpResponse> resendOtpAuthenticated(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody EmailOtpRequest request,
            HttpServletRequest httpRequest
    ) {
        return requestOtpAuthenticated(authHeader, request, httpRequest);
    }

    /**
     * Extract user ID from JWT token
     */
    private UUID getUserId(String authHeader) {
        String token = extractToken(authHeader);
        String userId = jwtOperations.extractUserId(token);
        return UUID.fromString(userId);
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }

    /**
     * Extract client IP address, considering proxy headers.
     */
    private String getClientIp(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP"
        };

        for (String header : headerNames) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // X-Forwarded-For may contain multiple IPs, take the first
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }
}
