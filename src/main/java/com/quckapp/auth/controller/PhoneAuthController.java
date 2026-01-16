package com.quckapp.auth.controller;

import com.quckapp.auth.dto.OtpResponse;
import com.quckapp.auth.dto.PhoneLoginRequest;
import com.quckapp.auth.dto.PhoneOtpRequest;
import com.quckapp.auth.dto.PhoneVerifyRequest;
import com.quckapp.auth.service.PhoneOtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth/phone")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Phone Authentication", description = "Phone-based OTP authentication endpoints")
public class PhoneAuthController {

    private final PhoneOtpService phoneOtpService;

    @PostMapping("/request-otp")
    @Operation(summary = "Request OTP", description = "Request a one-time password sent via SMS")
    public ResponseEntity<OtpResponse> requestOtp(
            @Valid @RequestBody PhoneOtpRequest request,
            HttpServletRequest httpRequest
    ) {
        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("OTP request received from IP: {}", ipAddress);

        OtpResponse response = phoneOtpService.requestOtp(
                request.getPhoneNumber(),
                ipAddress,
                userAgent
        );

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/verify-otp")
    @Operation(summary = "Verify OTP", description = "Verify the OTP code without logging in")
    public ResponseEntity<OtpResponse> verifyOtp(
            @Valid @RequestBody PhoneVerifyRequest request,
            HttpServletRequest httpRequest
    ) {
        String ipAddress = getClientIp(httpRequest);

        log.info("OTP verification request from IP: {}", ipAddress);

        OtpResponse response = phoneOtpService.verifyOtp(
                request.getPhoneNumber(),
                request.getCode(),
                ipAddress
        );

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/login")
    @Operation(summary = "Login with OTP",
               description = "Verify OTP and login. Creates account if phone number is new.")
    public ResponseEntity<OtpResponse> loginWithOtp(
            @Valid @RequestBody PhoneLoginRequest request,
            HttpServletRequest httpRequest
    ) {
        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Phone login request from IP: {}", ipAddress);

        OtpResponse response = phoneOtpService.loginWithOtp(request, ipAddress, userAgent);

        return response.isSuccess()
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/resend-otp")
    @Operation(summary = "Resend OTP", description = "Resend OTP to the same phone number")
    public ResponseEntity<OtpResponse> resendOtp(
            @Valid @RequestBody PhoneOtpRequest request,
            HttpServletRequest httpRequest
    ) {
        // Resend is the same as request, rate limiting handles cooldown
        return requestOtp(request, httpRequest);
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
