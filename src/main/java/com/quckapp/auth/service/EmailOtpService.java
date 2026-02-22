package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.EmailOtp;
import com.quckapp.auth.domain.entity.UserProfile;
import com.quckapp.auth.domain.repository.EmailOtpRepository;
import com.quckapp.auth.domain.repository.UserProfileRepository;
import com.quckapp.auth.dto.EmailOtpResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailOtpService {

    private final EmailOtpRepository emailOtpRepository;
    private final UserProfileRepository userProfileRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${otp.email.length:6}")
    private int otpLength;

    @Value("${otp.email.expiry-minutes:10}")
    private int expiryMinutes;

    @Value("${otp.email.max-attempts:5}")
    private int maxAttempts;

    @Value("${otp.email.resend-cooldown-seconds:60}")
    private int resendCooldownSeconds;

    @Value("${otp.email.max-requests-per-day:10}")
    private int maxRequestsPerDay;

    @Value("${otp.email.max-requests-per-ip-per-hour:20}")
    private int maxRequestsPerIpPerHour;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    /**
     * Request a new OTP for the given email address.
     */
    @Transactional
    public EmailOtpResponse requestOtp(String email, String ipAddress, String userAgent) {
        // Normalize email
        email = normalizeEmail(email);

        // Check rate limits
        String rateLimitError = checkRateLimits(email, ipAddress);
        if (rateLimitError != null) {
            return EmailOtpResponse.error(rateLimitError);
        }

        // Check resend cooldown
        Optional<EmailOtp> existingOtp = emailOtpRepository.findLatestValidOtp(email, Instant.now());
        if (existingOtp.isPresent()) {
            long secondsSinceCreated = ChronoUnit.SECONDS.between(
                    existingOtp.get().getCreatedAt(), Instant.now());
            if (secondsSinceCreated < resendCooldownSeconds) {
                int remainingCooldown = (int) (resendCooldownSeconds - secondsSinceCreated);
                return EmailOtpResponse.builder()
                        .success(false)
                        .message("Please wait before requesting another OTP")
                        .resendCooldownSeconds(remainingCooldown)
                        .build();
            }
        }

        // Invalidate any existing pending OTPs
        emailOtpRepository.invalidatePendingOtps(email);

        // Generate new OTP
        String otpCode = generateOtpCode();
        log.debug("DEBUG [REMOVE IN PROD]: Generated Email OTP for {}: {}", maskEmail(email), otpCode);
        String otpHash = passwordEncoder.encode(otpCode);

        // Find user if exists
        UUID userId = null;
        Optional<UserProfile> userOpt = userProfileRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            userId = userOpt.get().getId();
        }

        // Create and save OTP entity
        EmailOtp emailOtp = EmailOtp.builder()
                .email(email)
                .otpHash(otpHash)
                .expiresAt(Instant.now().plusSeconds(expiryMinutes * 60L))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .userId(userId)
                .build();

        emailOtpRepository.save(emailOtp);

        // Send OTP via Email
        emailService.sendOtp(email, otpCode, expiryMinutes);

        log.info("Email OTP requested for: {}", maskEmail(email));

        return EmailOtpResponse.otpSent(
                maskEmail(email),
                expiryMinutes * 60,
                resendCooldownSeconds
        );
    }

    /**
     * Request OTP for a specific user (for email verification after login)
     */
    @Transactional
    public EmailOtpResponse requestOtpForUser(UUID userId, String email, String ipAddress, String userAgent) {
        // Normalize email
        email = normalizeEmail(email);

        // Check rate limits
        String rateLimitError = checkRateLimits(email, ipAddress);
        if (rateLimitError != null) {
            return EmailOtpResponse.error(rateLimitError);
        }

        // Check resend cooldown
        Optional<EmailOtp> existingOtp = emailOtpRepository.findLatestValidOtp(email, Instant.now());
        if (existingOtp.isPresent()) {
            long secondsSinceCreated = ChronoUnit.SECONDS.between(
                    existingOtp.get().getCreatedAt(), Instant.now());
            if (secondsSinceCreated < resendCooldownSeconds) {
                int remainingCooldown = (int) (resendCooldownSeconds - secondsSinceCreated);
                return EmailOtpResponse.builder()
                        .success(false)
                        .message("Please wait before requesting another OTP")
                        .resendCooldownSeconds(remainingCooldown)
                        .build();
            }
        }

        // Invalidate any existing pending OTPs
        emailOtpRepository.invalidatePendingOtps(email);

        // Generate new OTP
        String otpCode = generateOtpCode();
        log.debug("DEBUG [REMOVE IN PROD]: Generated Email OTP for user {}: {}", userId, otpCode);
        String otpHash = passwordEncoder.encode(otpCode);

        // Create and save OTP entity
        EmailOtp emailOtp = EmailOtp.builder()
                .email(email)
                .otpHash(otpHash)
                .expiresAt(Instant.now().plusSeconds(expiryMinutes * 60L))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .userId(userId)
                .build();

        emailOtpRepository.save(emailOtp);

        // Send OTP via Email
        emailService.sendOtp(email, otpCode, expiryMinutes);

        log.info("Email OTP requested for user: {}, email: {}", userId, maskEmail(email));

        return EmailOtpResponse.otpSent(
                maskEmail(email),
                expiryMinutes * 60,
                resendCooldownSeconds
        );
    }

    /**
     * Verify an email OTP code.
     */
    @Transactional
    public EmailOtpResponse verifyOtp(String email, String code, String ipAddress) {
        email = normalizeEmail(email);

        Optional<EmailOtp> otpOpt = emailOtpRepository.findLatestValidOtp(email, Instant.now());

        if (otpOpt.isEmpty()) {
            log.warn("No valid email OTP found for: {}", maskEmail(email));
            return EmailOtpResponse.error("No valid OTP found. Please request a new one.");
        }

        EmailOtp otp = otpOpt.get();

        // Check max attempts
        if (otp.getAttemptCount() >= maxAttempts) {
            log.warn("Max email OTP attempts exceeded for: {}", maskEmail(email));
            return EmailOtpResponse.error("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        // Increment attempt count
        otp.incrementAttempt();
        emailOtpRepository.save(otp);

        // Verify the code
        if (!passwordEncoder.matches(code, otp.getOtpHash())) {
            int remaining = maxAttempts - otp.getAttemptCount();
            log.warn("Invalid email OTP attempt for: {}, remaining: {}",
                    maskEmail(email), remaining);
            return EmailOtpResponse.error("Invalid OTP code", remaining);
        }

        // Mark as verified
        otp.markVerified();
        emailOtpRepository.save(otp);

        // Update user email verification status if user exists
        String userId = null;
        Optional<UserProfile> userOpt = userProfileRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            UserProfile user = userOpt.get();
            // Email is already set, just mark as verified (add emailVerified field if needed)
            userId = user.getId().toString();
        }

        log.info("Email OTP verified successfully for: {}", maskEmail(email));

        return EmailOtpResponse.verified(userId);
    }

    /**
     * Verify email OTP for a specific user
     */
    @Transactional
    public EmailOtpResponse verifyOtpForUser(UUID userId, String email, String code, String ipAddress) {
        email = normalizeEmail(email);

        Optional<EmailOtp> otpOpt = emailOtpRepository.findLatestValidOtp(email, Instant.now());

        if (otpOpt.isEmpty()) {
            log.warn("No valid email OTP found for user: {}", userId);
            return EmailOtpResponse.error("No valid OTP found. Please request a new one.");
        }

        EmailOtp otp = otpOpt.get();

        // Verify this OTP belongs to the user
        if (otp.getUserId() != null && !otp.getUserId().equals(userId)) {
            log.warn("Email OTP user mismatch. Expected: {}, Got: {}", userId, otp.getUserId());
            return EmailOtpResponse.error("Invalid OTP for this user.");
        }

        // Check max attempts
        if (otp.getAttemptCount() >= maxAttempts) {
            log.warn("Max email OTP attempts exceeded for user: {}", userId);
            return EmailOtpResponse.error("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        // Increment attempt count
        otp.incrementAttempt();
        emailOtpRepository.save(otp);

        // Verify the code
        if (!passwordEncoder.matches(code, otp.getOtpHash())) {
            int remaining = maxAttempts - otp.getAttemptCount();
            log.warn("Invalid email OTP attempt for user: {}, remaining: {}", userId, remaining);
            return EmailOtpResponse.error("Invalid OTP code", remaining);
        }

        // Mark as verified
        otp.markVerified();
        emailOtpRepository.save(otp);

        // Update user profile with verified email
        Optional<UserProfile> userOpt = userProfileRepository.findById(userId);
        if (userOpt.isPresent()) {
            UserProfile user = userOpt.get();
            user.setEmail(email);
            userProfileRepository.save(user);
            log.info("Email verified and saved for user: {}", userId);
        }

        log.info("Email OTP verified successfully for user: {}", userId);

        return EmailOtpResponse.verified(userId.toString());
    }

    /**
     * Scheduled cleanup of expired email OTPs.
     */
    @Scheduled(cron = "0 0 * * * *") // Every hour
    @Transactional
    public void cleanupExpiredOtps() {
        Instant cutoff = Instant.now().minus(24, ChronoUnit.HOURS);
        int deleted = emailOtpRepository.deleteExpiredOtps(cutoff);
        if (deleted > 0) {
            log.info("Cleaned up {} expired email OTPs", deleted);
        }
    }

    // Private helper methods

    private String generateOtpCode() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            sb.append(secureRandom.nextInt(10));
        }
        return sb.toString();
    }

    private String normalizeEmail(String email) {
        return email.toLowerCase().trim();
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "****";
        }
        String[] parts = email.split("@");
        String local = parts[0];
        String domain = parts[1];

        if (local.length() <= 2) {
            return local.charAt(0) + "***@" + domain;
        }

        return local.substring(0, 2) + "***@" + domain;
    }

    private String checkRateLimits(String email, String ipAddress) {
        // Skip all rate limits in local profile
        if ("local".equalsIgnoreCase(activeProfile)) {
            return null;
        }

        // Check email-based rate limit
        Instant dayAgo = Instant.now().minus(24, ChronoUnit.HOURS);
        long emailRequests = emailOtpRepository.countOtpRequestsSince(email, dayAgo);
        if (emailRequests >= maxRequestsPerDay) {
            return "Too many OTP requests for this email. Please try again later.";
        }

        // Check IP-based rate limit
        Instant hourAgo = Instant.now().minus(1, ChronoUnit.HOURS);
        long ipRequests = emailOtpRepository.countOtpRequestsFromIpSince(ipAddress, hourAgo);
        if (ipRequests >= maxRequestsPerIpPerHour) {
            return "Too many OTP requests from this IP address. Please try again later.";
        }

        return null;
    }
}
