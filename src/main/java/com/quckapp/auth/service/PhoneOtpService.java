package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.PhoneOtp;
import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.entity.UserProfile;
import com.quckapp.auth.domain.entity.UserRole;
import com.quckapp.auth.domain.entity.AuthUser.AuthStatus;
import com.quckapp.auth.domain.repository.PhoneOtpRepository;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.domain.repository.UserProfileRepository;
import com.quckapp.auth.dto.OtpResponse;
import com.quckapp.auth.dto.PhoneLoginRequest;
import com.quckapp.auth.security.jwt.JwtOperations;
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
public class PhoneOtpService {

    private final PhoneOtpRepository phoneOtpRepository;
    private final UserProfileRepository userProfileRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SmsService smsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtOperations jwtService;

    private static final int REFRESH_TOKEN_EXPIRY_DAYS = 7;

    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${otp.phone.length:6}")
    private int otpLength;

    @Value("${otp.phone.expiry-minutes:5}")
    private int expiryMinutes;

    @Value("${otp.phone.max-attempts:5}")
    private int maxAttempts;

    @Value("${otp.phone.resend-cooldown-seconds:60}")
    private int resendCooldownSeconds;

    @Value("${otp.phone.max-requests-per-day:5}")
    private int maxRequestsPerDay;

    @Value("${otp.phone.max-requests-per-ip-per-hour:10}")
    private int maxRequestsPerIpPerHour;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    @Value("${sms.mock.enabled:false}")
    private boolean smsMockEnabled;

    /**
     * Request a new OTP for the given phone number.
     */
    @Transactional
    public OtpResponse requestOtp(String phoneNumber, String ipAddress, String userAgent) {
        // Normalize phone number
        phoneNumber = normalizePhoneNumber(phoneNumber);

        // Check rate limits
        String rateLimitError = checkRateLimits(phoneNumber, ipAddress);
        if (rateLimitError != null) {
            return OtpResponse.error(rateLimitError);
        }

        // Check resend cooldown
        Optional<PhoneOtp> existingOtp = phoneOtpRepository.findLatestValidOtp(phoneNumber, Instant.now());
        if (existingOtp.isPresent()) {
            long secondsSinceCreated = ChronoUnit.SECONDS.between(
                    existingOtp.get().getCreatedAt(), Instant.now());
            if (secondsSinceCreated < resendCooldownSeconds) {
                int remainingCooldown = (int) (resendCooldownSeconds - secondsSinceCreated);
                return OtpResponse.builder()
                        .success(false)
                        .message("Please wait before requesting another OTP")
                        .resendCooldownSeconds(remainingCooldown)
                        .build();
            }
        }

        // Invalidate any existing pending OTPs
        phoneOtpRepository.invalidatePendingOtps(phoneNumber);

        // Generate new OTP
        String otpCode = generateOtpCode();
        log.debug("DEBUG [REMOVE IN PROD]: Generated OTP for {}: {}", maskPhoneNumber(phoneNumber), otpCode);
        String otpHash = passwordEncoder.encode(otpCode);

        // Create and save OTP entity
        PhoneOtp phoneOtp = PhoneOtp.builder()
                .phoneNumber(phoneNumber)
                .otpHash(otpHash)
                .expiresAt(Instant.now().plusSeconds(expiryMinutes * 60L))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        phoneOtpRepository.save(phoneOtp);

        // Send OTP via SMS (async via Kafka)
        smsService.sendOtp(phoneNumber, otpCode, expiryMinutes);

        log.info("OTP requested for phone: {}, code: {}", maskPhoneNumber(phoneNumber), otpCode);

        // Build response with OTP included for development testing
        return OtpResponse.builder()
                .success(true)
                .message("OTP sent successfully")
                .maskedPhone(maskPhoneNumber(phoneNumber))
                .expiresInSeconds(expiryMinutes * 60)
                .resendCooldownSeconds(resendCooldownSeconds)
                .testOtp(otpCode)
                .build();
    }

    /**
     * Verify an OTP code.
     */
    @Transactional
    public OtpResponse verifyOtp(String phoneNumber, String code, String ipAddress) {
        phoneNumber = normalizePhoneNumber(phoneNumber);

        Optional<PhoneOtp> otpOpt = phoneOtpRepository.findLatestValidOtp(phoneNumber, Instant.now());

        if (otpOpt.isEmpty()) {
            log.warn("No valid OTP found for phone: {}", maskPhoneNumber(phoneNumber));
            return OtpResponse.error("No valid OTP found. Please request a new one.");
        }

        PhoneOtp otp = otpOpt.get();

        // Check max attempts
        if (otp.getAttemptCount() >= maxAttempts) {
            log.warn("Max OTP attempts exceeded for phone: {}", maskPhoneNumber(phoneNumber));
            return OtpResponse.error("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        // Increment attempt count
        otp.incrementAttempt();
        phoneOtpRepository.save(otp);

        // Verify the code
        if (!passwordEncoder.matches(code, otp.getOtpHash())) {
            int remaining = maxAttempts - otp.getAttemptCount();
            log.warn("Invalid OTP attempt for phone: {}, remaining: {}",
                    maskPhoneNumber(phoneNumber), remaining);
            return OtpResponse.error("Invalid OTP code", remaining);
        }

        // Mark as verified
        otp.markVerified();
        phoneOtpRepository.save(otp);

        // Update user phone verification status if user exists
        Optional<UserProfile> userOpt = userProfileRepository.findByPhoneNumber(phoneNumber);
        String userId = null;
        if (userOpt.isPresent()) {
            UserProfile user = userOpt.get();
            user.setPhoneVerified(true);
            user.setPhoneVerifiedAt(Instant.now());
            userProfileRepository.save(user);
            userId = user.getId().toString();
        }

        log.info("OTP verified successfully for phone: {}", maskPhoneNumber(phoneNumber));

        return OtpResponse.verified(userId);
    }

    /**
     * Login with phone OTP. Creates user if not exists.
     */
    @Transactional
    public OtpResponse loginWithOtp(PhoneLoginRequest request, String ipAddress, String userAgent) {
        String phoneNumber = normalizePhoneNumber(request.getPhoneNumber());

        // First verify the OTP
        OtpResponse verifyResponse = verifyOtp(phoneNumber, request.getCode(), ipAddress);
        if (!verifyResponse.isSuccess()) {
            return verifyResponse;
        }

        // Find or create user
        UserProfile userProfile = userProfileRepository.findByPhoneNumber(phoneNumber)
                .orElse(null);

        if (userProfile == null) {
            try {
                userProfile = createUserFromPhone(phoneNumber, request.getDisplayName());
            } catch (Exception e) {
                // If creation fails (e.g., constraint violation), try to find existing user again
                log.warn("Failed to create user, attempting to find existing: {}", e.getMessage());
                userProfile = userProfileRepository.findByPhoneNumber(phoneNumber)
                        .orElseThrow(() -> new RuntimeException("Failed to create or find user profile"));
            }
        }

        // Check if user is banned or inactive
        if (userProfile.isBanned()) {
            return OtpResponse.error("Account is suspended. Please contact support.");
        }

        if (!userProfile.isActive()) {
            return OtpResponse.error("Account is inactive. Please contact support.");
        }

        // Get or create AuthUser
        AuthUser authUser = userProfile.getAuthUser();
        if (authUser == null) {
            authUser = createAuthUser(userProfile);
        }

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(authUser);
        String refreshToken = jwtService.generateRefreshToken(authUser);

        // Save refresh token to database for token rotation and revocation
        saveRefreshToken(authUser, refreshToken, ipAddress, userAgent);

        // Update last login
        authUser.setLastLoginAt(Instant.now());
        authUser.setLastLoginIp(ipAddress);

        // User needs profile setup if they have a temporary username (starts with "user_")
        String username = userProfile.getUsername();
        boolean needsProfileSetup = username == null || username.isEmpty() || username.startsWith("user_");

        log.info("Phone login successful for: {}, needsProfileSetup: {}",
                maskPhoneNumber(phoneNumber), needsProfileSetup);

        return OtpResponse.loginSuccess(
                accessToken,
                refreshToken,
                OtpResponse.UserDto.builder()
                        .id(userProfile.getId().toString())
                        .phoneNumber(maskPhoneNumber(phoneNumber))
                        .username(userProfile.getUsername())
                        .displayName(userProfile.getDisplayName())
                        .email(userProfile.getEmail())
                        .avatar(userProfile.getAvatar())
                        .phoneVerified(true)
                        .newUser(needsProfileSetup) // true if user needs to set username
                        .build()
        );
    }

    /**
     * Scheduled cleanup of expired OTPs.
     */
    @Scheduled(cron = "0 0 * * * *") // Every hour
    @Transactional
    public void cleanupExpiredOtps() {
        Instant cutoff = Instant.now().minus(24, ChronoUnit.HOURS);
        int deleted = phoneOtpRepository.deleteExpiredOtps(cutoff);
        if (deleted > 0) {
            log.info("Cleaned up {} expired OTPs", deleted);
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

    private String normalizePhoneNumber(String phoneNumber) {
        // Remove spaces, dashes, and ensure + prefix
        String normalized = phoneNumber.replaceAll("[\\s\\-()]", "");
        if (!normalized.startsWith("+")) {
            normalized = "+" + normalized;
        }
        return normalized;
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "****";
        }
        int visibleDigits = 4;
        String suffix = phoneNumber.substring(phoneNumber.length() - visibleDigits);
        String prefix = phoneNumber.substring(0, Math.min(3, phoneNumber.length() - visibleDigits));
        String masked = "*".repeat(phoneNumber.length() - visibleDigits - prefix.length());
        return prefix + masked + suffix;
    }

    private String checkRateLimits(String phoneNumber, String ipAddress) {
        // Skip all rate limits in local profile
        if ("local".equalsIgnoreCase(activeProfile)) {
            return null;
        }

        // Check phone-based rate limit
        Instant dayAgo = Instant.now().minus(24, ChronoUnit.HOURS);
        long phoneRequests = phoneOtpRepository.countOtpRequestsSince(phoneNumber, dayAgo);
        if (phoneRequests >= maxRequestsPerDay) {
            return "Too many OTP requests for this phone number. Please try again later.";
        }

        // Check IP-based rate limit
        Instant hourAgo = Instant.now().minus(1, ChronoUnit.HOURS);
        long ipRequests = phoneOtpRepository.countOtpRequestsFromIpSince(ipAddress, hourAgo);
        if (ipRequests >= maxRequestsPerIpPerHour) {
            return "Too many OTP requests from this IP address. Please try again later.";
        }

        return null;
    }

    private UserProfile createUserFromPhone(String phoneNumber, String displayName) {
        // Generate placeholder email for phone-only users
        String placeholderEmail = phoneNumber.replaceAll("[^0-9]", "") + "@phone.local";

        // Create new AuthUser
        AuthUser authUser = AuthUser.builder()
                .email(placeholderEmail)
                .passwordHash("") // No password for phone-only users
                .externalId(UUID.randomUUID().toString())
                .status(AuthStatus.ACTIVE)
                .build();

        // Generate temporary username - user can change it on profile page
        String tempUsername = "user_" + UUID.randomUUID().toString().substring(0, 8);
        String defaultDisplayName = displayName != null ? displayName : "User " + phoneNumber.substring(phoneNumber.length() - 4);

        // Create UserProfile with temporary username - user changes it on profile page
        UserProfile profile = UserProfile.builder()
                .authUser(authUser)
                .phoneNumber(phoneNumber)
                .phoneVerified(true)
                .phoneVerifiedAt(Instant.now())
                .username(tempUsername) // Temporary username until user sets their own
                .displayName(defaultDisplayName)
                .isActive(true)
                .isVerified(true)
                .role(UserRole.USER)
                .build();

        return userProfileRepository.save(profile);
    }

    private AuthUser createAuthUser(UserProfile profile) {
        // Use profile email or generate placeholder from phone number
        String email = profile.getEmail();
        if (email == null || email.isEmpty()) {
            email = profile.getPhoneNumber().replaceAll("[^0-9]", "") + "@phone.local";
        }

        AuthUser authUser = AuthUser.builder()
                .externalId(UUID.randomUUID().toString())
                .email(email)
                .passwordHash("") // No password for phone-only users
                .status(AuthStatus.ACTIVE)
                .build();
        profile.setAuthUser(authUser);
        userProfileRepository.save(profile);
        return authUser;
    }

    /**
     * Save refresh token to database for token rotation and revocation.
     */
    private void saveRefreshToken(AuthUser user, String refreshToken, String ipAddress, String userAgent) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .expiresAt(Instant.now().plus(REFRESH_TOKEN_EXPIRY_DAYS, ChronoUnit.DAYS))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        refreshTokenRepository.save(token);
        log.debug("Refresh token saved for user: {}", user.getId());
    }
}
