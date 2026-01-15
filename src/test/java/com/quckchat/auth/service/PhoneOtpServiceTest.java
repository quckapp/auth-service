package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.*;
import com.quckapp.auth.domain.repository.PhoneOtpRepository;
import com.quckapp.auth.domain.repository.UserProfileRepository;
import com.quckapp.auth.dto.OtpResponse;
import com.quckapp.auth.dto.PhoneLoginRequest;
import com.quckapp.auth.security.jwt.JwtOperations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PhoneOtpService
 */
@ExtendWith(MockitoExtension.class)
class PhoneOtpServiceTest {

    @Mock
    private PhoneOtpRepository phoneOtpRepository;

    @Mock
    private UserProfileRepository userProfileRepository;

    @Mock
    private SmsService smsService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtOperations jwtService;

    private PhoneOtpService phoneOtpService;

    private static final String TEST_PHONE = "+1234567890";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";
    private static final String TEST_OTP_CODE = "123456";

    @BeforeEach
    void setUp() {
        phoneOtpService = new PhoneOtpService(
                phoneOtpRepository,
                userProfileRepository,
                smsService,
                passwordEncoder,
                jwtService
        );

        // Set configuration values via reflection
        ReflectionTestUtils.setField(phoneOtpService, "otpLength", 6);
        ReflectionTestUtils.setField(phoneOtpService, "expiryMinutes", 5);
        ReflectionTestUtils.setField(phoneOtpService, "maxAttempts", 5);
        ReflectionTestUtils.setField(phoneOtpService, "resendCooldownSeconds", 60);
        ReflectionTestUtils.setField(phoneOtpService, "maxRequestsPerDay", 5);
        ReflectionTestUtils.setField(phoneOtpService, "maxRequestsPerIpPerHour", 10);
    }

    @Nested
    @DisplayName("Request OTP tests")
    class RequestOtpTests {

        @Test
        @DisplayName("should request OTP successfully")
        void shouldRequestOtpSuccessfully() {
            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> {
                PhoneOtp otp = inv.getArgument(0);
                otp.setId(UUID.randomUUID());
                return otp;
            });

            OtpResponse response = phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).isEqualTo("OTP sent successfully");
            assertThat(response.getMaskedPhone()).isNotNull();
            assertThat(response.getExpiresInSeconds()).isEqualTo(300); // 5 minutes
            assertThat(response.getResendCooldownSeconds()).isEqualTo(60);

            verify(phoneOtpRepository).invalidatePendingOtps(TEST_PHONE);
            verify(phoneOtpRepository).save(any(PhoneOtp.class));
            verify(smsService).sendOtp(eq(TEST_PHONE), anyString(), eq(5));
        }

        @Test
        @DisplayName("should normalize phone number without plus sign")
        void shouldNormalizePhoneNumber() {
            String phoneWithoutPlus = "1234567890";
            when(phoneOtpRepository.countOtpRequestsSince(eq("+" + phoneWithoutPlus), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq("+" + phoneWithoutPlus), any(Instant.class))).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> inv.getArgument(0));

            OtpResponse response = phoneOtpService.requestOtp(phoneWithoutPlus, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
            verify(phoneOtpRepository).invalidatePendingOtps("+" + phoneWithoutPlus);
        }

        @Test
        @DisplayName("should normalize phone number with spaces and dashes")
        void shouldNormalizePhoneWithSpacesAndDashes() {
            String phoneWithFormat = "+1 (234) 567-890";
            String normalizedPhone = "+1234567890";
            when(phoneOtpRepository.countOtpRequestsSince(eq(normalizedPhone), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(normalizedPhone), any(Instant.class))).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> inv.getArgument(0));

            OtpResponse response = phoneOtpService.requestOtp(phoneWithFormat, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("should reject when phone rate limit exceeded")
        void shouldRejectWhenPhoneRateLimitExceeded() {
            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(5L);

            OtpResponse response = phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Too many OTP requests for this phone number");

            verify(phoneOtpRepository, never()).save(any());
            verify(smsService, never()).sendOtp(any(), any(), anyInt());
        }

        @Test
        @DisplayName("should reject when IP rate limit exceeded")
        void shouldRejectWhenIpRateLimitExceeded() {
            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(10L);

            OtpResponse response = phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Too many OTP requests from this IP address");

            verify(phoneOtpRepository, never()).save(any());
        }

        @Test
        @DisplayName("should reject when resend cooldown not met")
        void shouldRejectWhenCooldownNotMet() {
            PhoneOtp recentOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .createdAt(Instant.now().minusSeconds(30)) // 30 seconds ago
                    .expiresAt(Instant.now().plusSeconds(270))
                    .build();

            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(recentOtp));

            OtpResponse response = phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Please wait before requesting another OTP");
            assertThat(response.getResendCooldownSeconds()).isGreaterThan(0);

            verify(phoneOtpRepository, never()).save(any());
        }

        @Test
        @DisplayName("should allow request when cooldown has passed")
        void shouldAllowRequestWhenCooldownPassed() {
            PhoneOtp oldOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .createdAt(Instant.now().minusSeconds(65)) // 65 seconds ago (> 60 cooldown)
                    .expiresAt(Instant.now().plusSeconds(235))
                    .build();

            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(oldOtp));
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> inv.getArgument(0));

            OtpResponse response = phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
            verify(phoneOtpRepository).save(any(PhoneOtp.class));
        }

        @Test
        @DisplayName("should invalidate pending OTPs when requesting new one")
        void shouldInvalidatePendingOtps() {
            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> inv.getArgument(0));

            phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            verify(phoneOtpRepository).invalidatePendingOtps(TEST_PHONE);
        }

        @Test
        @DisplayName("should save OTP with correct data")
        void shouldSaveOtpWithCorrectData() {
            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> inv.getArgument(0));

            phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            ArgumentCaptor<PhoneOtp> captor = ArgumentCaptor.forClass(PhoneOtp.class);
            verify(phoneOtpRepository).save(captor.capture());

            PhoneOtp savedOtp = captor.getValue();
            assertThat(savedOtp.getPhoneNumber()).isEqualTo(TEST_PHONE);
            assertThat(savedOtp.getOtpHash()).isEqualTo("hashedOtp");
            assertThat(savedOtp.getIpAddress()).isEqualTo(TEST_IP);
            assertThat(savedOtp.getUserAgent()).isEqualTo(TEST_USER_AGENT);
            assertThat(savedOtp.getExpiresAt()).isAfter(Instant.now());
        }
    }

    @Nested
    @DisplayName("Verify OTP tests")
    class VerifyOtpTests {

        @Test
        @DisplayName("should verify OTP successfully for existing user")
        void shouldVerifyOtpSuccessfully() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            UserProfile existingUser = UserProfile.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .phoneVerified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.of(existingUser));
            when(userProfileRepository.save(any(UserProfile.class))).thenReturn(existingUser);

            OtpResponse response = phoneOtpService.verifyOtp(TEST_PHONE, TEST_OTP_CODE, TEST_IP);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getVerified()).isTrue();
            assertThat(response.getUserId()).isEqualTo(existingUser.getId().toString());

            verify(userProfileRepository).save(argThat(user ->
                    user.isPhoneVerified() && user.getPhoneVerifiedAt() != null
            ));
        }

        @Test
        @DisplayName("should verify OTP successfully for non-existing user")
        void shouldVerifyOtpForNonExistingUser() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.empty());

            OtpResponse response = phoneOtpService.verifyOtp(TEST_PHONE, TEST_OTP_CODE, TEST_IP);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getVerified()).isTrue();
            assertThat(response.getUserId()).isNull();

            verify(userProfileRepository, never()).save(any());
        }

        @Test
        @DisplayName("should reject when no valid OTP found")
        void shouldRejectWhenNoValidOtp() {
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.empty());

            OtpResponse response = phoneOtpService.verifyOtp(TEST_PHONE, TEST_OTP_CODE, TEST_IP);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("No valid OTP found");
        }

        @Test
        @DisplayName("should reject when max attempts exceeded")
        void shouldRejectWhenMaxAttemptsExceeded() {
            PhoneOtp otpWithMaxAttempts = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(5) // Max attempts reached
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(otpWithMaxAttempts));

            OtpResponse response = phoneOtpService.verifyOtp(TEST_PHONE, TEST_OTP_CODE, TEST_IP);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Maximum verification attempts exceeded");
        }

        @Test
        @DisplayName("should reject with invalid OTP code")
        void shouldRejectInvalidOtpCode() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches("wrongCode", "hashedOtp")).thenReturn(false);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);

            OtpResponse response = phoneOtpService.verifyOtp(TEST_PHONE, "wrongCode", TEST_IP);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Invalid OTP code");
            assertThat(response.getRemainingAttempts()).isEqualTo(4); // 5 - 1 attempt
        }

        @Test
        @DisplayName("should increment attempt count on failed verification")
        void shouldIncrementAttemptCount() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(2)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches("wrongCode", "hashedOtp")).thenReturn(false);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);

            phoneOtpService.verifyOtp(TEST_PHONE, "wrongCode", TEST_IP);

            // Verify save was called (attempt increment)
            verify(phoneOtpRepository, times(1)).save(any(PhoneOtp.class));
        }

        @Test
        @DisplayName("should mark OTP as verified on success")
        void shouldMarkOtpAsVerified() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.empty());

            phoneOtpService.verifyOtp(TEST_PHONE, TEST_OTP_CODE, TEST_IP);

            // Save should be called twice: once for increment, once for verification
            verify(phoneOtpRepository, times(2)).save(any(PhoneOtp.class));
        }
    }

    @Nested
    @DisplayName("Login with OTP tests")
    class LoginWithOtpTests {

        private PhoneLoginRequest createLoginRequest(String phone, String code) {
            return PhoneLoginRequest.builder()
                    .phoneNumber(phone)
                    .code(code)
                    .displayName("Test User")
                    .build();
        }

        @Test
        @DisplayName("should login successfully for existing user")
        void shouldLoginSuccessfullyForExistingUser() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            AuthUser authUser = AuthUser.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .build();

            UserProfile existingUser = UserProfile.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .displayName("Existing User")
                    .authUser(authUser)
                    .isActive(true)
                    .isBanned(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.of(existingUser));
            when(userProfileRepository.save(any(UserProfile.class))).thenReturn(existingUser);
            when(jwtService.generateAccessToken(authUser)).thenReturn("access-token");
            when(jwtService.generateRefreshToken(authUser)).thenReturn("refresh-token");

            OtpResponse response = phoneOtpService.loginWithOtp(createLoginRequest(TEST_PHONE, TEST_OTP_CODE), TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).isEqualTo("Login successful");
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
            assertThat(response.getUser()).isNotNull();
            assertThat(response.getUser().getDisplayName()).isEqualTo("Existing User");
            assertThat(response.getUser().isPhoneVerified()).isTrue();
        }

        @Test
        @DisplayName("should create new user and login for new phone")
        void shouldCreateNewUserForNewPhone() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            // First call for verifyOtp - empty, second call for loginWithOtp - return created user
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE))
                    .thenReturn(Optional.empty())
                    .thenReturn(Optional.empty());
            when(userProfileRepository.save(any(UserProfile.class))).thenAnswer(inv -> {
                UserProfile profile = inv.getArgument(0);
                if (profile.getId() == null) {
                    profile.setId(UUID.randomUUID());
                }
                return profile;
            });
            when(jwtService.generateAccessToken(any(AuthUser.class))).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any(AuthUser.class))).thenReturn("refresh-token");

            OtpResponse response = phoneOtpService.loginWithOtp(createLoginRequest(TEST_PHONE, TEST_OTP_CODE), TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getUser()).isNotNull();
            assertThat(response.getUser().isNewUser()).isTrue();
            assertThat(response.getUser().isPhoneVerified()).isTrue();

            // Verify user was created
            verify(userProfileRepository, atLeastOnce()).save(any(UserProfile.class));
        }

        @Test
        @DisplayName("should reject login for banned user")
        void shouldRejectLoginForBannedUser() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            UserProfile bannedUser = UserProfile.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .isActive(true)
                    .isBanned(true)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.of(bannedUser));
            when(userProfileRepository.save(any(UserProfile.class))).thenReturn(bannedUser);

            OtpResponse response = phoneOtpService.loginWithOtp(createLoginRequest(TEST_PHONE, TEST_OTP_CODE), TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Account is suspended");
        }

        @Test
        @DisplayName("should reject login for inactive user")
        void shouldRejectLoginForInactiveUser() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            UserProfile inactiveUser = UserProfile.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .isActive(false)
                    .isBanned(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.of(inactiveUser));
            when(userProfileRepository.save(any(UserProfile.class))).thenReturn(inactiveUser);

            OtpResponse response = phoneOtpService.loginWithOtp(createLoginRequest(TEST_PHONE, TEST_OTP_CODE), TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Account is inactive");
        }

        @Test
        @DisplayName("should fail login when OTP verification fails")
        void shouldFailLoginWhenOtpVerificationFails() {
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.empty());

            OtpResponse response = phoneOtpService.loginWithOtp(createLoginRequest(TEST_PHONE, TEST_OTP_CODE), TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("No valid OTP found");
        }

        @Test
        @DisplayName("should create AuthUser if profile has none")
        void shouldCreateAuthUserIfNone() {
            PhoneOtp validOtp = PhoneOtp.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .otpHash("hashedOtp")
                    .attemptCount(0)
                    .expiresAt(Instant.now().plusSeconds(300))
                    .verified(false)
                    .build();

            UserProfile userWithoutAuth = UserProfile.builder()
                    .id(UUID.randomUUID())
                    .phoneNumber(TEST_PHONE)
                    .email("test@example.com")
                    .displayName("Test User")
                    .authUser(null) // No AuthUser
                    .isActive(true)
                    .isBanned(false)
                    .build();

            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.of(validOtp));
            when(passwordEncoder.matches(TEST_OTP_CODE, "hashedOtp")).thenReturn(true);
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenReturn(validOtp);
            when(userProfileRepository.findByPhoneNumber(TEST_PHONE)).thenReturn(Optional.of(userWithoutAuth));
            when(userProfileRepository.save(any(UserProfile.class))).thenAnswer(inv -> inv.getArgument(0));
            when(jwtService.generateAccessToken(any(AuthUser.class))).thenReturn("access-token");
            when(jwtService.generateRefreshToken(any(AuthUser.class))).thenReturn("refresh-token");

            OtpResponse response = phoneOtpService.loginWithOtp(createLoginRequest(TEST_PHONE, TEST_OTP_CODE), TEST_IP, TEST_USER_AGENT);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getAccessToken()).isNotNull();

            // Verify AuthUser was created and profile was saved
            verify(userProfileRepository, atLeastOnce()).save(argThat(profile ->
                    profile.getAuthUser() != null
            ));
        }
    }

    @Nested
    @DisplayName("Cleanup tests")
    class CleanupTests {

        @Test
        @DisplayName("should cleanup expired OTPs")
        void shouldCleanupExpiredOtps() {
            when(phoneOtpRepository.deleteExpiredOtps(any(Instant.class))).thenReturn(10);

            phoneOtpService.cleanupExpiredOtps();

            verify(phoneOtpRepository).deleteExpiredOtps(any(Instant.class));
        }

        @Test
        @DisplayName("should not log when no OTPs cleaned up")
        void shouldNotLogWhenNoOtpsCleaned() {
            when(phoneOtpRepository.deleteExpiredOtps(any(Instant.class))).thenReturn(0);

            phoneOtpService.cleanupExpiredOtps();

            verify(phoneOtpRepository).deleteExpiredOtps(any(Instant.class));
        }
    }

    @Nested
    @DisplayName("Phone number masking tests")
    class PhoneNumberMaskingTests {

        @Test
        @DisplayName("should mask phone number in response")
        void shouldMaskPhoneNumberInResponse() {
            when(phoneOtpRepository.countOtpRequestsSince(eq(TEST_PHONE), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.countOtpRequestsFromIpSince(eq(TEST_IP), any(Instant.class))).thenReturn(0L);
            when(phoneOtpRepository.findLatestValidOtp(eq(TEST_PHONE), any(Instant.class))).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("hashedOtp");
            when(phoneOtpRepository.save(any(PhoneOtp.class))).thenAnswer(inv -> inv.getArgument(0));

            OtpResponse response = phoneOtpService.requestOtp(TEST_PHONE, TEST_IP, TEST_USER_AGENT);

            assertThat(response.getMaskedPhone()).isNotNull();
            assertThat(response.getMaskedPhone()).isNotEqualTo(TEST_PHONE);
            // Masked phone should end with last 4 digits
            assertThat(response.getMaskedPhone()).endsWith("7890");
        }
    }
}
