package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.dto.OtpResponse;
import com.quckapp.auth.dto.PhoneLoginRequest;
import com.quckapp.auth.dto.PhoneOtpRequest;
import com.quckapp.auth.dto.PhoneVerifyRequest;
import com.quckapp.auth.service.PhoneOtpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for PhoneAuthController
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PhoneAuthControllerTest {

    @Mock
    private PhoneOtpService phoneOtpService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        PhoneAuthController controller = new PhoneAuthController(phoneOtpService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("Request OTP Tests")
    class RequestOtpTests {

        @Test
        @DisplayName("should request OTP successfully")
        void shouldRequestOtpSuccessfully() throws Exception {
            PhoneOtpRequest request = PhoneOtpRequest.builder()
                    .phoneNumber("+1234567890")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("OTP sent successfully")
                    .maskedPhone("+1******890")
                    .expiresInSeconds(300)
                    .resendCooldownSeconds(60)
                    .build();

            when(phoneOtpService.requestOtp(eq("+1234567890"), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/request-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
                            .header("User-Agent", "TestAgent"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("OTP sent successfully"))
                    .andExpect(jsonPath("$.maskedPhone").value("+1******890"))
                    .andExpect(jsonPath("$.expiresInSeconds").value(300));

            verify(phoneOtpService).requestOtp(eq("+1234567890"), any(), eq("TestAgent"));
        }

        @Test
        @DisplayName("should return bad request when OTP request fails")
        void shouldReturnBadRequestWhenOtpRequestFails() throws Exception {
            PhoneOtpRequest request = PhoneOtpRequest.builder()
                    .phoneNumber("+1234567890")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(false)
                    .message("Rate limit exceeded")
                    .build();

            when(phoneOtpService.requestOtp(any(), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/request-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.message").value("Rate limit exceeded"));
        }

        @Test
        @DisplayName("should extract client IP from X-Forwarded-For header")
        void shouldExtractClientIpFromXForwardedFor() throws Exception {
            PhoneOtpRequest request = PhoneOtpRequest.builder()
                    .phoneNumber("+1234567890")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("OTP sent")
                    .build();

            when(phoneOtpService.requestOtp(any(), eq("192.168.1.1"), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/request-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
                            .header("X-Forwarded-For", "192.168.1.1, 10.0.0.1"))
                    .andExpect(status().isOk());

            verify(phoneOtpService).requestOtp(any(), eq("192.168.1.1"), any());
        }

        @Test
        @DisplayName("should extract client IP from X-Real-IP header")
        void shouldExtractClientIpFromXRealIp() throws Exception {
            PhoneOtpRequest request = PhoneOtpRequest.builder()
                    .phoneNumber("+1234567890")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("OTP sent")
                    .build();

            when(phoneOtpService.requestOtp(any(), eq("10.0.0.5"), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/request-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
                            .header("X-Real-IP", "10.0.0.5"))
                    .andExpect(status().isOk());

            verify(phoneOtpService).requestOtp(any(), eq("10.0.0.5"), any());
        }
    }

    @Nested
    @DisplayName("Verify OTP Tests")
    class VerifyOtpTests {

        @Test
        @DisplayName("should verify OTP successfully")
        void shouldVerifyOtpSuccessfully() throws Exception {
            PhoneVerifyRequest request = PhoneVerifyRequest.builder()
                    .phoneNumber("+1234567890")
                    .code("123456")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("Phone verified successfully")
                    .verified(true)
                    .userId("user-123")
                    .build();

            when(phoneOtpService.verifyOtp(eq("+1234567890"), eq("123456"), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/verify-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.verified").value(true))
                    .andExpect(jsonPath("$.userId").value("user-123"));

            verify(phoneOtpService).verifyOtp(eq("+1234567890"), eq("123456"), any());
        }

        @Test
        @DisplayName("should return bad request for invalid OTP")
        void shouldReturnBadRequestForInvalidOtp() throws Exception {
            PhoneVerifyRequest request = PhoneVerifyRequest.builder()
                    .phoneNumber("+1234567890")
                    .code("000000")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(false)
                    .message("Invalid OTP code")
                    .remainingAttempts(2)
                    .build();

            when(phoneOtpService.verifyOtp(any(), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/verify-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.message").value("Invalid OTP code"))
                    .andExpect(jsonPath("$.remainingAttempts").value(2));
        }

        @Test
        @DisplayName("should return bad request for expired OTP")
        void shouldReturnBadRequestForExpiredOtp() throws Exception {
            PhoneVerifyRequest request = PhoneVerifyRequest.builder()
                    .phoneNumber("+1234567890")
                    .code("123456")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(false)
                    .message("OTP has expired")
                    .build();

            when(phoneOtpService.verifyOtp(any(), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/verify-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("OTP has expired"));
        }
    }

    @Nested
    @DisplayName("Login with OTP Tests")
    class LoginWithOtpTests {

        @Test
        @DisplayName("should login with OTP successfully")
        void shouldLoginWithOtpSuccessfully() throws Exception {
            PhoneLoginRequest request = PhoneLoginRequest.builder()
                    .phoneNumber("+1234567890")
                    .code("123456")
                    .deviceId("device-123")
                    .deviceName("iPhone 15")
                    .build();

            OtpResponse.UserDto userDto = OtpResponse.UserDto.builder()
                    .id("user-123")
                    .phoneNumber("+1234567890")
                    .displayName("John Doe")
                    .phoneVerified(true)
                    .newUser(false)
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("Login successful")
                    .accessToken("access-token-123")
                    .refreshToken("refresh-token-123")
                    .user(userDto)
                    .build();

            when(phoneOtpService.loginWithOtp(any(PhoneLoginRequest.class), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
                            .header("User-Agent", "TestAgent"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.accessToken").value("access-token-123"))
                    .andExpect(jsonPath("$.refreshToken").value("refresh-token-123"))
                    .andExpect(jsonPath("$.user.id").value("user-123"))
                    .andExpect(jsonPath("$.user.phoneVerified").value(true));

            verify(phoneOtpService).loginWithOtp(any(PhoneLoginRequest.class), any(), eq("TestAgent"));
        }

        @Test
        @DisplayName("should login and create new user")
        void shouldLoginAndCreateNewUser() throws Exception {
            PhoneLoginRequest request = PhoneLoginRequest.builder()
                    .phoneNumber("+9876543210")
                    .code("654321")
                    .displayName("New User")
                    .build();

            OtpResponse.UserDto userDto = OtpResponse.UserDto.builder()
                    .id("new-user-123")
                    .phoneNumber("+9876543210")
                    .displayName("New User")
                    .phoneVerified(true)
                    .newUser(true)
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("Login successful")
                    .accessToken("access-token-new")
                    .refreshToken("refresh-token-new")
                    .user(userDto)
                    .build();

            when(phoneOtpService.loginWithOtp(any(PhoneLoginRequest.class), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.user.newUser").value(true));
        }

        @Test
        @DisplayName("should return bad request for failed login")
        void shouldReturnBadRequestForFailedLogin() throws Exception {
            PhoneLoginRequest request = PhoneLoginRequest.builder()
                    .phoneNumber("+1234567890")
                    .code("000000")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(false)
                    .message("Invalid OTP")
                    .remainingAttempts(1)
                    .build();

            when(phoneOtpService.loginWithOtp(any(PhoneLoginRequest.class), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.remainingAttempts").value(1));
        }
    }

    @Nested
    @DisplayName("Resend OTP Tests")
    class ResendOtpTests {

        @Test
        @DisplayName("should resend OTP successfully")
        void shouldResendOtpSuccessfully() throws Exception {
            PhoneOtpRequest request = PhoneOtpRequest.builder()
                    .phoneNumber("+1234567890")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(true)
                    .message("OTP sent successfully")
                    .maskedPhone("+1******890")
                    .expiresInSeconds(300)
                    .resendCooldownSeconds(60)
                    .build();

            when(phoneOtpService.requestOtp(any(), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/resend-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("OTP sent successfully"));

            verify(phoneOtpService).requestOtp(eq("+1234567890"), any(), any());
        }

        @Test
        @DisplayName("should return bad request when resend is rate limited")
        void shouldReturnBadRequestWhenResendRateLimited() throws Exception {
            PhoneOtpRequest request = PhoneOtpRequest.builder()
                    .phoneNumber("+1234567890")
                    .build();

            OtpResponse response = OtpResponse.builder()
                    .success(false)
                    .message("Please wait before requesting another OTP")
                    .resendCooldownSeconds(45)
                    .build();

            when(phoneOtpService.requestOtp(any(), any(), any()))
                    .thenReturn(response);

            mockMvc.perform(post("/v1/auth/phone/resend-otp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.resendCooldownSeconds").value(45));
        }
    }
}
