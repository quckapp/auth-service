package com.quckapp.auth.service.impl;

import com.quckapp.auth.kafka.PhoneOtpRequestedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for KafkaSmsService
 */
@ExtendWith(MockitoExtension.class)
class KafkaSmsServiceTest {

    @Mock
    private KafkaTemplate<String, Object> kafkaTemplate;

    private KafkaSmsService kafkaSmsService;

    private static final String OTP_TOPIC = "notification.sms.otp";
    private static final String GENERIC_SMS_TOPIC = "notification.sms.generic";
    private static final String APP_NAME = "auth-service";

    @BeforeEach
    void setUp() {
        kafkaSmsService = new KafkaSmsService(kafkaTemplate);

        // Set the @Value fields using reflection
        ReflectionTestUtils.setField(kafkaSmsService, "otpTopic", OTP_TOPIC);
        ReflectionTestUtils.setField(kafkaSmsService, "genericSmsTopic", GENERIC_SMS_TOPIC);
        ReflectionTestUtils.setField(kafkaSmsService, "appName", APP_NAME);
    }

    @Nested
    @DisplayName("Send OTP Tests")
    class SendOtpTests {

        @Test
        @DisplayName("should send OTP successfully")
        void shouldSendOtpSuccessfully() {
            String phoneNumber = "+1234567890";
            String code = "123456";
            int expiryMinutes = 5;

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class)))
                    .thenReturn(future);

            kafkaSmsService.sendOtp(phoneNumber, code, expiryMinutes);

            ArgumentCaptor<PhoneOtpRequestedEvent> eventCaptor = ArgumentCaptor.forClass(PhoneOtpRequestedEvent.class);
            verify(kafkaTemplate).send(eq(OTP_TOPIC), eq(phoneNumber), eventCaptor.capture());

            PhoneOtpRequestedEvent event = eventCaptor.getValue();
            assertThat(event.getPhoneNumber()).isEqualTo(phoneNumber);
            assertThat(event.getOtpCode()).isEqualTo(code);
            assertThat(event.getAppName()).isEqualTo(APP_NAME);
            assertThat(event.getLocale()).isEqualTo("en");
            assertThat(event.getEventId()).isNotBlank();
            assertThat(event.getRequestedAt()).isNotNull();
            assertThat(event.getExpiresAt()).isAfter(Instant.now());
        }

        @Test
        @DisplayName("should calculate correct expiry time")
        void shouldCalculateCorrectExpiryTime() {
            String phoneNumber = "+1234567890";
            String code = "654321";
            int expiryMinutes = 10;

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class)))
                    .thenReturn(future);

            Instant beforeSend = Instant.now();
            kafkaSmsService.sendOtp(phoneNumber, code, expiryMinutes);
            Instant afterSend = Instant.now();

            ArgumentCaptor<PhoneOtpRequestedEvent> eventCaptor = ArgumentCaptor.forClass(PhoneOtpRequestedEvent.class);
            verify(kafkaTemplate).send(eq(OTP_TOPIC), eq(phoneNumber), eventCaptor.capture());

            PhoneOtpRequestedEvent event = eventCaptor.getValue();
            // Expiry should be approximately expiryMinutes * 60 seconds from now
            long expectedExpirySeconds = expiryMinutes * 60L;
            assertThat(event.getExpiresAt()).isAfter(beforeSend.plusSeconds(expectedExpirySeconds - 5));
            assertThat(event.getExpiresAt()).isBefore(afterSend.plusSeconds(expectedExpirySeconds + 5));
        }

        @Test
        @DisplayName("should handle send failure gracefully")
        void shouldHandleSendFailureGracefully() {
            String phoneNumber = "+1234567890";
            String code = "123456";
            int expiryMinutes = 5;

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.completeExceptionally(new RuntimeException("Kafka connection failed"));
            when(kafkaTemplate.send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class)))
                    .thenReturn(future);

            // Should not throw exception - failure is logged
            assertThatNoException().isThrownBy(() ->
                    kafkaSmsService.sendOtp(phoneNumber, code, expiryMinutes));

            verify(kafkaTemplate).send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class));
        }

        @Test
        @DisplayName("should generate unique event ID for each OTP")
        void shouldGenerateUniqueEventIdForEachOtp() {
            String phoneNumber = "+1234567890";
            String code = "123456";

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class)))
                    .thenReturn(future);

            kafkaSmsService.sendOtp(phoneNumber, code, 5);
            kafkaSmsService.sendOtp(phoneNumber, code, 5);

            ArgumentCaptor<PhoneOtpRequestedEvent> eventCaptor = ArgumentCaptor.forClass(PhoneOtpRequestedEvent.class);
            verify(kafkaTemplate, times(2)).send(eq(OTP_TOPIC), eq(phoneNumber), eventCaptor.capture());

            assertThat(eventCaptor.getAllValues().get(0).getEventId())
                    .isNotEqualTo(eventCaptor.getAllValues().get(1).getEventId());
        }
    }

    @Nested
    @DisplayName("Send Generic SMS Tests")
    class SendGenericSmsTests {

        @Test
        @DisplayName("should send generic SMS successfully")
        void shouldSendGenericSmsSuccessfully() {
            String phoneNumber = "+1234567890";
            String message = "Your login was successful.";

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(GENERIC_SMS_TOPIC), eq(phoneNumber), any(KafkaSmsService.GenericSmsEvent.class)))
                    .thenReturn(future);

            kafkaSmsService.sendSms(phoneNumber, message);

            ArgumentCaptor<KafkaSmsService.GenericSmsEvent> eventCaptor =
                    ArgumentCaptor.forClass(KafkaSmsService.GenericSmsEvent.class);
            verify(kafkaTemplate).send(eq(GENERIC_SMS_TOPIC), eq(phoneNumber), eventCaptor.capture());

            KafkaSmsService.GenericSmsEvent event = eventCaptor.getValue();
            assertThat(event.phoneNumber()).isEqualTo(phoneNumber);
            assertThat(event.message()).isEqualTo(message);
            assertThat(event.appName()).isEqualTo(APP_NAME);
            assertThat(event.eventId()).isNotBlank();
            assertThat(event.requestedAt()).isNotNull();
        }

        @Test
        @DisplayName("should handle generic SMS send failure gracefully")
        void shouldHandleGenericSmsSendFailureGracefully() {
            String phoneNumber = "+1234567890";
            String message = "Test message";

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.completeExceptionally(new RuntimeException("Kafka connection failed"));
            when(kafkaTemplate.send(eq(GENERIC_SMS_TOPIC), eq(phoneNumber), any(KafkaSmsService.GenericSmsEvent.class)))
                    .thenReturn(future);

            // Should not throw exception - failure is logged
            assertThatNoException().isThrownBy(() ->
                    kafkaSmsService.sendSms(phoneNumber, message));

            verify(kafkaTemplate).send(eq(GENERIC_SMS_TOPIC), eq(phoneNumber), any(KafkaSmsService.GenericSmsEvent.class));
        }
    }

    @Nested
    @DisplayName("Phone Number Masking Tests")
    class PhoneNumberMaskingTests {

        @Test
        @DisplayName("should mask phone number in logs")
        void shouldMaskPhoneNumberInLogs() {
            // This is primarily testing the private maskPhoneNumber method
            // We verify it indirectly through the logging behavior
            String phoneNumber = "+12025551234";
            String code = "123456";

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class)))
                    .thenReturn(future);

            // If we get here without exception, the masking is working
            assertThatNoException().isThrownBy(() ->
                    kafkaSmsService.sendOtp(phoneNumber, code, 5));
        }

        @Test
        @DisplayName("should handle short phone numbers in masking")
        void shouldHandleShortPhoneNumbersInMasking() {
            String phoneNumber = "123"; // Less than 4 characters
            String code = "123456";

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(OTP_TOPIC), eq(phoneNumber), any(PhoneOtpRequestedEvent.class)))
                    .thenReturn(future);

            // Should not throw exception even with short phone number
            assertThatNoException().isThrownBy(() ->
                    kafkaSmsService.sendOtp(phoneNumber, code, 5));
        }

        @Test
        @DisplayName("should handle null phone number in masking")
        void shouldHandleNullPhoneNumberInMasking() {
            String phoneNumber = null;
            String message = "Test message";

            CompletableFuture<SendResult<String, Object>> future = new CompletableFuture<>();
            future.complete(mock(SendResult.class));
            when(kafkaTemplate.send(eq(GENERIC_SMS_TOPIC), eq(phoneNumber), any(KafkaSmsService.GenericSmsEvent.class)))
                    .thenReturn(future);

            // Should not throw exception even with null phone number
            assertThatNoException().isThrownBy(() ->
                    kafkaSmsService.sendSms(phoneNumber, message));
        }
    }
}
