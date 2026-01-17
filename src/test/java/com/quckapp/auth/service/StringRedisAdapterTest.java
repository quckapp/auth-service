package com.quckapp.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

/**
 * Unit tests for StringRedisAdapter
 */
@ExtendWith(MockitoExtension.class)
class StringRedisAdapterTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private StringRedisAdapter stringRedisAdapter;

    @BeforeEach
    void setUp() {
        stringRedisAdapter = new StringRedisAdapter(redisTemplate);
    }

    @Nested
    @DisplayName("Set operation tests")
    class SetOperationTests {

        @Test
        @DisplayName("should set value with TTL")
        void shouldSetValueWithTtl() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "test:key";
            String value = "test-value";
            Duration ttl = Duration.ofMinutes(30);

            stringRedisAdapter.set(key, value, ttl);

            verify(redisTemplate).opsForValue();
            verify(valueOperations).set(key, value, ttl);
        }

        @Test
        @DisplayName("should set value with short TTL")
        void shouldSetValueWithShortTtl() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "session:abc123";
            String value = "session-data";
            Duration ttl = Duration.ofSeconds(60);

            stringRedisAdapter.set(key, value, ttl);

            verify(valueOperations).set(key, value, ttl);
        }

        @Test
        @DisplayName("should set value with long TTL")
        void shouldSetValueWithLongTtl() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "refresh:token:user123";
            String value = "refresh-token-data";
            Duration ttl = Duration.ofDays(7);

            stringRedisAdapter.set(key, value, ttl);

            verify(valueOperations).set(key, value, ttl);
        }

        @Test
        @DisplayName("should handle empty value")
        void shouldHandleEmptyValue() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "empty:key";
            String value = "";
            Duration ttl = Duration.ofMinutes(5);

            stringRedisAdapter.set(key, value, ttl);

            verify(valueOperations).set(key, value, ttl);
        }
    }

    @Nested
    @DisplayName("Get operation tests")
    class GetOperationTests {

        @Test
        @DisplayName("should get existing value")
        void shouldGetExistingValue() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "test:key";
            String expectedValue = "stored-value";
            given(valueOperations.get(key)).willReturn(expectedValue);

            String result = stringRedisAdapter.get(key);

            assertThat(result).isEqualTo(expectedValue);
            verify(redisTemplate).opsForValue();
            verify(valueOperations).get(key);
        }

        @Test
        @DisplayName("should return null for non-existing key")
        void shouldReturnNullForNonExistingKey() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "non:existing:key";
            given(valueOperations.get(key)).willReturn(null);

            String result = stringRedisAdapter.get(key);

            assertThat(result).isNull();
        }

        @Test
        @DisplayName("should get empty string value")
        void shouldGetEmptyStringValue() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "empty:value:key";
            given(valueOperations.get(key)).willReturn("");

            String result = stringRedisAdapter.get(key);

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should get complex value")
        void shouldGetComplexValue() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "user:profile:123";
            String jsonValue = "{\"userId\":\"123\",\"name\":\"Test User\",\"email\":\"test@example.com\"}";
            given(valueOperations.get(key)).willReturn(jsonValue);

            String result = stringRedisAdapter.get(key);

            assertThat(result).isEqualTo(jsonValue);
        }
    }

    @Nested
    @DisplayName("HasKey operation tests")
    class HasKeyOperationTests {

        @Test
        @DisplayName("should return true when key exists")
        void shouldReturnTrueWhenKeyExists() {
            String key = "existing:key";
            given(redisTemplate.hasKey(key)).willReturn(Boolean.TRUE);

            boolean result = stringRedisAdapter.hasKey(key);

            assertThat(result).isTrue();
            verify(redisTemplate).hasKey(key);
        }

        @Test
        @DisplayName("should return false when key does not exist")
        void shouldReturnFalseWhenKeyDoesNotExist() {
            String key = "non:existing:key";
            given(redisTemplate.hasKey(key)).willReturn(Boolean.FALSE);

            boolean result = stringRedisAdapter.hasKey(key);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false when hasKey returns null")
        void shouldReturnFalseWhenHasKeyReturnsNull() {
            String key = "unknown:key";
            given(redisTemplate.hasKey(key)).willReturn(null);

            boolean result = stringRedisAdapter.hasKey(key);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should check key with special characters")
        void shouldCheckKeyWithSpecialCharacters() {
            String key = "rate:limit:user@example.com:192.168.1.1";
            given(redisTemplate.hasKey(key)).willReturn(Boolean.TRUE);

            boolean result = stringRedisAdapter.hasKey(key);

            assertThat(result).isTrue();
            verify(redisTemplate).hasKey(key);
        }
    }

    @Nested
    @DisplayName("Delete operation tests")
    class DeleteOperationTests {

        @Test
        @DisplayName("should delete existing key")
        void shouldDeleteExistingKey() {
            String key = "key:to:delete";
            given(redisTemplate.delete(key)).willReturn(Boolean.TRUE);

            stringRedisAdapter.delete(key);

            verify(redisTemplate).delete(key);
        }

        @Test
        @DisplayName("should handle delete of non-existing key")
        void shouldHandleDeleteOfNonExistingKey() {
            String key = "non:existing:key";
            given(redisTemplate.delete(key)).willReturn(Boolean.FALSE);

            // Should not throw
            assertThatCode(() -> stringRedisAdapter.delete(key))
                    .doesNotThrowAnyException();

            verify(redisTemplate).delete(key);
        }

        @Test
        @DisplayName("should delete session key")
        void shouldDeleteSessionKey() {
            String key = "session:user:abc123";
            given(redisTemplate.delete(key)).willReturn(Boolean.TRUE);

            stringRedisAdapter.delete(key);

            verify(redisTemplate).delete(key);
        }

        @Test
        @DisplayName("should delete rate limit key")
        void shouldDeleteRateLimitKey() {
            String key = "rate:limit:ip:10.0.0.1";
            given(redisTemplate.delete(key)).willReturn(Boolean.TRUE);

            stringRedisAdapter.delete(key);

            verify(redisTemplate).delete(key);
        }
    }

    @Nested
    @DisplayName("Integration scenario tests")
    class IntegrationScenarioTests {

        @Test
        @DisplayName("should support full lifecycle: set, get, hasKey, delete")
        void shouldSupportFullLifecycle() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String key = "lifecycle:test:key";
            String value = "lifecycle-value";
            Duration ttl = Duration.ofMinutes(10);

            // Set
            stringRedisAdapter.set(key, value, ttl);
            verify(valueOperations).set(key, value, ttl);

            // Get
            given(valueOperations.get(key)).willReturn(value);
            String retrievedValue = stringRedisAdapter.get(key);
            assertThat(retrievedValue).isEqualTo(value);

            // HasKey
            given(redisTemplate.hasKey(key)).willReturn(Boolean.TRUE);
            boolean exists = stringRedisAdapter.hasKey(key);
            assertThat(exists).isTrue();

            // Delete
            given(redisTemplate.delete(key)).willReturn(Boolean.TRUE);
            stringRedisAdapter.delete(key);
            verify(redisTemplate).delete(key);
        }

        @Test
        @DisplayName("should handle OTP storage scenario")
        void shouldHandleOtpStorageScenario() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String phoneNumber = "+1234567890";
            String otpKey = "otp:" + phoneNumber;
            String otpCode = "123456";
            Duration otpTtl = Duration.ofMinutes(5);

            // Store OTP
            stringRedisAdapter.set(otpKey, otpCode, otpTtl);
            verify(valueOperations).set(otpKey, otpCode, otpTtl);

            // Verify OTP exists
            given(redisTemplate.hasKey(otpKey)).willReturn(Boolean.TRUE);
            assertThat(stringRedisAdapter.hasKey(otpKey)).isTrue();

            // Get OTP for verification
            given(valueOperations.get(otpKey)).willReturn(otpCode);
            assertThat(stringRedisAdapter.get(otpKey)).isEqualTo(otpCode);

            // Delete after verification
            stringRedisAdapter.delete(otpKey);
            verify(redisTemplate).delete(otpKey);
        }

        @Test
        @DisplayName("should handle session token scenario")
        void shouldHandleSessionTokenScenario() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String userId = "user-123";
            String sessionKey = "session:" + userId;
            String sessionToken = "jwt-token-abc123";
            Duration sessionTtl = Duration.ofHours(24);

            // Create session
            stringRedisAdapter.set(sessionKey, sessionToken, sessionTtl);
            verify(valueOperations).set(sessionKey, sessionToken, sessionTtl);

            // Validate session
            given(valueOperations.get(sessionKey)).willReturn(sessionToken);
            String retrievedToken = stringRedisAdapter.get(sessionKey);
            assertThat(retrievedToken).isEqualTo(sessionToken);

            // Logout - delete session
            stringRedisAdapter.delete(sessionKey);
            verify(redisTemplate).delete(sessionKey);
        }

        @Test
        @DisplayName("should handle password reset token scenario")
        void shouldHandlePasswordResetTokenScenario() {
            given(redisTemplate.opsForValue()).willReturn(valueOperations);
            String email = "user@example.com";
            String resetKey = "password:reset:" + email;
            String resetToken = "reset-token-xyz789";
            Duration resetTtl = Duration.ofHours(1);

            // Store reset token
            stringRedisAdapter.set(resetKey, resetToken, resetTtl);
            verify(valueOperations).set(resetKey, resetToken, resetTtl);

            // Check if reset is pending
            given(redisTemplate.hasKey(resetKey)).willReturn(Boolean.TRUE);
            assertThat(stringRedisAdapter.hasKey(resetKey)).isTrue();

            // Retrieve token for validation
            given(valueOperations.get(resetKey)).willReturn(resetToken);
            assertThat(stringRedisAdapter.get(resetKey)).isEqualTo(resetToken);

            // Invalidate after use
            stringRedisAdapter.delete(resetKey);
            verify(redisTemplate).delete(resetKey);
        }
    }
}
