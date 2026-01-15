package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for ApiKey entity
 */
@DisplayName("ApiKey Entity Tests")
class ApiKeyTest {

    private ApiKey apiKey;

    @BeforeEach
    void setUp() {
        apiKey = ApiKey.builder()
                .id(UUID.randomUUID())
                .name("Test API Key")
                .keyHash("hashed-key-value")
                .keyPrefix("qc_test_")
                .active(true)
                .permissions(new HashSet<>())
                .ipWhitelist(new HashSet<>())
                .build();
    }

    @Nested
    @DisplayName("isValid() Tests")
    class IsValidTests {

        @Test
        @DisplayName("should return true when active and not expired")
        void shouldReturnTrueWhenActiveAndNotExpired() {
            apiKey.setActive(true);
            apiKey.setExpiresAt(null);

            assertThat(apiKey.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return true when active and expiration is in future")
        void shouldReturnTrueWhenActiveAndExpirationInFuture() {
            apiKey.setActive(true);
            apiKey.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

            assertThat(apiKey.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return false when not active")
        void shouldReturnFalseWhenNotActive() {
            apiKey.setActive(false);

            assertThat(apiKey.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when expired")
        void shouldReturnFalseWhenExpired() {
            apiKey.setActive(true);
            apiKey.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(apiKey.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when inactive even if not expired")
        void shouldReturnFalseWhenInactiveEvenIfNotExpired() {
            apiKey.setActive(false);
            apiKey.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

            assertThat(apiKey.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("hasPermission() Tests")
    class HasPermissionTests {

        @Test
        @DisplayName("should return true when key has the specific permission")
        void shouldReturnTrueWhenHasSpecificPermission() {
            apiKey.getPermissions().add(ApiKey.ApiPermission.READ_USER);

            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.READ_USER)).isTrue();
        }

        @Test
        @DisplayName("should return false when key does not have the permission")
        void shouldReturnFalseWhenDoesNotHavePermission() {
            apiKey.getPermissions().add(ApiKey.ApiPermission.READ_USER);

            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.WRITE_USER)).isFalse();
        }

        @Test
        @DisplayName("should return true for any permission when key has ADMIN permission")
        void shouldReturnTrueForAnyPermissionWhenAdmin() {
            apiKey.getPermissions().add(ApiKey.ApiPermission.ADMIN);

            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.READ_USER)).isTrue();
            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.WRITE_USER)).isTrue();
            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.VALIDATE_TOKEN)).isTrue();
            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.REVOKE_TOKEN)).isTrue();
            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.READ_AUDIT)).isTrue();
            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.MANAGE_SESSIONS)).isTrue();
        }

        @Test
        @DisplayName("should return false when permissions set is empty")
        void shouldReturnFalseWhenPermissionsEmpty() {
            assertThat(apiKey.hasPermission(ApiKey.ApiPermission.READ_USER)).isFalse();
        }
    }

    @Nested
    @DisplayName("isIpAllowed() Tests")
    class IsIpAllowedTests {

        @Test
        @DisplayName("should return true when whitelist is empty")
        void shouldReturnTrueWhenWhitelistEmpty() {
            assertThat(apiKey.isIpAllowed("192.168.1.1")).isTrue();
            assertThat(apiKey.isIpAllowed("10.0.0.1")).isTrue();
        }

        @Test
        @DisplayName("should return true when IP is in whitelist")
        void shouldReturnTrueWhenIpInWhitelist() {
            apiKey.getIpWhitelist().add("192.168.1.1");
            apiKey.getIpWhitelist().add("10.0.0.1");

            assertThat(apiKey.isIpAllowed("192.168.1.1")).isTrue();
            assertThat(apiKey.isIpAllowed("10.0.0.1")).isTrue();
        }

        @Test
        @DisplayName("should return false when IP is not in whitelist")
        void shouldReturnFalseWhenIpNotInWhitelist() {
            apiKey.getIpWhitelist().add("192.168.1.1");

            assertThat(apiKey.isIpAllowed("192.168.1.2")).isFalse();
            assertThat(apiKey.isIpAllowed("10.0.0.1")).isFalse();
        }
    }

    @Nested
    @DisplayName("recordUsage() Tests")
    class RecordUsageTests {

        @Test
        @DisplayName("should update lastUsedAt timestamp")
        void shouldUpdateLastUsedAtTimestamp() {
            Instant before = Instant.now();
            apiKey.recordUsage("192.168.1.1");
            Instant after = Instant.now();

            assertThat(apiKey.getLastUsedAt()).isNotNull();
            assertThat(apiKey.getLastUsedAt()).isBetween(before, after.plusMillis(1));
        }

        @Test
        @DisplayName("should update lastUsedIp")
        void shouldUpdateLastUsedIp() {
            apiKey.recordUsage("192.168.1.100");

            assertThat(apiKey.getLastUsedIp()).isEqualTo("192.168.1.100");
        }

        @Test
        @DisplayName("should increment usage count")
        void shouldIncrementUsageCount() {
            apiKey.setUsageCount(5);

            apiKey.recordUsage("192.168.1.1");
            assertThat(apiKey.getUsageCount()).isEqualTo(6);

            apiKey.recordUsage("192.168.1.1");
            assertThat(apiKey.getUsageCount()).isEqualTo(7);
        }

        @Test
        @DisplayName("should record multiple usages correctly")
        void shouldRecordMultipleUsagesCorrectly() {
            apiKey.setUsageCount(0);

            apiKey.recordUsage("192.168.1.1");
            apiKey.recordUsage("192.168.1.2");
            apiKey.recordUsage("10.0.0.1");

            assertThat(apiKey.getUsageCount()).isEqualTo(3);
            assertThat(apiKey.getLastUsedIp()).isEqualTo("10.0.0.1");
        }
    }

    @Nested
    @DisplayName("ApiPermission Enum Tests")
    class ApiPermissionEnumTests {

        @Test
        @DisplayName("should have all expected permission values")
        void shouldHaveAllExpectedPermissionValues() {
            ApiKey.ApiPermission[] permissions = ApiKey.ApiPermission.values();

            assertThat(permissions).hasSize(7);
            assertThat(permissions).contains(
                    ApiKey.ApiPermission.ADMIN,
                    ApiKey.ApiPermission.READ_USER,
                    ApiKey.ApiPermission.WRITE_USER,
                    ApiKey.ApiPermission.VALIDATE_TOKEN,
                    ApiKey.ApiPermission.REVOKE_TOKEN,
                    ApiKey.ApiPermission.READ_AUDIT,
                    ApiKey.ApiPermission.MANAGE_SESSIONS
            );
        }

        @Test
        @DisplayName("should convert from string correctly")
        void shouldConvertFromStringCorrectly() {
            assertThat(ApiKey.ApiPermission.valueOf("ADMIN")).isEqualTo(ApiKey.ApiPermission.ADMIN);
            assertThat(ApiKey.ApiPermission.valueOf("READ_USER")).isEqualTo(ApiKey.ApiPermission.READ_USER);
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create ApiKey with default values")
        void shouldCreateApiKeyWithDefaultValues() {
            ApiKey key = ApiKey.builder()
                    .name("Test")
                    .keyHash("hash")
                    .keyPrefix("qc_")
                    .build();

            assertThat(key.isActive()).isTrue();
            assertThat(key.getUsageCount()).isEqualTo(0);
            assertThat(key.getPermissions()).isNotNull().isEmpty();
            assertThat(key.getIpWhitelist()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("should create ApiKey with custom values")
        void shouldCreateApiKeyWithCustomValues() {
            Set<ApiKey.ApiPermission> permissions = new HashSet<>();
            permissions.add(ApiKey.ApiPermission.READ_USER);
            permissions.add(ApiKey.ApiPermission.WRITE_USER);

            Set<String> ipWhitelist = new HashSet<>();
            ipWhitelist.add("192.168.1.1");

            ApiKey key = ApiKey.builder()
                    .name("Custom Key")
                    .keyHash("custom-hash")
                    .keyPrefix("qc_live_")
                    .active(false)
                    .permissions(permissions)
                    .ipWhitelist(ipWhitelist)
                    .rateLimitPerMinute(100)
                    .rateLimitPerHour(1000)
                    .build();

            assertThat(key.getName()).isEqualTo("Custom Key");
            assertThat(key.getKeyHash()).isEqualTo("custom-hash");
            assertThat(key.getKeyPrefix()).isEqualTo("qc_live_");
            assertThat(key.isActive()).isFalse();
            assertThat(key.getPermissions()).hasSize(2);
            assertThat(key.getIpWhitelist()).hasSize(1);
            assertThat(key.getRateLimitPerMinute()).isEqualTo(100);
            assertThat(key.getRateLimitPerHour()).isEqualTo(1000);
        }
    }
}
