package com.quckapp.auth.integration.service;

import com.quckapp.auth.service.SmsService;
import com.quckapp.auth.service.StringRedisOperations;
import com.quckapp.auth.service.TokenBlacklistService;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;

/**
 * Base class for service layer integration tests.
 * Uses @SpringBootTest to load full Spring context with all beans.
 * Connects to external MySQL from docker-compose (port 3308).
 * Mocks Redis and Kafka to avoid requiring those services.
 *
 * Prerequisites:
 * - Run 'docker compose up -d mysql' from auth-service directory
 * - MySQL will be available on localhost:3308
 */
@SpringBootTest
@TestPropertySource(properties = {
    // MySQL connection (same as repository tests)
    "spring.datasource.url=jdbc:mysql://localhost:3308/quckapp_auth?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
    "spring.datasource.username=root",
    "spring.datasource.password=root_secret",
    "spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration",
    "spring.jpa.hibernate.ddl-auto=none",
    "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect",
    "spring.jpa.properties.hibernate.type.preferred_uuid_jdbc_type=CHAR",

    // Disable Kafka auto-configuration
    "spring.kafka.bootstrap-servers=",
    "spring.kafka.consumer.group-id=test",

    // Disable OAuth2 client auto-configuration completely
    "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration",

    // JWT configuration for tests
    "jwt.secret=test-secret-key-for-integration-tests-must-be-at-least-256-bits-long-for-security-compliance",
    "jwt.access-token-expiration=900000",
    "jwt.refresh-token-expiration=604800000",
    "jwt.issuer=quckapp-auth-test",

    // Security configuration
    "security.rate-limit.enabled=false",
    "security.password.min-length=8",
    "security.password.require-uppercase=true",
    "security.password.require-lowercase=true",
    "security.password.require-digit=true",
    "security.password.require-special=false",

    // Logging
    "logging.level.com.quckapp.auth=DEBUG"
})
public abstract class BaseServiceIntegrationTest {

    // Mock Redis templates to avoid connection issues
    @MockBean
    protected RedisTemplate<String, Object> redisTemplate;

    @MockBean
    protected StringRedisTemplate stringRedisTemplate;

    // Mock Redis-dependent services
    @MockBean
    protected StringRedisOperations stringRedisOperations;

    @MockBean
    protected TokenBlacklistService tokenBlacklistService;

    // Mock Kafka to avoid connection issues
    @MockBean
    protected KafkaTemplate<String, Object> kafkaTemplate;

    // Mock SMS service (depends on Kafka)
    @MockBean
    protected SmsService smsService;

    // Mock OAuth2 ClientRegistrationRepository for SecurityConfig
    @MockBean
    protected ClientRegistrationRepository clientRegistrationRepository;
}
