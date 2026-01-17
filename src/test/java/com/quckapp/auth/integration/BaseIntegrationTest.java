package com.quckapp.auth.integration;

import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Base class for repository integration tests using external MySQL.
 * Uses @DataJpaTest for focused JPA repository testing.
 * Connects to the MySQL instance from docker-compose (port 3308).
 *
 * Prerequisites:
 * - Run 'docker compose up -d mysql' from auth-service directory
 * - MySQL will be available on localhost:3308
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:mysql://localhost:3308/quckapp_auth?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
    "spring.datasource.username=root",
    "spring.datasource.password=root_secret",
    "spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration",
    "spring.jpa.hibernate.ddl-auto=none",
    "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect",
    "spring.jpa.properties.hibernate.type.preferred_uuid_jdbc_type=CHAR"
})
public abstract class BaseIntegrationTest {
    // Uses external MySQL from docker-compose
    // No Testcontainers - connects to already running container
}
