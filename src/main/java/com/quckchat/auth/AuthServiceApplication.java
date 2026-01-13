package com.quckchat.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * QuckChat Auth Service - Spring Boot Application
 *
 * Full Security Suite:
 * - JWT + OAuth2 Authentication
 * - 2FA (TOTP)
 * - Session Management
 * - Rate Limiting
 * - API Keys
 * - IP Whitelist
 * - Audit Logging
 * - Data Encryption
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableAsync
@EnableScheduling
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
