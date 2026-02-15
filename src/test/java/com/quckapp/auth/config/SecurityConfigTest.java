package com.quckapp.auth.config;

import com.quckapp.auth.security.jwt.JwtAuthenticationFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SecurityConfig
 */
@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new SecurityConfig(jwtAuthenticationFilter);
    }

    @Nested
    @DisplayName("Password Encoder Bean Tests")
    class PasswordEncoderBeanTests {

        @Test
        @DisplayName("should create BCryptPasswordEncoder bean")
        void shouldCreateBCryptPasswordEncoderBean() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();

            assertThat(passwordEncoder).isNotNull();
            assertThat(passwordEncoder).isInstanceOf(BCryptPasswordEncoder.class);
        }

        @Test
        @DisplayName("should encode password correctly")
        void shouldEncodePasswordCorrectly() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();
            String rawPassword = "testPassword123";

            String encodedPassword = passwordEncoder.encode(rawPassword);

            assertThat(encodedPassword).isNotNull();
            assertThat(encodedPassword).isNotEqualTo(rawPassword);
            assertThat(passwordEncoder.matches(rawPassword, encodedPassword)).isTrue();
        }

        @Test
        @DisplayName("should not match incorrect password")
        void shouldNotMatchIncorrectPassword() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();
            String rawPassword = "testPassword123";
            String wrongPassword = "wrongPassword";

            String encodedPassword = passwordEncoder.encode(rawPassword);

            assertThat(passwordEncoder.matches(wrongPassword, encodedPassword)).isFalse();
        }

        @Test
        @DisplayName("should generate different hashes for same password")
        void shouldGenerateDifferentHashesForSamePassword() {
            PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();
            String rawPassword = "testPassword123";

            String encodedPassword1 = passwordEncoder.encode(rawPassword);
            String encodedPassword2 = passwordEncoder.encode(rawPassword);

            // BCrypt generates different hashes due to random salt
            assertThat(encodedPassword1).isNotEqualTo(encodedPassword2);
            // But both should match the original password
            assertThat(passwordEncoder.matches(rawPassword, encodedPassword1)).isTrue();
            assertThat(passwordEncoder.matches(rawPassword, encodedPassword2)).isTrue();
        }
    }

    @Nested
    @DisplayName("Security Config Construction Tests")
    class SecurityConfigConstructionTests {

        @Test
        @DisplayName("should construct SecurityConfig with all dependencies")
        void shouldConstructSecurityConfigWithAllDependencies() {
            assertThat(securityConfig).isNotNull();
        }
    }
}
