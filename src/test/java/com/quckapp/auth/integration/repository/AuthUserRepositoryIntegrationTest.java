package com.quckapp.auth.integration.repository;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.integration.BaseIntegrationTest;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for AuthUserRepository using MySQL Testcontainer.
 * Tests actual database operations including:
 * - CRUD operations
 * - Custom queries
 * - UUID handling
 * - Constraints validation
 */
@DisplayName("AuthUserRepository MySQL Integration Tests")
class AuthUserRepositoryIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private AuthUserRepository authUserRepository;

    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        // Clean up before each test
        authUserRepository.deleteAll();

        testUser = AuthUser.builder()
                .email("test@example.com")
                .passwordHash("$2a$10$hashedpassword")
                .externalId("ext-" + UUID.randomUUID())
                .status(AuthUser.AuthStatus.ACTIVE)
                .twoFactorEnabled(false)
                .emailVerified(true)
                .build();
    }

    @AfterEach
    void tearDown() {
        authUserRepository.deleteAll();
    }

    @Nested
    @DisplayName("Create operations")
    class CreateOperations {

        @Test
        @DisplayName("Should save user and generate UUID")
        void shouldSaveUserAndGenerateUuid() {
            // When
            AuthUser savedUser = authUserRepository.save(testUser);

            // Then
            assertThat(savedUser.getId()).isNotNull();
            assertThat(savedUser.getEmail()).isEqualTo("test@example.com");
            assertThat(savedUser.getCreatedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should save user with all fields")
        void shouldSaveUserWithAllFields() {
            // Given
            testUser.setTwoFactorEnabled(true);
            testUser.setTwoFactorSecret("JBSWY3DPEHPK3PXP");
            testUser.setLastLoginAt(Instant.now());
            testUser.setLastLoginIp("192.168.1.1");
            testUser.setFailedLoginAttempts(3);

            // When
            AuthUser savedUser = authUserRepository.save(testUser);

            // Then
            AuthUser foundUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(foundUser.isTwoFactorEnabled()).isTrue();
            assertThat(foundUser.getTwoFactorSecret()).isEqualTo("JBSWY3DPEHPK3PXP");
            assertThat(foundUser.getLastLoginAt()).isNotNull();
            assertThat(foundUser.getLastLoginIp()).isEqualTo("192.168.1.1");
            assertThat(foundUser.getFailedLoginAttempts()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should persist OAuth-only user without password")
        void shouldPersistOAuthOnlyUser() {
            // Given
            testUser.setPasswordHash(null);

            // When
            AuthUser savedUser = authUserRepository.save(testUser);

            // Then
            AuthUser foundUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(foundUser.getPasswordHash()).isNull();
            assertThat(foundUser.getEmail()).isEqualTo("test@example.com");
        }
    }

    @Nested
    @DisplayName("Read operations")
    class ReadOperations {

        @Test
        @DisplayName("Should find user by ID")
        void shouldFindUserById() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // When
            Optional<AuthUser> foundUser = authUserRepository.findById(savedUser.getId());

            // Then
            assertThat(foundUser).isPresent();
            assertThat(foundUser.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("Should find user by email")
        void shouldFindUserByEmail() {
            // Given
            authUserRepository.save(testUser);

            // When
            Optional<AuthUser> foundUser = authUserRepository.findByEmail("test@example.com");

            // Then
            assertThat(foundUser).isPresent();
            assertThat(foundUser.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("Should find user by email case insensitive")
        @Transactional
        void shouldFindUserByEmailCaseInsensitive() {
            // Given
            authUserRepository.save(testUser);

            // When - MySQL is case-insensitive by default for VARCHAR
            Optional<AuthUser> foundUser = authUserRepository.findByEmail("TEST@EXAMPLE.COM");

            // Then
            assertThat(foundUser).isPresent();
        }

        @Test
        @DisplayName("Should find user by external ID")
        void shouldFindUserByExternalId() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // When
            Optional<AuthUser> foundUser = authUserRepository.findByExternalId(testUser.getExternalId());

            // Then
            assertThat(foundUser).isPresent();
            assertThat(foundUser.get().getId()).isEqualTo(savedUser.getId());
        }

        @Test
        @DisplayName("Should return empty when user not found by email")
        void shouldReturnEmptyWhenNotFoundByEmail() {
            // When
            Optional<AuthUser> foundUser = authUserRepository.findByEmail("nonexistent@example.com");

            // Then
            assertThat(foundUser).isEmpty();
        }
    }

    @Nested
    @DisplayName("Update operations")
    class UpdateOperations {

        @Test
        @DisplayName("Should update user email")
        void shouldUpdateUserEmail() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // When
            savedUser.setEmail("updated@example.com");
            authUserRepository.save(savedUser);

            // Then
            AuthUser foundUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(foundUser.getEmail()).isEqualTo("updated@example.com");
            assertThat(foundUser.getUpdatedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should update password hash")
        void shouldUpdatePasswordHash() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);
            String newHash = "$2a$10$newhash";

            // When
            savedUser.setPasswordHash(newHash);
            savedUser.setPasswordChangedAt(Instant.now());
            authUserRepository.save(savedUser);

            // Then
            AuthUser foundUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(foundUser.getPasswordHash()).isEqualTo(newHash);
            assertThat(foundUser.getPasswordChangedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should update failed login attempts")
        void shouldUpdateFailedLoginAttempts() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // When
            savedUser.incrementFailedAttempts();
            savedUser.incrementFailedAttempts();
            authUserRepository.save(savedUser);

            // Then
            AuthUser foundUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(foundUser.getFailedLoginAttempts()).isEqualTo(2);
        }

        @Test
        @DisplayName("Should lock and unlock account")
        void shouldLockAndUnlockAccount() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);
            Instant lockTime = Instant.now().plusSeconds(3600);

            // When - Lock account
            savedUser.setLockedUntil(lockTime);
            authUserRepository.save(savedUser);

            // Then
            AuthUser lockedUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(lockedUser.isLocked()).isTrue();

            // When - Unlock account
            lockedUser.resetFailedAttempts();
            authUserRepository.save(lockedUser);

            // Then
            AuthUser unlockedUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(unlockedUser.isLocked()).isFalse();
            assertThat(unlockedUser.getFailedLoginAttempts()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should update 2FA settings")
        void shouldUpdate2FASettings() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // When
            savedUser.setTwoFactorEnabled(true);
            savedUser.setTwoFactorSecret("NEWTOTP3SECRET");
            authUserRepository.save(savedUser);

            // Then
            AuthUser foundUser = authUserRepository.findById(savedUser.getId()).orElseThrow();
            assertThat(foundUser.isTwoFactorEnabled()).isTrue();
            assertThat(foundUser.getTwoFactorSecret()).isEqualTo("NEWTOTP3SECRET");
        }
    }

    @Nested
    @DisplayName("Delete operations")
    class DeleteOperations {

        @Test
        @DisplayName("Should delete user by ID")
        void shouldDeleteUserById() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);
            UUID userId = savedUser.getId();

            // When
            authUserRepository.deleteById(userId);

            // Then
            assertThat(authUserRepository.findById(userId)).isEmpty();
        }

        @Test
        @DisplayName("Should delete user entity")
        void shouldDeleteUserEntity() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // When
            authUserRepository.delete(savedUser);

            // Then
            assertThat(authUserRepository.findById(savedUser.getId())).isEmpty();
        }
    }

    @Nested
    @DisplayName("Existence checks")
    class ExistenceChecks {

        @Test
        @DisplayName("Should check if email exists")
        void shouldCheckIfEmailExists() {
            // Given
            authUserRepository.save(testUser);

            // When/Then
            assertThat(authUserRepository.existsByEmail("test@example.com")).isTrue();
            assertThat(authUserRepository.existsByEmail("nonexistent@example.com")).isFalse();
        }

        @Test
        @DisplayName("Should check if external ID exists")
        void shouldCheckIfExternalIdExists() {
            // Given
            authUserRepository.save(testUser);

            // When/Then
            assertThat(authUserRepository.existsByExternalId(testUser.getExternalId())).isTrue();
            assertThat(authUserRepository.existsByExternalId("nonexistent-ext-id")).isFalse();
        }
    }

    @Nested
    @DisplayName("Status operations")
    class StatusOperations {

        @Test
        @DisplayName("Should save and retrieve different statuses")
        void shouldSaveAndRetrieveDifferentStatuses() {
            // Test ACTIVE
            testUser.setStatus(AuthUser.AuthStatus.ACTIVE);
            AuthUser activeUser = authUserRepository.save(testUser);
            assertThat(authUserRepository.findById(activeUser.getId()).get().getStatus())
                    .isEqualTo(AuthUser.AuthStatus.ACTIVE);

            // Test INACTIVE
            activeUser.setStatus(AuthUser.AuthStatus.INACTIVE);
            authUserRepository.save(activeUser);
            assertThat(authUserRepository.findById(activeUser.getId()).get().getStatus())
                    .isEqualTo(AuthUser.AuthStatus.INACTIVE);

            // Test SUSPENDED
            activeUser.setStatus(AuthUser.AuthStatus.SUSPENDED);
            authUserRepository.save(activeUser);
            assertThat(authUserRepository.findById(activeUser.getId()).get().getStatus())
                    .isEqualTo(AuthUser.AuthStatus.SUSPENDED);

            // Test PENDING_VERIFICATION
            activeUser.setStatus(AuthUser.AuthStatus.PENDING_VERIFICATION);
            authUserRepository.save(activeUser);
            assertThat(authUserRepository.findById(activeUser.getId()).get().getStatus())
                    .isEqualTo(AuthUser.AuthStatus.PENDING_VERIFICATION);
        }

        @Test
        @DisplayName("Should correctly determine if user is active")
        void shouldCorrectlyDetermineIfUserIsActive() {
            // Given
            AuthUser savedUser = authUserRepository.save(testUser);

            // Active user (not locked)
            assertThat(savedUser.isActive()).isTrue();

            // Locked user
            savedUser.setLockedUntil(Instant.now().plusSeconds(3600));
            assertThat(savedUser.isActive()).isFalse();

            // Unlocked but suspended
            savedUser.setLockedUntil(null);
            savedUser.setStatus(AuthUser.AuthStatus.SUSPENDED);
            assertThat(savedUser.isActive()).isFalse();
        }
    }

    @Nested
    @DisplayName("Multiple users operations")
    class MultipleUsersOperations {

        @Test
        @DisplayName("Should handle multiple users")
        void shouldHandleMultipleUsers() {
            // Given
            AuthUser user1 = AuthUser.builder()
                    .email("user1@example.com")
                    .passwordHash("hash1")
                    .externalId("ext-1")
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .build();

            AuthUser user2 = AuthUser.builder()
                    .email("user2@example.com")
                    .passwordHash("hash2")
                    .externalId("ext-2")
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .build();

            AuthUser user3 = AuthUser.builder()
                    .email("user3@example.com")
                    .passwordHash("hash3")
                    .externalId("ext-3")
                    .status(AuthUser.AuthStatus.INACTIVE)
                    .build();

            // When
            authUserRepository.save(user1);
            authUserRepository.save(user2);
            authUserRepository.save(user3);

            // Then
            assertThat(authUserRepository.count()).isEqualTo(3);
            assertThat(authUserRepository.findByEmail("user1@example.com")).isPresent();
            assertThat(authUserRepository.findByEmail("user2@example.com")).isPresent();
            assertThat(authUserRepository.findByEmail("user3@example.com")).isPresent();
        }

        @Test
        @DisplayName("Should find all users")
        void shouldFindAllUsers() {
            // Given
            for (int i = 0; i < 5; i++) {
                AuthUser user = AuthUser.builder()
                        .email("user" + i + "@example.com")
                        .passwordHash("hash" + i)
                        .externalId("ext-" + i)
                        .status(AuthUser.AuthStatus.ACTIVE)
                        .build();
                authUserRepository.save(user);
            }

            // When/Then
            assertThat(authUserRepository.findAll()).hasSize(5);
        }
    }
}
