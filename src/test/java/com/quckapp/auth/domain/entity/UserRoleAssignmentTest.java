package com.quckapp.auth.domain.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for UserRoleAssignment entity
 */
@DisplayName("UserRoleAssignment Entity Tests")
class UserRoleAssignmentTest {

    private UserRoleAssignment assignment;

    @BeforeEach
    void setUp() {
        assignment = UserRoleAssignment.builder()
                .assignedBy(UUID.randomUUID())
                .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS))
                .isActive(true)
                .build();
    }

    @Nested
    @DisplayName("isExpired() Tests")
    class IsExpiredTests {

        @Test
        @DisplayName("should return false when expiresAt is null")
        void shouldReturnFalseWhenExpiresAtIsNull() {
            assignment.setExpiresAt(null);

            assertThat(assignment.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return false when expiration is in the future")
        void shouldReturnFalseWhenExpirationInFuture() {
            assignment.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));

            assertThat(assignment.isExpired()).isFalse();
        }

        @Test
        @DisplayName("should return true when expiration is in the past")
        void shouldReturnTrueWhenExpirationInPast() {
            assignment.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(assignment.isExpired()).isTrue();
        }

        @Test
        @DisplayName("should return true when expiration just passed")
        void shouldReturnTrueWhenExpirationJustPassed() {
            assignment.setExpiresAt(Instant.now().minus(1, ChronoUnit.SECONDS));

            assertThat(assignment.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("isValid() Tests")
    class IsValidTests {

        @Test
        @DisplayName("should return true when active and not expired")
        void shouldReturnTrueWhenActiveAndNotExpired() {
            assignment.setActive(true);
            assignment.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));

            assertThat(assignment.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return true when active and no expiration set")
        void shouldReturnTrueWhenActiveAndNoExpiration() {
            assignment.setActive(true);
            assignment.setExpiresAt(null);

            assertThat(assignment.isValid()).isTrue();
        }

        @Test
        @DisplayName("should return false when not active")
        void shouldReturnFalseWhenNotActive() {
            assignment.setActive(false);
            assignment.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));

            assertThat(assignment.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when expired")
        void shouldReturnFalseWhenExpired() {
            assignment.setActive(true);
            assignment.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(assignment.isValid()).isFalse();
        }

        @Test
        @DisplayName("should return false when both inactive and expired")
        void shouldReturnFalseWhenInactiveAndExpired() {
            assignment.setActive(false);
            assignment.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(assignment.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("should create assignment with default values")
        void shouldCreateAssignmentWithDefaultValues() {
            UserRoleAssignment newAssignment = UserRoleAssignment.builder()
                    .build();

            assertThat(newAssignment.isActive()).isTrue();
            assertThat(newAssignment.getAssignedAt()).isNotNull();
        }

        @Test
        @DisplayName("should create assignment with all fields")
        void shouldCreateAssignmentWithAllFields() {
            UUID assignerId = UUID.randomUUID();
            Instant expiry = Instant.now().plus(90, ChronoUnit.DAYS);

            UserRoleAssignment newAssignment = UserRoleAssignment.builder()
                    .assignedBy(assignerId)
                    .expiresAt(expiry)
                    .isActive(false)
                    .build();

            assertThat(newAssignment.getAssignedBy()).isEqualTo(assignerId);
            assertThat(newAssignment.getExpiresAt()).isEqualTo(expiry);
            assertThat(newAssignment.isActive()).isFalse();
        }
    }
}
