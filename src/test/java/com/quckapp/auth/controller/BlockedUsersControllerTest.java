package com.quckapp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.quckapp.auth.dto.UserProfileDtos.UserProfileSummaryDto;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.UserSettingsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for BlockedUsersController
 */
@ExtendWith(MockitoExtension.class)
class BlockedUsersControllerTest {

    @RestControllerAdvice
    static class TestExceptionHandler {
        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleIllegalArgument(IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }
    }

    @Mock
    private UserSettingsService userSettingsService;

    @Mock
    private JwtOperations jwtOperations;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final UUID TEST_USER_ID = UUID.randomUUID();
    private static final UUID BLOCKED_USER_ID = UUID.randomUUID();
    private static final String VALID_TOKEN = "valid-token";
    private static final String AUTH_HEADER = "Bearer " + VALID_TOKEN;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        BlockedUsersController controller = new BlockedUsersController(userSettingsService, jwtOperations);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new TestExceptionHandler())
                .build();
    }

    @Nested
    @DisplayName("Block User Tests")
    class BlockUserTests {

        @Test
        @DisplayName("should block user successfully")
        void shouldBlockUserSuccessfully() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            BlockedUsersController.BlockUserRequest request = new BlockedUsersController.BlockUserRequest();
            request.setUserId(BLOCKED_USER_ID);

            mockMvc.perform(post("/v1/blocked-users")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User blocked successfully"))
                    .andExpect(jsonPath("$.blockedUserId").value(BLOCKED_USER_ID.toString()));

            verify(userSettingsService).blockUser(TEST_USER_ID, BLOCKED_USER_ID);
        }

        @Test
        @DisplayName("should reject blocking self")
        void shouldRejectBlockingSelf() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            doThrow(new RuntimeException("Cannot block yourself"))
                    .when(userSettingsService).blockUser(TEST_USER_ID, TEST_USER_ID);

            BlockedUsersController.BlockUserRequest request = new BlockedUsersController.BlockUserRequest();
            request.setUserId(TEST_USER_ID);

            mockMvc.perform(post("/v1/blocked-users")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Unblock User Tests")
    class UnblockUserTests {

        @Test
        @DisplayName("should unblock user successfully")
        void shouldUnblockUserSuccessfully() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            mockMvc.perform(delete("/v1/blocked-users/{blockedUserId}", BLOCKED_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("User unblocked successfully"))
                    .andExpect(jsonPath("$.unblockedUserId").value(BLOCKED_USER_ID.toString()));

            verify(userSettingsService).unblockUser(TEST_USER_ID, BLOCKED_USER_ID);
        }
    }

    @Nested
    @DisplayName("Get Blocked Users Tests")
    class GetBlockedUsersTests {

        @Test
        @DisplayName("should get blocked users list with profiles")
        void shouldGetBlockedUsersList() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            UserProfileSummaryDto profile = UserProfileSummaryDto.builder()
                    .id(BLOCKED_USER_ID)
                    .username("blockeduser")
                    .displayName("Blocked User")
                    .build();

            when(userSettingsService.getBlockedUsers(TEST_USER_ID)).thenReturn(List.of(profile));

            mockMvc.perform(get("/v1/blocked-users")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.blockedCount").value(1))
                    .andExpect(jsonPath("$.blockedUsers[0].id").value(BLOCKED_USER_ID.toString()))
                    .andExpect(jsonPath("$.blockedUsers[0].username").value("blockeduser"));
        }

        @Test
        @DisplayName("should get blocked user IDs only")
        void shouldGetBlockedUserIdsOnly() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            UUID blockedId1 = UUID.randomUUID();
            UUID blockedId2 = UUID.randomUUID();
            when(userSettingsService.getBlockedUserIds(TEST_USER_ID))
                    .thenReturn(Set.of(blockedId1, blockedId2));

            mockMvc.perform(get("/v1/blocked-users/ids")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.blockedCount").value(2));
        }

        @Test
        @DisplayName("should get blocked users count")
        void shouldGetBlockedUsersCount() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(userSettingsService.getBlockedUserIds(TEST_USER_ID))
                    .thenReturn(Set.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()));

            mockMvc.perform(get("/v1/blocked-users/count")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.blockedCount").value(3));
        }
    }

    @Nested
    @DisplayName("Check Block Status Tests")
    class CheckBlockStatusTests {

        @Test
        @DisplayName("should check if user is blocked")
        void shouldCheckIfUserIsBlocked() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(userSettingsService.isBlocked(TEST_USER_ID, BLOCKED_USER_ID)).thenReturn(true);

            mockMvc.perform(get("/v1/blocked-users/check/{targetUserId}", BLOCKED_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.targetUserId").value(BLOCKED_USER_ID.toString()))
                    .andExpect(jsonPath("$.blocked").value(true));
        }

        @Test
        @DisplayName("should check mutual block status")
        void shouldCheckMutualBlockStatus() throws Exception {
            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(userSettingsService.isBlocked(TEST_USER_ID, BLOCKED_USER_ID)).thenReturn(true);
            when(userSettingsService.isBlocked(BLOCKED_USER_ID, TEST_USER_ID)).thenReturn(false);

            mockMvc.perform(get("/v1/blocked-users/check-mutual/{targetUserId}", BLOCKED_USER_ID)
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.targetUserId").value(BLOCKED_USER_ID.toString()))
                    .andExpect(jsonPath("$.youBlockedThem").value(true))
                    .andExpect(jsonPath("$.theyBlockedYou").value(false))
                    .andExpect(jsonPath("$.anyBlocked").value(true));
        }

        @Test
        @DisplayName("should check batch block status")
        void shouldCheckBatchBlockStatus() throws Exception {
            UUID user1 = UUID.randomUUID();
            UUID user2 = UUID.randomUUID();
            UUID user3 = UUID.randomUUID();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(userSettingsService.getBlockedUserIds(TEST_USER_ID)).thenReturn(Set.of(user1, user3));

            BlockedUsersController.BatchBlockCheckRequest request = new BlockedUsersController.BatchBlockCheckRequest();
            request.setUserIds(Set.of(user1, user2, user3));

            mockMvc.perform(post("/v1/blocked-users/check-batch")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(TEST_USER_ID.toString()))
                    .andExpect(jsonPath("$.checkedCount").value(3))
                    .andExpect(jsonPath("$.blockedCount").value(2));
        }
    }

    @Nested
    @DisplayName("Bulk Operations Tests")
    class BulkOperationsTests {

        @Test
        @DisplayName("should block multiple users")
        void shouldBlockMultipleUsers() throws Exception {
            UUID user1 = UUID.randomUUID();
            UUID user2 = UUID.randomUUID();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            BlockedUsersController.BulkBlockRequest request = new BlockedUsersController.BulkBlockRequest();
            request.setUserIds(Set.of(user1, user2));

            mockMvc.perform(post("/v1/blocked-users/block-multiple")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Bulk block operation completed"))
                    .andExpect(jsonPath("$.successCount").value(2))
                    .andExpect(jsonPath("$.failedCount").value(0));

            verify(userSettingsService).blockUser(TEST_USER_ID, user1);
            verify(userSettingsService).blockUser(TEST_USER_ID, user2);
        }

        @Test
        @DisplayName("should unblock multiple users")
        void shouldUnblockMultipleUsers() throws Exception {
            UUID user1 = UUID.randomUUID();
            UUID user2 = UUID.randomUUID();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());

            BlockedUsersController.BulkBlockRequest request = new BlockedUsersController.BulkBlockRequest();
            request.setUserIds(Set.of(user1, user2));

            mockMvc.perform(post("/v1/blocked-users/unblock-multiple")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Bulk unblock operation completed"))
                    .andExpect(jsonPath("$.successCount").value(2));

            verify(userSettingsService).unblockUser(TEST_USER_ID, user1);
            verify(userSettingsService).unblockUser(TEST_USER_ID, user2);
        }

        @Test
        @DisplayName("should unblock all users")
        void shouldUnblockAllUsers() throws Exception {
            UUID user1 = UUID.randomUUID();
            UUID user2 = UUID.randomUUID();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            when(userSettingsService.getBlockedUserIds(TEST_USER_ID)).thenReturn(Set.of(user1, user2));

            mockMvc.perform(delete("/v1/blocked-users")
                            .header("Authorization", AUTH_HEADER))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("All users unblocked"))
                    .andExpect(jsonPath("$.unblockedCount").value(2));

            verify(userSettingsService).unblockUser(TEST_USER_ID, user1);
            verify(userSettingsService).unblockUser(TEST_USER_ID, user2);
        }

        @Test
        @DisplayName("should handle partial failures in bulk operations")
        void shouldHandlePartialFailuresInBulkOperations() throws Exception {
            UUID user1 = UUID.randomUUID();
            UUID user2 = UUID.randomUUID();

            when(jwtOperations.extractUserId(VALID_TOKEN)).thenReturn(TEST_USER_ID.toString());
            doNothing().when(userSettingsService).blockUser(TEST_USER_ID, user1);
            doThrow(new RuntimeException("User not found")).when(userSettingsService).blockUser(TEST_USER_ID, user2);

            BlockedUsersController.BulkBlockRequest request = new BlockedUsersController.BulkBlockRequest();
            request.setUserIds(Set.of(user1, user2));

            mockMvc.perform(post("/v1/blocked-users/block-multiple")
                            .header("Authorization", AUTH_HEADER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.successCount").value(1))
                    .andExpect(jsonPath("$.failedCount").value(1));
        }
    }
}
