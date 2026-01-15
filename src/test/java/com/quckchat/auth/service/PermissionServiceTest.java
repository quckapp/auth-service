package com.quckapp.auth.service;

import com.quckapp.auth.domain.entity.Permission;
import com.quckapp.auth.domain.entity.RolePermission;
import com.quckapp.auth.domain.repository.PermissionRepository;
import com.quckapp.auth.dto.RbacDtos.CreatePermissionRequest;
import com.quckapp.auth.dto.RbacDtos.PermissionDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PermissionService
 */
@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    @Mock
    private PermissionRepository permissionRepository;

    private PermissionService permissionService;

    private UUID testPermissionId;
    private Permission testPermission;

    @BeforeEach
    void setUp() {
        permissionService = new PermissionService(permissionRepository);

        testPermissionId = UUID.randomUUID();
        testPermission = Permission.builder()
                .id(testPermissionId)
                .name("users:read")
                .description("Read user information")
                .resource("users")
                .action("read")
                .isActive(true)
                .rolePermissions(new HashSet<>())
                .build();
    }

    @Nested
    @DisplayName("Create Permission Tests")
    class CreatePermissionTests {

        @Test
        @DisplayName("should create permission successfully")
        void shouldCreatePermissionSuccessfully() {
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name("posts:create")
                    .description("Create posts")
                    .resource("posts")
                    .action("create")
                    .build();

            when(permissionRepository.existsByName("posts:create")).thenReturn(false);
            when(permissionRepository.findByResourceAndAction("posts", "create")).thenReturn(Optional.empty());
            when(permissionRepository.save(any(Permission.class))).thenAnswer(invocation -> {
                Permission permission = invocation.getArgument(0);
                permission.setId(UUID.randomUUID());
                return permission;
            });

            PermissionDto result = permissionService.createPermission(request);

            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("posts:create");
            assertThat(result.getResource()).isEqualTo("posts");
            assertThat(result.getAction()).isEqualTo("create");

            ArgumentCaptor<Permission> permissionCaptor = ArgumentCaptor.forClass(Permission.class);
            verify(permissionRepository).save(permissionCaptor.capture());
            assertThat(permissionCaptor.getValue().isActive()).isTrue();
        }

        @Test
        @DisplayName("should throw exception when permission name already exists")
        void shouldThrowWhenPermissionNameExists() {
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name("users:read")
                    .description("Read users")
                    .resource("users")
                    .action("read")
                    .build();

            when(permissionRepository.existsByName("users:read")).thenReturn(true);

            assertThatThrownBy(() -> permissionService.createPermission(request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission already exists");

            verify(permissionRepository, never()).save(any());
        }

        @Test
        @DisplayName("should throw exception when resource:action combination exists")
        void shouldThrowWhenResourceActionCombinationExists() {
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name("user-read-perm")
                    .description("Read users")
                    .resource("users")
                    .action("read")
                    .build();

            when(permissionRepository.existsByName("user-read-perm")).thenReturn(false);
            when(permissionRepository.findByResourceAndAction("users", "read"))
                    .thenReturn(Optional.of(testPermission));

            assertThatThrownBy(() -> permissionService.createPermission(request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission for resource:action already exists");

            verify(permissionRepository, never()).save(any());
        }

        @Test
        @DisplayName("should lowercase name, resource, and action")
        void shouldLowercaseNameResourceAndAction() {
            CreatePermissionRequest request = CreatePermissionRequest.builder()
                    .name("POSTS:DELETE")
                    .description("Delete posts")
                    .resource("POSTS")
                    .action("DELETE")
                    .build();

            when(permissionRepository.existsByName("POSTS:DELETE")).thenReturn(false);
            when(permissionRepository.findByResourceAndAction("POSTS", "DELETE")).thenReturn(Optional.empty());
            when(permissionRepository.save(any(Permission.class))).thenAnswer(invocation -> {
                Permission permission = invocation.getArgument(0);
                permission.setId(UUID.randomUUID());
                return permission;
            });

            permissionService.createPermission(request);

            ArgumentCaptor<Permission> permissionCaptor = ArgumentCaptor.forClass(Permission.class);
            verify(permissionRepository).save(permissionCaptor.capture());
            assertThat(permissionCaptor.getValue().getName()).isEqualTo("posts:delete");
            assertThat(permissionCaptor.getValue().getResource()).isEqualTo("posts");
            assertThat(permissionCaptor.getValue().getAction()).isEqualTo("delete");
        }
    }

    @Nested
    @DisplayName("Get Permission Tests")
    class GetPermissionTests {

        @Test
        @DisplayName("should get permission by ID")
        void shouldGetPermissionById() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));

            PermissionDto result = permissionService.getPermission(testPermissionId);

            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(testPermissionId);
            assertThat(result.getName()).isEqualTo("users:read");
        }

        @Test
        @DisplayName("should throw exception when permission not found by ID")
        void shouldThrowWhenPermissionNotFoundById() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> permissionService.getPermission(testPermissionId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission not found");
        }

        @Test
        @DisplayName("should get permission by name")
        void shouldGetPermissionByName() {
            when(permissionRepository.findByName("users:read")).thenReturn(Optional.of(testPermission));

            Optional<PermissionDto> result = permissionService.getPermissionByName("users:read");

            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("users:read");
        }

        @Test
        @DisplayName("should get permission by name with case insensitivity")
        void shouldGetPermissionByNameCaseInsensitive() {
            when(permissionRepository.findByName("users:read")).thenReturn(Optional.of(testPermission));

            Optional<PermissionDto> result = permissionService.getPermissionByName("USERS:READ");

            assertThat(result).isPresent();
            verify(permissionRepository).findByName("users:read");
        }

        @Test
        @DisplayName("should get permission by resource and action")
        void shouldGetPermissionByResourceAndAction() {
            when(permissionRepository.findByResourceAndAction("users", "read"))
                    .thenReturn(Optional.of(testPermission));

            Optional<PermissionDto> result = permissionService.getPermissionByResourceAndAction("users", "read");

            assertThat(result).isPresent();
            assertThat(result.get().getResource()).isEqualTo("users");
            assertThat(result.get().getAction()).isEqualTo("read");
        }

        @Test
        @DisplayName("should get permission by resource and action case insensitive")
        void shouldGetPermissionByResourceAndActionCaseInsensitive() {
            when(permissionRepository.findByResourceAndAction("users", "read"))
                    .thenReturn(Optional.of(testPermission));

            Optional<PermissionDto> result = permissionService.getPermissionByResourceAndAction("USERS", "READ");

            assertThat(result).isPresent();
            verify(permissionRepository).findByResourceAndAction("users", "read");
        }
    }

    @Nested
    @DisplayName("Get All Permissions Tests")
    class GetAllPermissionsTests {

        @Test
        @DisplayName("should get all permissions")
        void shouldGetAllPermissions() {
            Permission permission2 = Permission.builder()
                    .id(UUID.randomUUID())
                    .name("posts:write")
                    .resource("posts")
                    .action("write")
                    .isActive(true)
                    .rolePermissions(new HashSet<>())
                    .build();

            when(permissionRepository.findAll()).thenReturn(Arrays.asList(testPermission, permission2));

            List<PermissionDto> result = permissionService.getAllPermissions();

            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("should get active permissions only")
        void shouldGetActivePermissionsOnly() {
            when(permissionRepository.findByIsActiveTrue()).thenReturn(Collections.singletonList(testPermission));

            List<PermissionDto> result = permissionService.getActivePermissions();

            assertThat(result).hasSize(1);
            assertThat(result.get(0).isActive()).isTrue();
        }

        @Test
        @DisplayName("should get permissions by resource")
        void shouldGetPermissionsByResource() {
            Permission permission2 = Permission.builder()
                    .id(UUID.randomUUID())
                    .name("users:write")
                    .resource("users")
                    .action("write")
                    .isActive(true)
                    .rolePermissions(new HashSet<>())
                    .build();

            when(permissionRepository.findByResource("users"))
                    .thenReturn(Arrays.asList(testPermission, permission2));

            List<PermissionDto> result = permissionService.getPermissionsByResource("users");

            assertThat(result).hasSize(2);
            assertThat(result).allMatch(p -> p.getResource().equals("users"));
        }

        @Test
        @DisplayName("should get permissions by resource case insensitive")
        void shouldGetPermissionsByResourceCaseInsensitive() {
            when(permissionRepository.findByResource("users"))
                    .thenReturn(Collections.singletonList(testPermission));

            permissionService.getPermissionsByResource("USERS");

            verify(permissionRepository).findByResource("users");
        }

        @Test
        @DisplayName("should get permissions by role ID")
        void shouldGetPermissionsByRoleId() {
            UUID roleId = UUID.randomUUID();
            when(permissionRepository.findByRoleId(roleId)).thenReturn(Collections.singletonList(testPermission));

            List<PermissionDto> result = permissionService.getPermissionsByRoleId(roleId);

            assertThat(result).hasSize(1);
        }

        @Test
        @DisplayName("should get all resources")
        void shouldGetAllResources() {
            when(permissionRepository.findAllResources()).thenReturn(Arrays.asList("users", "posts", "comments"));

            List<String> result = permissionService.getAllResources();

            assertThat(result).containsExactly("users", "posts", "comments");
        }
    }

    @Nested
    @DisplayName("Update Permission Tests")
    class UpdatePermissionTests {

        @Test
        @DisplayName("should update permission description")
        void shouldUpdatePermissionDescription() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));
            when(permissionRepository.save(any(Permission.class))).thenReturn(testPermission);

            PermissionDto result = permissionService.updatePermission(testPermissionId, "Updated description", null);

            assertThat(result).isNotNull();
            assertThat(testPermission.getDescription()).isEqualTo("Updated description");
            verify(permissionRepository).save(testPermission);
        }

        @Test
        @DisplayName("should update permission active status")
        void shouldUpdatePermissionActiveStatus() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));
            when(permissionRepository.save(any(Permission.class))).thenReturn(testPermission);

            permissionService.updatePermission(testPermissionId, null, false);

            assertThat(testPermission.isActive()).isFalse();
            verify(permissionRepository).save(testPermission);
        }

        @Test
        @DisplayName("should update both description and active status")
        void shouldUpdateBothDescriptionAndActiveStatus() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));
            when(permissionRepository.save(any(Permission.class))).thenReturn(testPermission);

            permissionService.updatePermission(testPermissionId, "New description", false);

            assertThat(testPermission.getDescription()).isEqualTo("New description");
            assertThat(testPermission.isActive()).isFalse();
        }

        @Test
        @DisplayName("should throw when permission not found for update")
        void shouldThrowWhenPermissionNotFoundForUpdate() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> permissionService.updatePermission(testPermissionId, "New description", null))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission not found");

            verify(permissionRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Delete Permission Tests")
    class DeletePermissionTests {

        @Test
        @DisplayName("should delete permission successfully")
        void shouldDeletePermissionSuccessfully() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));

            permissionService.deletePermission(testPermissionId);

            verify(permissionRepository).delete(testPermission);
        }

        @Test
        @DisplayName("should throw when permission not found for delete")
        void shouldThrowWhenPermissionNotFoundForDelete() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> permissionService.deletePermission(testPermissionId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission not found");

            verify(permissionRepository, never()).delete(any());
        }

        @Test
        @DisplayName("should throw when permission is assigned to roles")
        void shouldThrowWhenPermissionIsAssignedToRoles() {
            RolePermission rolePermission = new RolePermission();
            testPermission.getRolePermissions().add(rolePermission);
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));

            assertThatThrownBy(() -> permissionService.deletePermission(testPermissionId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Cannot delete permission that is assigned to roles");

            verify(permissionRepository, never()).delete(any());
        }
    }

    @Nested
    @DisplayName("Deactivate Permission Tests")
    class DeactivatePermissionTests {

        @Test
        @DisplayName("should deactivate permission")
        void shouldDeactivatePermission() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.of(testPermission));

            permissionService.deactivatePermission(testPermissionId);

            assertThat(testPermission.isActive()).isFalse();
            verify(permissionRepository).save(testPermission);
        }

        @Test
        @DisplayName("should throw when permission not found for deactivation")
        void shouldThrowWhenPermissionNotFoundForDeactivation() {
            when(permissionRepository.findById(testPermissionId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> permissionService.deactivatePermission(testPermissionId))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Permission not found");

            verify(permissionRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Bulk Operations Tests")
    class BulkOperationsTests {

        @Test
        @DisplayName("should create multiple permissions")
        void shouldCreateMultiplePermissions() {
            List<CreatePermissionRequest> requests = Arrays.asList(
                    CreatePermissionRequest.builder()
                            .name("posts:create")
                            .description("Create posts")
                            .resource("posts")
                            .action("create")
                            .build(),
                    CreatePermissionRequest.builder()
                            .name("posts:delete")
                            .description("Delete posts")
                            .resource("posts")
                            .action("delete")
                            .build()
            );

            when(permissionRepository.existsByName(anyString())).thenReturn(false);
            when(permissionRepository.findByResourceAndAction(anyString(), anyString())).thenReturn(Optional.empty());
            when(permissionRepository.save(any(Permission.class))).thenAnswer(invocation -> {
                Permission permission = invocation.getArgument(0);
                permission.setId(UUID.randomUUID());
                return permission;
            });

            List<PermissionDto> result = permissionService.createPermissions(requests);

            assertThat(result).hasSize(2);
            verify(permissionRepository, times(2)).save(any(Permission.class));
        }
    }
}
