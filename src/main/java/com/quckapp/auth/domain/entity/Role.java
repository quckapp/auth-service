package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Role Entity - Defines roles for RBAC
 */
@Entity
@Table(name = "roles", indexes = {
    @Index(name = "idx_roles_name", columnList = "name"),
    @Index(name = "idx_roles_is_active", columnList = "isActive")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(length = 255)
    private String description;

    @Builder.Default
    private boolean isSystemRole = false;

    @Builder.Default
    private boolean isActive = true;

    @Builder.Default
    private int priority = 0;

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<RolePermission> rolePermissions = new HashSet<>();

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<UserRoleAssignment> userRoles = new HashSet<>();

    @CreatedDate
    @Column(updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;

    // Helper methods
    public void addPermission(Permission permission, UUID grantedBy) {
        RolePermission rolePermission = RolePermission.builder()
            .role(this)
            .permission(permission)
            .grantedBy(grantedBy)
            .build();
        rolePermissions.add(rolePermission);
    }

    public void removePermission(Permission permission) {
        rolePermissions.removeIf(rp -> rp.getPermission().equals(permission));
    }

    public boolean hasPermission(String permissionName) {
        return rolePermissions.stream()
            .anyMatch(rp -> rp.getPermission().getName().equals(permissionName));
    }
}
