package com.quckapp.auth.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Role-Permission mapping entity
 */
@Entity
@Table(name = "role_permissions", indexes = {
    @Index(name = "idx_role_permissions_role_id", columnList = "role_id"),
    @Index(name = "idx_role_permissions_permission_id", columnList = "permission_id")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@IdClass(RolePermissionId.class)
public class RolePermission {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_id", nullable = false)
    private Permission permission;

    @Builder.Default
    @Column(updatable = false)
    private Instant grantedAt = Instant.now();

    private UUID grantedBy;
}
