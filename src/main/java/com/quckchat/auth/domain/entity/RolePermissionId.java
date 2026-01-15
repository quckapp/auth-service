package com.quckapp.auth.domain.entity;

import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 * Composite primary key for RolePermission
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class RolePermissionId implements Serializable {
    private UUID role;
    private UUID permission;
}
