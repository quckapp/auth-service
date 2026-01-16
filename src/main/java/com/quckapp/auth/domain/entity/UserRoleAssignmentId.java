package com.quckapp.auth.domain.entity;

import lombok.*;

import java.io.Serializable;
import java.util.UUID;

/**
 * Composite primary key for UserRoleAssignment
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class UserRoleAssignmentId implements Serializable {
    private UUID user;
    private UUID role;
}
