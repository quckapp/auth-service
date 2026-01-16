package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser, UUID> {

    Optional<AuthUser> findByEmail(String email);

    Optional<AuthUser> findByExternalId(String externalId);

    boolean existsByEmail(String email);

    boolean existsByExternalId(String externalId);
}
