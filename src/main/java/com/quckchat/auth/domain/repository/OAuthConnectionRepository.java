package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.OAuthConnection;
import com.quckapp.auth.domain.entity.OAuthConnection.OAuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OAuthConnectionRepository extends JpaRepository<OAuthConnection, UUID> {

    Optional<OAuthConnection> findByProviderAndProviderUserId(OAuthProvider provider, String providerUserId);

    List<OAuthConnection> findByUserId(UUID userId);

    Optional<OAuthConnection> findByUserIdAndProvider(UUID userId, OAuthProvider provider);

    boolean existsByUserIdAndProvider(UUID userId, OAuthProvider provider);

    boolean existsByProviderAndProviderUserId(OAuthProvider provider, String providerUserId);

    @Modifying
    @Query("DELETE FROM OAuthConnection oc WHERE oc.user.id = :userId AND oc.provider = :provider")
    int deleteByUserIdAndProvider(@Param("userId") UUID userId, @Param("provider") OAuthProvider provider);

    @Query("SELECT oc.provider FROM OAuthConnection oc WHERE oc.user.id = :userId")
    List<OAuthProvider> findProvidersByUserId(@Param("userId") UUID userId);

    @Query("SELECT COUNT(oc) FROM OAuthConnection oc WHERE oc.user.id = :userId")
    int countByUserId(@Param("userId") UUID userId);
}
