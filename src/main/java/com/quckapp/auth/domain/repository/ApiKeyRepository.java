package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for API Key management.
 * Used for service-to-service authentication.
 */
@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    /**
     * Find API key by its hash
     */
    Optional<ApiKey> findByKeyHash(String keyHash);

    /**
     * Find API key by service name
     */
    Optional<ApiKey> findByServiceName(String serviceName);

    /**
     * Find all active API keys
     */
    List<ApiKey> findByActiveTrue();

    /**
     * Find all API keys for a specific user
     */
    List<ApiKey> findByUserId(UUID userId);

    /**
     * Find active API keys for a specific user
     */
    List<ApiKey> findByUserIdAndActiveTrue(UUID userId);

    /**
     * Check if an API key exists with the given hash
     */
    boolean existsByKeyHash(String keyHash);

    /**
     * Find API keys by prefix
     */
    List<ApiKey> findByKeyPrefixStartingWith(String prefix);

    /**
     * Count active API keys
     */
    long countByActiveTrue();

    /**
     * Find API keys that have been used recently
     */
    @Query("SELECT a FROM ApiKey a WHERE a.lastUsedAt IS NOT NULL ORDER BY a.lastUsedAt DESC")
    List<ApiKey> findRecentlyUsed();
}
