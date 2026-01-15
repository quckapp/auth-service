package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.TrustedDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for TrustedDevice entity operations
 */
@Repository
public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, UUID> {

    // Find by user
    List<TrustedDevice> findByUserId(UUID userId);

    List<TrustedDevice> findByUserIdAndIsTrustedTrue(UUID userId);

    @Query("SELECT td FROM TrustedDevice td WHERE td.user.id = :userId AND td.isTrusted = true AND (td.expiresAt IS NULL OR td.expiresAt > CURRENT_TIMESTAMP)")
    List<TrustedDevice> findActiveTrustedDevicesByUserId(@Param("userId") UUID userId);

    // Find by fingerprint
    Optional<TrustedDevice> findByUserIdAndDeviceFingerprint(UUID userId, String deviceFingerprint);

    @Query("SELECT td FROM TrustedDevice td WHERE td.user.id = :userId AND td.deviceFingerprint = :fingerprint AND td.isTrusted = true AND (td.expiresAt IS NULL OR td.expiresAt > CURRENT_TIMESTAMP)")
    Optional<TrustedDevice> findValidTrustedDevice(@Param("userId") UUID userId, @Param("fingerprint") String fingerprint);

    // Check if device is trusted
    boolean existsByUserIdAndDeviceFingerprint(UUID userId, String deviceFingerprint);

    @Query("SELECT CASE WHEN COUNT(td) > 0 THEN true ELSE false END FROM TrustedDevice td " +
           "WHERE td.user.id = :userId AND td.deviceFingerprint = :fingerprint AND td.isTrusted = true " +
           "AND (td.expiresAt IS NULL OR td.expiresAt > CURRENT_TIMESTAMP)")
    boolean isDeviceTrusted(@Param("userId") UUID userId, @Param("fingerprint") String fingerprint);

    // Count trusted devices
    @Query("SELECT COUNT(td) FROM TrustedDevice td WHERE td.user.id = :userId AND td.isTrusted = true AND (td.expiresAt IS NULL OR td.expiresAt > CURRENT_TIMESTAMP)")
    int countActiveTrustedDevices(@Param("userId") UUID userId);

    // Update operations
    @Modifying
    @Query("UPDATE TrustedDevice td SET td.lastUsedAt = :now WHERE td.id = :deviceId")
    int updateLastUsed(@Param("deviceId") UUID deviceId, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE TrustedDevice td SET td.isTrusted = false WHERE td.id = :deviceId")
    int revokeTrust(@Param("deviceId") UUID deviceId);

    @Modifying
    @Query("UPDATE TrustedDevice td SET td.isTrusted = false WHERE td.user.id = :userId")
    int revokeAllTrustedDevices(@Param("userId") UUID userId);

    @Modifying
    @Query("UPDATE TrustedDevice td SET td.isTrusted = false WHERE td.user.id = :userId AND td.id != :excludeDeviceId")
    int revokeOtherTrustedDevices(@Param("userId") UUID userId, @Param("excludeDeviceId") UUID excludeDeviceId);

    // Delete operations
    @Modifying
    @Query("DELETE FROM TrustedDevice td WHERE td.user.id = :userId AND td.deviceFingerprint = :fingerprint")
    int deleteByUserIdAndFingerprint(@Param("userId") UUID userId, @Param("fingerprint") String fingerprint);

    @Modifying
    @Query("DELETE FROM TrustedDevice td WHERE td.user.id = :userId")
    int deleteAllByUserId(@Param("userId") UUID userId);

    // Cleanup expired devices
    @Query("SELECT td FROM TrustedDevice td WHERE td.expiresAt IS NOT NULL AND td.expiresAt < CURRENT_TIMESTAMP")
    List<TrustedDevice> findExpiredDevices();

    @Modifying
    @Query("DELETE FROM TrustedDevice td WHERE td.expiresAt IS NOT NULL AND td.expiresAt < :threshold")
    int deleteExpiredDevices(@Param("threshold") Instant threshold);

    @Modifying
    @Query("UPDATE TrustedDevice td SET td.isTrusted = false WHERE td.expiresAt IS NOT NULL AND td.expiresAt < CURRENT_TIMESTAMP AND td.isTrusted = true")
    int revokeExpiredDevices();

    // Statistics
    @Query("SELECT td.deviceType, COUNT(td) FROM TrustedDevice td WHERE td.isTrusted = true GROUP BY td.deviceType")
    List<Object[]> countByDeviceType();
}
