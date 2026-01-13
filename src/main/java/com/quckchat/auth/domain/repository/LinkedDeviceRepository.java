package com.quckchat.auth.domain.repository;

import com.quckchat.auth.domain.entity.LinkedDevice;
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
 * Repository for LinkedDevice entity operations
 */
@Repository
public interface LinkedDeviceRepository extends JpaRepository<LinkedDevice, UUID> {

    // Find by user
    List<LinkedDevice> findByUserProfileId(UUID userId);

    // Find specific device
    Optional<LinkedDevice> findByUserProfileIdAndDeviceId(UUID userId, String deviceId);

    // Check device existence
    boolean existsByUserProfileIdAndDeviceId(UUID userId, String deviceId);

    // FCM token queries
    @Query("SELECT d.fcmToken FROM LinkedDevice d WHERE d.userProfile.id = :userId AND d.fcmToken IS NOT NULL")
    List<String> findFcmTokensByUserId(@Param("userId") UUID userId);

    @Query("SELECT d.fcmToken FROM LinkedDevice d WHERE d.userProfile.id IN :userIds AND d.fcmToken IS NOT NULL")
    List<String> findFcmTokensByUserIds(@Param("userIds") List<UUID> userIds);

    @Query("SELECT d.userProfile.id, d.fcmToken FROM LinkedDevice d " +
           "WHERE d.userProfile.id IN :userIds AND d.fcmToken IS NOT NULL")
    List<Object[]> findFcmTokensGroupedByUserIds(@Param("userIds") List<UUID> userIds);

    // Find device by FCM token
    Optional<LinkedDevice> findByFcmToken(String fcmToken);

    // Delete operations
    void deleteByUserProfileIdAndDeviceId(UUID userId, String deviceId);

    @Modifying
    @Query("DELETE FROM LinkedDevice d WHERE d.userProfile.id = :userId")
    int deleteAllByUserId(@Param("userId") UUID userId);

    // Update operations
    @Modifying
    @Query("UPDATE LinkedDevice d SET d.lastActive = :now WHERE d.userProfile.id = :userId AND d.deviceId = :deviceId")
    int updateDeviceActivity(
            @Param("userId") UUID userId,
            @Param("deviceId") String deviceId,
            @Param("now") Instant now);

    @Modifying
    @Query("UPDATE LinkedDevice d SET d.fcmToken = :fcmToken WHERE d.userProfile.id = :userId AND d.deviceId = :deviceId")
    int updateFcmToken(
            @Param("userId") UUID userId,
            @Param("deviceId") String deviceId,
            @Param("fcmToken") String fcmToken);

    @Modifying
    @Query("UPDATE LinkedDevice d SET d.fcmToken = null WHERE d.fcmToken = :fcmToken")
    int clearFcmToken(@Param("fcmToken") String fcmToken);

    // Statistics
    @Query("SELECT COUNT(d) FROM LinkedDevice d WHERE d.userProfile.id = :userId")
    int countDevicesByUserId(@Param("userId") UUID userId);

    @Query("SELECT d.deviceType, COUNT(d) FROM LinkedDevice d GROUP BY d.deviceType")
    List<Object[]> countByDeviceType();

    // Cleanup queries
    @Query("SELECT d FROM LinkedDevice d WHERE d.lastActive < :threshold")
    List<LinkedDevice> findInactiveDevices(@Param("threshold") Instant threshold);

    @Modifying
    @Query("DELETE FROM LinkedDevice d WHERE d.lastActive < :threshold")
    int deleteInactiveDevices(@Param("threshold") Instant threshold);
}
