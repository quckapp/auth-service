package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.PhoneOtp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PhoneOtpRepository extends JpaRepository<PhoneOtp, UUID> {

    /**
     * Find the latest valid (not expired, not verified) OTP for a phone number
     */
    @Query("SELECT o FROM PhoneOtp o WHERE o.phoneNumber = :phoneNumber " +
           "AND o.verified = false AND o.expiresAt > :now " +
           "ORDER BY o.createdAt DESC LIMIT 1")
    Optional<PhoneOtp> findLatestValidOtp(
        @Param("phoneNumber") String phoneNumber,
        @Param("now") Instant now
    );

    /**
     * Count OTPs requested for a phone number within a time window
     */
    @Query("SELECT COUNT(o) FROM PhoneOtp o WHERE o.phoneNumber = :phoneNumber " +
           "AND o.createdAt > :since")
    long countOtpRequestsSince(
        @Param("phoneNumber") String phoneNumber,
        @Param("since") Instant since
    );

    /**
     * Count OTPs requested from an IP address within a time window
     */
    @Query("SELECT COUNT(o) FROM PhoneOtp o WHERE o.ipAddress = :ipAddress " +
           "AND o.createdAt > :since")
    long countOtpRequestsFromIpSince(
        @Param("ipAddress") String ipAddress,
        @Param("since") Instant since
    );

    /**
     * Find all expired OTPs for cleanup
     */
    List<PhoneOtp> findByExpiresAtBefore(Instant expiredBefore);

    /**
     * Delete expired OTPs older than a certain time
     */
    @Modifying
    @Query("DELETE FROM PhoneOtp o WHERE o.expiresAt < :expiredBefore")
    int deleteExpiredOtps(@Param("expiredBefore") Instant expiredBefore);

    /**
     * Invalidate all pending OTPs for a phone number (when a new one is requested)
     */
    @Modifying
    @Query("UPDATE PhoneOtp o SET o.verified = true WHERE o.phoneNumber = :phoneNumber " +
           "AND o.verified = false")
    int invalidatePendingOtps(@Param("phoneNumber") String phoneNumber);
}
