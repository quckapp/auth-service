package com.quckapp.auth.domain.repository;

import com.quckapp.auth.domain.entity.EmailOtp;
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
public interface EmailOtpRepository extends JpaRepository<EmailOtp, UUID> {

    /**
     * Find the latest valid (not expired, not verified) OTP for an email
     */
    @Query("SELECT o FROM EmailOtp o WHERE o.email = :email " +
           "AND o.verified = false AND o.expiresAt > :now " +
           "ORDER BY o.createdAt DESC LIMIT 1")
    Optional<EmailOtp> findLatestValidOtp(
        @Param("email") String email,
        @Param("now") Instant now
    );

    /**
     * Count OTPs requested for an email within a time window
     */
    @Query("SELECT COUNT(o) FROM EmailOtp o WHERE o.email = :email " +
           "AND o.createdAt > :since")
    long countOtpRequestsSince(
        @Param("email") String email,
        @Param("since") Instant since
    );

    /**
     * Count OTPs requested from an IP address within a time window
     */
    @Query("SELECT COUNT(o) FROM EmailOtp o WHERE o.ipAddress = :ipAddress " +
           "AND o.createdAt > :since")
    long countOtpRequestsFromIpSince(
        @Param("ipAddress") String ipAddress,
        @Param("since") Instant since
    );

    /**
     * Find all expired OTPs for cleanup
     */
    List<EmailOtp> findByExpiresAtBefore(Instant expiredBefore);

    /**
     * Delete expired OTPs older than a certain time
     */
    @Modifying
    @Query("DELETE FROM EmailOtp o WHERE o.expiresAt < :expiredBefore")
    int deleteExpiredOtps(@Param("expiredBefore") Instant expiredBefore);

    /**
     * Invalidate all pending OTPs for an email (when a new one is requested)
     */
    @Modifying
    @Query("UPDATE EmailOtp o SET o.verified = true WHERE o.email = :email " +
           "AND o.verified = false")
    int invalidatePendingOtps(@Param("email") String email);
}
