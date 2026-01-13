package com.quckchat.auth.service;

import com.quckchat.auth.domain.entity.*;
import com.quckchat.auth.domain.repository.*;
import com.quckchat.auth.dto.UserProfileDtos.*;
import com.quckchat.auth.kafka.UserEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for user profile management operations
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserProfileService {

    private final UserProfileRepository profileRepository;
    private final UserSettingsRepository settingsRepository;
    private final LinkedDeviceRepository deviceRepository;
    private final UserEventPublisher eventPublisher;

    // ==================== Profile CRUD ====================

    public UserProfileDto createProfile(AuthUser authUser, CreateProfileRequest request) {
        log.info("Creating profile for auth user: {}", authUser.getId());

        // Validate uniqueness
        validateProfileUniqueness(request.getPhoneNumber(), request.getUsername(), request.getEmail(), null);

        // Create profile
        UserProfile profile = UserProfile.builder()
                .authUser(authUser)
                .phoneNumber(request.getPhoneNumber())
                .username(request.getUsername())
                .displayName(request.getDisplayName())
                .email(request.getEmail())
                .avatar(request.getAvatar())
                .bio(request.getBio())
                .publicKey(request.getPublicKey())
                .status(UserStatus.OFFLINE)
                .lastSeen(Instant.now())
                .isActive(true)
                .isVerified(false)
                .role(UserRole.USER)
                .permissions(new HashSet<>())
                .isBanned(false)
                .build();

        profile = profileRepository.save(profile);

        // Create default settings
        UserSettings settings = UserSettings.createDefault(profile);
        settingsRepository.save(settings);
        profile.setSettings(settings);

        // Publish event
        eventPublisher.publishProfileCreated(profile);

        log.info("Profile created successfully: {}", profile.getId());
        return UserProfileDto.from(profile);
    }

    @Transactional(readOnly = true)
    public UserProfileDto getProfile(UUID userId) {
        UserProfile profile = findProfileOrThrow(userId);
        return UserProfileDto.from(profile);
    }

    @Transactional(readOnly = true)
    public UserProfileDto getProfileByExternalId(String externalId) {
        UserProfile profile = profileRepository.findByExternalId(externalId)
                .orElseThrow(() -> new RuntimeException("Profile not found for external ID: " + externalId));
        return UserProfileDto.from(profile);
    }

    public UserProfileDto updateProfile(UUID userId, UpdateProfileRequest request) {
        log.info("Updating profile: {}", userId);
        UserProfile profile = findProfileOrThrow(userId);

        // Validate uniqueness (excluding current user)
        String newPhone = request.getUsername() != null ? null : profile.getPhoneNumber(); // Phone can't be changed
        validateProfileUniqueness(newPhone, request.getUsername(), request.getEmail(), userId);

        // Update fields
        if (request.getUsername() != null) {
            profile.setUsername(request.getUsername());
        }
        if (request.getDisplayName() != null) {
            profile.setDisplayName(request.getDisplayName());
        }
        if (request.getEmail() != null) {
            profile.setEmail(request.getEmail());
        }
        if (request.getAvatar() != null) {
            profile.setAvatar(request.getAvatar());
        }
        if (request.getBio() != null) {
            profile.setBio(request.getBio());
        }
        if (request.getPublicKey() != null) {
            profile.setPublicKey(request.getPublicKey());
        }

        profile = profileRepository.save(profile);

        // Publish event
        eventPublisher.publishProfileUpdated(profile);

        log.info("Profile updated successfully: {}", userId);
        return UserProfileDto.from(profile);
    }

    public void deleteProfile(UUID userId) {
        log.info("Deleting profile: {}", userId);
        UserProfile profile = findProfileOrThrow(userId);

        // Publish event before deletion
        eventPublisher.publishProfileDeleted(profile);

        profileRepository.delete(profile);
        log.info("Profile deleted successfully: {}", userId);
    }

    // ==================== Profile Lookups ====================

    @Transactional(readOnly = true)
    public Optional<UserProfileDto> findByPhoneNumber(String phoneNumber) {
        return profileRepository.findByPhoneNumber(phoneNumber)
                .map(UserProfileDto::from);
    }

    @Transactional(readOnly = true)
    public Optional<UserProfileDto> findByUsername(String username) {
        return profileRepository.findByUsername(username)
                .map(UserProfileDto::from);
    }

    @Transactional(readOnly = true)
    public Optional<UserProfileDto> findByEmail(String email) {
        return profileRepository.findByEmail(email)
                .map(UserProfileDto::from);
    }

    @Transactional(readOnly = true)
    public List<UserProfileDto> getUsersByIds(List<UUID> ids) {
        return profileRepository.findByIdIn(ids).stream()
                .map(UserProfileDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<UserProfileDto> getUsersByExternalIds(List<String> externalIds) {
        return profileRepository.findByExternalIdIn(externalIds).stream()
                .map(UserProfileDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Page<UserProfileSummaryDto> searchUsers(String query, UUID excludeUserId, Pageable pageable) {
        return profileRepository.searchUsers(query, excludeUserId, pageable)
                .map(UserProfileSummaryDto::from);
    }

    // ==================== Status Management ====================

    public void updateStatus(UUID userId, UserStatus status) {
        log.debug("Updating status for user {}: {}", userId, status);
        int updated = profileRepository.updateStatus(userId, status, Instant.now());
        if (updated == 0) {
            throw new RuntimeException("Profile not found: " + userId);
        }

        // Publish event
        eventPublisher.publishStatusChanged(userId, status);
    }

    public void updateLastSeen(UUID userId) {
        profileRepository.updateLastSeen(userId, Instant.now());
    }

    // ==================== Admin Operations ====================

    public void banUser(UUID userId, UUID bannedBy, String reason) {
        log.info("Banning user {}: {}", userId, reason);
        UserProfile profile = findProfileOrThrow(userId);

        profile.ban(bannedBy, reason);
        profileRepository.save(profile);

        // Publish event
        eventPublisher.publishUserBanned(profile, bannedBy, reason);

        log.info("User banned successfully: {}", userId);
    }

    public void unbanUser(UUID userId) {
        log.info("Unbanning user: {}", userId);
        int updated = profileRepository.unbanUser(userId);
        if (updated == 0) {
            throw new RuntimeException("Profile not found: " + userId);
        }

        // Publish event
        eventPublisher.publishUserUnbanned(userId);

        log.info("User unbanned successfully: {}", userId);
    }

    public void updateRole(UUID userId, UserRole role) {
        log.info("Updating role for user {}: {}", userId, role);
        int updated = profileRepository.updateRole(userId, role);
        if (updated == 0) {
            throw new RuntimeException("Profile not found: " + userId);
        }

        // Publish event
        eventPublisher.publishRoleChanged(userId, role);

        log.info("Role updated successfully for user: {}", userId);
    }

    public void updatePermissions(UUID userId, Set<String> permissions) {
        log.info("Updating permissions for user {}: {}", userId, permissions);
        UserProfile profile = findProfileOrThrow(userId);

        profile.setPermissions(permissions);
        profileRepository.save(profile);

        log.info("Permissions updated successfully for user: {}", userId);
    }

    public void verifyUser(UUID userId) {
        log.info("Verifying user: {}", userId);
        profileRepository.updateVerificationStatus(userId, true);
    }

    // ==================== Statistics ====================

    @Transactional(readOnly = true)
    public UserStatisticsDto getStatistics() {
        long total = profileRepository.count();
        long active = profileRepository.countActiveUsers();
        long online = profileRepository.countOnlineUsers();
        long banned = profileRepository.countBannedUsers();

        Map<String, Long> byRole = profileRepository.countByRole().stream()
                .collect(Collectors.toMap(
                        arr -> ((UserRole) arr[0]).name(),
                        arr -> (Long) arr[1]
                ));

        return UserStatisticsDto.builder()
                .totalUsers(total)
                .activeUsers(active)
                .onlineUsers(online)
                .bannedUsers(banned)
                .usersByRole(byRole)
                .build();
    }

    // ==================== Helper Methods ====================

    private UserProfile findProfileOrThrow(UUID userId) {
        return profileRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found: " + userId));
    }

    private void validateProfileUniqueness(String phoneNumber, String username, String email, UUID excludeUserId) {
        if (phoneNumber != null) {
            profileRepository.findByPhoneNumber(phoneNumber)
                    .filter(p -> excludeUserId == null || !p.getId().equals(excludeUserId))
                    .ifPresent(p -> {
                        throw new RuntimeException("Phone number already exists");
                    });
        }

        if (username != null) {
            profileRepository.findByUsername(username)
                    .filter(p -> excludeUserId == null || !p.getId().equals(excludeUserId))
                    .ifPresent(p -> {
                        throw new RuntimeException("Username already exists");
                    });
        }

        if (email != null) {
            profileRepository.findByEmail(email)
                    .filter(p -> excludeUserId == null || !p.getId().equals(excludeUserId))
                    .ifPresent(p -> {
                        throw new RuntimeException("Email already exists");
                    });
        }
    }
}
