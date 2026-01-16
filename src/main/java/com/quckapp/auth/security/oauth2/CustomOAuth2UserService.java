package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.OAuthConnection;
import com.quckapp.auth.domain.entity.OAuthConnection.OAuthProvider;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.OAuthConnectionRepository;
import com.quckapp.auth.kafka.UserEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Custom OAuth2 User Service that handles user creation and linking
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final AuthUserRepository authUserRepository;
    private final OAuthConnectionRepository oauthConnectionRepository;
    private final UserEventPublisher userEventPublisher;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("Processing OAuth2 login for provider: {}", registrationId);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (Exception ex) {
            log.error("OAuth2 processing error: {}", ex.getMessage(), ex);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("processing_error", ex.getMessage(), null)
            );
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo userInfo = OAuth2UserInfo.create(registrationId, oAuth2User.getAttributes());

        if (userInfo.getEmail() == null || userInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_not_found", "Email not found from OAuth2 provider", null)
            );
        }

        OAuthProvider provider = OAuthProvider.valueOf(registrationId.toUpperCase());
        String providerUserId = userInfo.getId();

        // Check if OAuth connection exists
        Optional<OAuthConnection> existingConnection = oauthConnectionRepository
                .findByProviderAndProviderUserId(provider, providerUserId);

        AuthUser user;
        boolean isNewUser = false;

        if (existingConnection.isPresent()) {
            // Existing OAuth connection - update tokens and return user
            OAuthConnection connection = existingConnection.get();
            user = connection.getUser();

            // Update OAuth tokens
            updateOAuthConnection(connection, userRequest);

            log.info("Existing OAuth user logged in: {}", user.getEmail());

        } else {
            // No existing connection - check if user exists by email
            Optional<AuthUser> existingUser = authUserRepository.findByEmail(userInfo.getEmail());

            if (existingUser.isPresent()) {
                // User exists but no OAuth connection - link the account
                user = existingUser.get();
                createOAuthConnection(user, provider, providerUserId, userRequest, userInfo);

                log.info("Linked OAuth provider {} to existing user: {}", registrationId, user.getEmail());

            } else {
                // New user - create account and OAuth connection
                user = createNewUser(userInfo);
                createOAuthConnection(user, provider, providerUserId, userRequest, userInfo);
                isNewUser = true;

                // Publish event
                userEventPublisher.publishUserRegistered(user);

                log.info("Created new user via OAuth: {}", user.getEmail());
            }
        }

        // Update last login
        user.setLastLoginAt(Instant.now());
        authUserRepository.save(user);

        return OAuth2UserPrincipal.create(user, oAuth2User.getAttributes(), isNewUser);
    }

    private AuthUser createNewUser(OAuth2UserInfo userInfo) {
        AuthUser user = AuthUser.builder()
                .email(userInfo.getEmail())
                .externalId(UUID.randomUUID().toString())
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true) // OAuth emails are pre-verified
                .build();

        return authUserRepository.save(user);
    }

    private void createOAuthConnection(AuthUser user, OAuthProvider provider, String providerUserId,
                                       OAuth2UserRequest userRequest, OAuth2UserInfo userInfo) {
        OAuthConnection connection = OAuthConnection.builder()
                .user(user)
                .provider(provider)
                .providerUserId(providerUserId)
                .providerEmail(userInfo.getEmail())
                .providerName(userInfo.getName())
                .providerAvatarUrl(userInfo.getImageUrl())
                .scopes(String.join(",", userRequest.getClientRegistration().getScopes()))
                .accessToken(userRequest.getAccessToken().getTokenValue())
                .tokenExpiresAt(userRequest.getAccessToken().getExpiresAt())
                .lastUsedAt(Instant.now())
                .build();

        oauthConnectionRepository.save(connection);
    }

    private void updateOAuthConnection(OAuthConnection connection, OAuth2UserRequest userRequest) {
        connection.setAccessToken(userRequest.getAccessToken().getTokenValue());
        connection.setTokenExpiresAt(userRequest.getAccessToken().getExpiresAt());
        connection.setLastUsedAt(Instant.now());

        oauthConnectionRepository.save(connection);
    }
}
