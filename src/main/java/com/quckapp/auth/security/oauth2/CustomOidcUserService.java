package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.OAuthConnection;
import com.quckapp.auth.domain.entity.OAuthConnection.OAuthProvider;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.OAuthConnectionRepository;
import com.quckapp.auth.kafka.UserEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Custom OIDC User Service for OpenID Connect providers (Google, Apple)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final AuthUserRepository authUserRepository;
    private final OAuthConnectionRepository oauthConnectionRepository;
    private final UserEventPublisher userEventPublisher;

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("Processing OIDC login for provider: {}", registrationId);

        try {
            return processOidcUser(userRequest, oidcUser);
        } catch (Exception ex) {
            log.error("OIDC processing error: {}", ex.getMessage(), ex);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("processing_error", ex.getMessage(), null)
            );
        }
    }

    private OidcUser processOidcUser(OidcUserRequest userRequest, OidcUser oidcUser) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        String email = oidcUser.getEmail();
        String providerUserId = oidcUser.getSubject();
        String name = oidcUser.getFullName();
        String picture = oidcUser.getPicture();

        if (email == null || email.isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_not_found", "Email not found from OIDC provider", null)
            );
        }

        OAuthProvider provider = OAuthProvider.valueOf(registrationId.toUpperCase());

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

            log.info("Existing OIDC user logged in: {}", user.getEmail());

        } else {
            // No existing connection - check if user exists by email
            Optional<AuthUser> existingUser = authUserRepository.findByEmail(email);

            if (existingUser.isPresent()) {
                // User exists but no OAuth connection - link the account
                user = existingUser.get();
                createOAuthConnection(user, provider, providerUserId, userRequest, oidcUser);

                log.info("Linked OIDC provider {} to existing user: {}", registrationId, user.getEmail());

            } else {
                // New user - create account and OAuth connection
                user = createNewUser(email, name);
                createOAuthConnection(user, provider, providerUserId, userRequest, oidcUser);
                isNewUser = true;

                // Publish event
                userEventPublisher.publishUserRegistered(user);

                log.info("Created new user via OIDC: {}", user.getEmail());
            }
        }

        // Update last login
        user.setLastLoginAt(Instant.now());
        authUserRepository.save(user);

        return new CustomOidcUser(user, oidcUser, isNewUser);
    }

    private AuthUser createNewUser(String email, String name) {
        AuthUser user = AuthUser.builder()
                .email(email)
                .externalId(UUID.randomUUID().toString())
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true) // OIDC emails are pre-verified
                .build();

        return authUserRepository.save(user);
    }

    private void createOAuthConnection(AuthUser user, OAuthProvider provider, String providerUserId,
                                       OidcUserRequest userRequest, OidcUser oidcUser) {
        OAuthConnection connection = OAuthConnection.builder()
                .user(user)
                .provider(provider)
                .providerUserId(providerUserId)
                .providerEmail(oidcUser.getEmail())
                .providerName(oidcUser.getFullName())
                .providerAvatarUrl(oidcUser.getPicture())
                .scopes(String.join(",", userRequest.getClientRegistration().getScopes()))
                .accessToken(userRequest.getAccessToken().getTokenValue())
                .tokenExpiresAt(userRequest.getAccessToken().getExpiresAt())
                .lastUsedAt(Instant.now())
                .build();

        oauthConnectionRepository.save(connection);
    }

    private void updateOAuthConnection(OAuthConnection connection, OidcUserRequest userRequest) {
        connection.setAccessToken(userRequest.getAccessToken().getTokenValue());
        connection.setTokenExpiresAt(userRequest.getAccessToken().getExpiresAt());
        connection.setLastUsedAt(Instant.now());

        oauthConnectionRepository.save(connection);
    }
}
