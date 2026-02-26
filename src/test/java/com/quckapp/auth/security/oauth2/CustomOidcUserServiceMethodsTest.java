package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.OAuthConnection;
import com.quckapp.auth.domain.entity.OAuthConnection.OAuthProvider;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.OAuthConnectionRepository;
import com.quckapp.auth.kafka.UserEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomOidcUserService methods
 * Uses Mockito for interface mocking and reflection for private method testing
 */
@DisplayName("CustomOidcUserService Method Tests")
@ExtendWith(MockitoExtension.class)
class CustomOidcUserServiceMethodsTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private OAuthConnectionRepository oauthConnectionRepository;

    // UserEventPublisher is a class - pass null for tests that don't need it
    private UserEventPublisher userEventPublisher = null;

    private CustomOidcUserService service;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        service = new CustomOidcUserService(
            authUserRepository,
            oauthConnectionRepository,
            userEventPublisher
        );

        testUser = AuthUser.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();
    }

    @Nested
    @DisplayName("createNewUser() Tests via Reflection")
    class CreateNewUserTests {

        @Test
        @DisplayName("should create new user with email and name")
        void shouldCreateNewUserWithEmailAndName() throws Exception {
            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser saved = invocation.getArgument(0);
                return AuthUser.builder()
                        .id(UUID.randomUUID())
                        .email(saved.getEmail())
                        .externalId(saved.getExternalId())
                        .status(saved.getStatus())
                        .emailVerified(saved.isEmailVerified())
                        .build();
            });

            Method method = CustomOidcUserService.class
                    .getDeclaredMethod("createNewUser", String.class, String.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(service, "newuser@gmail.com", "New User");

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo("newuser@gmail.com");
            assertThat(result.isEmailVerified()).isTrue();
            assertThat(result.getStatus()).isEqualTo(AuthUser.AuthStatus.ACTIVE);
            verify(authUserRepository).save(any(AuthUser.class));
        }

        @Test
        @DisplayName("should create user even with null name")
        void shouldCreateUserWithNullName() throws Exception {
            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser saved = invocation.getArgument(0);
                return AuthUser.builder()
                        .id(UUID.randomUUID())
                        .email(saved.getEmail())
                        .externalId(saved.getExternalId())
                        .status(saved.getStatus())
                        .emailVerified(saved.isEmailVerified())
                        .build();
            });

            Method method = CustomOidcUserService.class
                    .getDeclaredMethod("createNewUser", String.class, String.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(service, "user@example.com", null);

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo("user@example.com");
            verify(authUserRepository).save(any(AuthUser.class));
        }
    }

    @Nested
    @DisplayName("updateOAuthConnection() Tests via Reflection")
    class UpdateOAuthConnectionTests {

        @Test
        @DisplayName("should update OIDC connection tokens")
        void shouldUpdateConnectionTokens() throws Exception {
            OAuthConnection connection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-12345")
                    .accessToken("old-token")
                    .build();

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-client-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .jwkSetUri("https://www.googleapis.com/oauth2/v1/certs")
                    .userNameAttributeName("sub")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "new-oidc-token-value",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "google-12345");
            claims.put("email", "test@gmail.com");

            OidcIdToken idToken = new OidcIdToken(
                    "id-token-value",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    claims
            );

            OidcUserRequest userRequest = new OidcUserRequest(clientRegistration, accessToken, idToken);

            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            Method method = CustomOidcUserService.class
                    .getDeclaredMethod("updateOAuthConnection", OAuthConnection.class, OidcUserRequest.class);
            method.setAccessible(true);

            method.invoke(service, connection, userRequest);

            assertThat(connection.getAccessToken()).isEqualTo("new-oidc-token-value");
            assertThat(connection.getLastUsedAt()).isNotNull();
            verify(oauthConnectionRepository).save(connection);
        }
    }

    @Nested
    @DisplayName("createOAuthConnection() Tests via Reflection")
    class CreateOAuthConnectionTests {

        @Test
        @DisplayName("should create OIDC connection for user")
        void shouldCreateOidcConnectionForUser() throws Exception {
            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-client-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .jwkSetUri("https://www.googleapis.com/oauth2/v1/certs")
                    .userNameAttributeName("sub")
                    .scope("openid", "email", "profile")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "oidc-access-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "google-12345");
            claims.put("email", "user@gmail.com");
            claims.put("name", "Test User");
            claims.put("picture", "http://example.com/pic.jpg");

            OidcIdToken idToken = new OidcIdToken(
                    "id-token-value",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    claims
            );

            OidcUserRequest userRequest = new OidcUserRequest(clientRegistration, accessToken, idToken);

            DefaultOidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(invocation -> {
                        OAuthConnection conn = invocation.getArgument(0);
                        return OAuthConnection.builder()
                                .id(UUID.randomUUID())
                                .user(conn.getUser())
                                .provider(conn.getProvider())
                                .providerUserId(conn.getProviderUserId())
                                .providerEmail(conn.getProviderEmail())
                                .providerName(conn.getProviderName())
                                .accessToken(conn.getAccessToken())
                                .build();
                    });

            Method method = CustomOidcUserService.class
                    .getDeclaredMethod("createOAuthConnection", AuthUser.class, OAuthProvider.class,
                            String.class, OidcUserRequest.class, OidcUser.class);
            method.setAccessible(true);

            method.invoke(service, testUser, OAuthProvider.GOOGLE, "google-12345", userRequest, oidcUser);

            verify(oauthConnectionRepository).save(argThat(conn ->
                    conn.getUser().equals(testUser) &&
                    conn.getProvider() == OAuthProvider.GOOGLE &&
                    conn.getProviderUserId().equals("google-12345") &&
                    conn.getAccessToken().equals("oidc-access-token")
            ));
        }
    }

    @Nested
    @DisplayName("processOidcUser() Tests via Reflection")
    class ProcessOidcUserTests {

        @Test
        @DisplayName("should return existing user when OAuth connection exists")
        void shouldReturnExistingUserWhenConnectionExists() throws Exception {
            OAuthConnection existingConnection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-oidc-12345")
                    .accessToken("old-token")
                    .build();

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-oidc-12345"))
                    .thenReturn(Optional.of(existingConnection));
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .jwkSetUri("https://www.googleapis.com/oauth2/v1/certs")
                    .userNameAttributeName("sub")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "new-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "google-oidc-12345");
            claims.put("email", "test@example.com");
            claims.put("name", "Test User");

            OidcIdToken idToken = new OidcIdToken(
                    "id-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    claims
            );

            OidcUserRequest userRequest = new OidcUserRequest(clientRegistration, accessToken, idToken);
            DefaultOidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

            Method method = CustomOidcUserService.class
                    .getDeclaredMethod("processOidcUser", OidcUserRequest.class, OidcUser.class);
            method.setAccessible(true);

            OidcUser result = (OidcUser) method.invoke(service, userRequest, oidcUser);

            assertThat(result).isInstanceOf(CustomOidcUser.class);
            CustomOidcUser customOidcUser = (CustomOidcUser) result;
            assertThat(customOidcUser.getAuthUser()).isEqualTo(testUser);
            assertThat(customOidcUser.isNewUser()).isFalse();

            verify(oauthConnectionRepository).findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-oidc-12345");
        }

        @Test
        @DisplayName("should link OIDC to existing user found by email")
        void shouldLinkOidcToExistingUserByEmail() throws Exception {
            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-new-user"))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail("existing@example.com"))
                    .thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .jwkSetUri("https://www.googleapis.com/oauth2/v1/certs")
                    .userNameAttributeName("sub")
                    .scope("email", "profile")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "token-value",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "google-new-user");
            claims.put("email", "existing@example.com");
            claims.put("name", "Existing User");

            OidcIdToken idToken = new OidcIdToken(
                    "id-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    claims
            );

            OidcUserRequest userRequest = new OidcUserRequest(clientRegistration, accessToken, idToken);
            DefaultOidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

            Method method = CustomOidcUserService.class
                    .getDeclaredMethod("processOidcUser", OidcUserRequest.class, OidcUser.class);
            method.setAccessible(true);

            OidcUser result = (OidcUser) method.invoke(service, userRequest, oidcUser);

            assertThat(result).isInstanceOf(CustomOidcUser.class);
            CustomOidcUser customOidcUser = (CustomOidcUser) result;
            assertThat(customOidcUser.isNewUser()).isFalse();

            verify(authUserRepository).findByEmail("existing@example.com");
            verify(oauthConnectionRepository).save(any(OAuthConnection.class));
        }

    }

    @Nested
    @DisplayName("CustomOidcUser Tests")
    class CustomOidcUserTests {

        @Test
        @DisplayName("should create CustomOidcUser with user and oidc data")
        void shouldCreateCustomOidcUser() {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "google-12345");
            claims.put("email", "test@gmail.com");
            claims.put("name", "Test User");

            OidcIdToken idToken = new OidcIdToken(
                    "id-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    claims
            );

            DefaultOidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, true);

            assertThat(customOidcUser.getAuthUser()).isEqualTo(testUser);
            assertThat(customOidcUser.isNewUser()).isTrue();
            assertThat(customOidcUser.getEmail()).isEqualTo("test@gmail.com");
            assertThat(customOidcUser.getSubject()).isEqualTo("google-12345");
        }

        @Test
        @DisplayName("should return existing user flag correctly")
        void shouldReturnExistingUserFlag() {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "google-12345");
            claims.put("email", "test@gmail.com");

            OidcIdToken idToken = new OidcIdToken(
                    "id-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    claims
            );

            DefaultOidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
            CustomOidcUser existingOidcUser = new CustomOidcUser(testUser, oidcUser, false);

            assertThat(existingOidcUser.isNewUser()).isFalse();
        }
    }
}
