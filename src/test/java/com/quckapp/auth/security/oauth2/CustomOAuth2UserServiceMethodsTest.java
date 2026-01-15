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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomOAuth2UserService methods
 * Uses Mockito for interface mocking and reflection for private method testing
 */
@DisplayName("CustomOAuth2UserService Method Tests")
@ExtendWith(MockitoExtension.class)
class CustomOAuth2UserServiceMethodsTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private OAuthConnectionRepository oauthConnectionRepository;

    // UserEventPublisher is a class - pass null for tests that don't need it
    private UserEventPublisher userEventPublisher = null;

    private CustomOAuth2UserService service;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        service = new CustomOAuth2UserService(
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
    @DisplayName("OAuth2UserInfo Creation Tests")
    class OAuth2UserInfoTests {

        @Test
        @DisplayName("should create Google OAuth2UserInfo from attributes")
        void shouldCreateGoogleUserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-12345");
            attributes.put("email", "user@gmail.com");
            attributes.put("name", "Test User");
            attributes.put("picture", "http://example.com/pic.jpg");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("google", attributes);

            assertThat(userInfo).isInstanceOf(GoogleOAuth2UserInfo.class);
            assertThat(userInfo.getId()).isEqualTo("google-12345");
            assertThat(userInfo.getEmail()).isEqualTo("user@gmail.com");
            assertThat(userInfo.getName()).isEqualTo("Test User");
            assertThat(userInfo.getImageUrl()).isEqualTo("http://example.com/pic.jpg");
        }

        @Test
        @DisplayName("should create Facebook OAuth2UserInfo from attributes")
        void shouldCreateFacebookUserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "fb-12345");
            attributes.put("email", "user@facebook.com");
            attributes.put("name", "FB User");
            Map<String, Object> picture = new HashMap<>();
            Map<String, Object> data = new HashMap<>();
            data.put("url", "http://facebook.com/pic.jpg");
            picture.put("data", data);
            attributes.put("picture", picture);

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("facebook", attributes);

            assertThat(userInfo).isInstanceOf(FacebookOAuth2UserInfo.class);
            assertThat(userInfo.getId()).isEqualTo("fb-12345");
            assertThat(userInfo.getEmail()).isEqualTo("user@facebook.com");
        }

        @Test
        @DisplayName("should create GitHub OAuth2UserInfo from attributes")
        void shouldCreateGithubUserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", 12345);
            attributes.put("email", "user@github.com");
            attributes.put("name", "GitHub User");
            attributes.put("avatar_url", "http://github.com/avatar.png");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("github", attributes);

            assertThat(userInfo).isInstanceOf(GithubOAuth2UserInfo.class);
            assertThat(userInfo.getId()).isEqualTo("12345");
            assertThat(userInfo.getEmail()).isEqualTo("user@github.com");
        }

        @Test
        @DisplayName("should create Apple OAuth2UserInfo from attributes")
        void shouldCreateAppleUserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "apple-user-12345");
            attributes.put("email", "user@icloud.com");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("apple", attributes);

            assertThat(userInfo).isInstanceOf(AppleOAuth2UserInfo.class);
            assertThat(userInfo.getId()).isEqualTo("apple-user-12345");
            assertThat(userInfo.getEmail()).isEqualTo("user@icloud.com");
        }
    }

    @Nested
    @DisplayName("createNewUser() Tests via Reflection")
    class CreateNewUserTests {

        @Test
        @DisplayName("should create new user with OAuth2UserInfo")
        void shouldCreateNewUserFromUserInfo() throws Exception {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-12345");
            attributes.put("email", "newuser@gmail.com");
            attributes.put("name", "New User");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("google", attributes);

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser saved = invocation.getArgument(0);
                if (saved.getId() == null) {
                    // Simulate ID generation
                    return AuthUser.builder()
                            .id(UUID.randomUUID())
                            .email(saved.getEmail())
                            .externalId(saved.getExternalId())
                            .status(saved.getStatus())
                            .emailVerified(saved.isEmailVerified())
                            .build();
                }
                return saved;
            });

            Method method = CustomOAuth2UserService.class
                    .getDeclaredMethod("createNewUser", OAuth2UserInfo.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(service, userInfo);

            assertThat(result).isNotNull();
            assertThat(result.getEmail()).isEqualTo("newuser@gmail.com");
            assertThat(result.isEmailVerified()).isTrue();
            assertThat(result.getStatus()).isEqualTo(AuthUser.AuthStatus.ACTIVE);
            verify(authUserRepository).save(any(AuthUser.class));
        }
    }

    @Nested
    @DisplayName("updateOAuthConnection() Tests via Reflection")
    class UpdateOAuthConnectionTests {

        @Test
        @DisplayName("should update OAuth connection tokens")
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
                    .userNameAttributeName("sub")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "new-access-token-value",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);

            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            Method method = CustomOAuth2UserService.class
                    .getDeclaredMethod("updateOAuthConnection", OAuthConnection.class, OAuth2UserRequest.class);
            method.setAccessible(true);

            method.invoke(service, connection, userRequest);

            assertThat(connection.getAccessToken()).isEqualTo("new-access-token-value");
            assertThat(connection.getLastUsedAt()).isNotNull();
            verify(oauthConnectionRepository).save(connection);
        }
    }

    @Nested
    @DisplayName("createOAuthConnection() Tests via Reflection")
    class CreateOAuthConnectionTests {

        @Test
        @DisplayName("should create OAuth connection for user")
        void shouldCreateConnectionForUser() throws Exception {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-12345");
            attributes.put("email", "user@gmail.com");
            attributes.put("name", "Test User");
            attributes.put("picture", "http://example.com/pic.jpg");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("google", attributes);

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-client-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .userNameAttributeName("sub")
                    .scope("openid", "email", "profile")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "test-access-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);

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
                                .providerAvatarUrl(conn.getProviderAvatarUrl())
                                .accessToken(conn.getAccessToken())
                                .tokenExpiresAt(conn.getTokenExpiresAt())
                                .scopes(conn.getScopes())
                                .lastUsedAt(conn.getLastUsedAt())
                                .build();
                    });

            Method method = CustomOAuth2UserService.class
                    .getDeclaredMethod("createOAuthConnection", AuthUser.class, OAuthProvider.class,
                            String.class, OAuth2UserRequest.class, OAuth2UserInfo.class);
            method.setAccessible(true);

            method.invoke(service, testUser, OAuthProvider.GOOGLE, "google-12345", userRequest, userInfo);

            verify(oauthConnectionRepository).save(argThat(conn ->
                    conn.getUser().equals(testUser) &&
                    conn.getProvider() == OAuthProvider.GOOGLE &&
                    conn.getProviderUserId().equals("google-12345") &&
                    conn.getAccessToken().equals("test-access-token")
            ));
        }
    }

    @Nested
    @DisplayName("processOAuth2User() Tests via Reflection")
    class ProcessOAuth2UserTests {

        @Test
        @DisplayName("should return existing user when OAuth connection exists")
        void shouldReturnExistingUserWhenConnectionExists() throws Exception {
            OAuthConnection existingConnection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-12345")
                    .accessToken("old-token")
                    .build();

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-12345"))
                    .thenReturn(Optional.of(existingConnection));
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-12345");
            attributes.put("email", "test@example.com");
            attributes.put("name", "Test User");

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .userNameAttributeName("sub")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "new-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);

            DefaultOAuth2User oAuth2User = new DefaultOAuth2User(
                    Collections.emptyList(),
                    attributes,
                    "sub"
            );

            Method method = CustomOAuth2UserService.class
                    .getDeclaredMethod("processOAuth2User", OAuth2UserRequest.class, OAuth2User.class);
            method.setAccessible(true);

            OAuth2User result = (OAuth2User) method.invoke(service, userRequest, oAuth2User);

            assertThat(result).isInstanceOf(OAuth2UserPrincipal.class);
            OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
            assertThat(principal.getId()).isEqualTo(testUser.getId());

            verify(oauthConnectionRepository).findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-12345");
            verify(oauthConnectionRepository).save(existingConnection);
        }

        @Test
        @DisplayName("should link OAuth to existing user found by email")
        void shouldLinkOAuthToExistingUserByEmail() throws Exception {
            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-99999"))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail("existing@example.com"))
                    .thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-99999");
            attributes.put("email", "existing@example.com");
            attributes.put("name", "Existing User");

            ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("google")
                    .clientId("test-client-id")
                    .clientSecret("test-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                    .userNameAttributeName("sub")
                    .scope("email", "profile")
                    .build();

            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "token-value",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);

            DefaultOAuth2User oAuth2User = new DefaultOAuth2User(
                    Collections.emptyList(),
                    attributes,
                    "sub"
            );

            Method method = CustomOAuth2UserService.class
                    .getDeclaredMethod("processOAuth2User", OAuth2UserRequest.class, OAuth2User.class);
            method.setAccessible(true);

            OAuth2User result = (OAuth2User) method.invoke(service, userRequest, oAuth2User);

            assertThat(result).isInstanceOf(OAuth2UserPrincipal.class);
            OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
            assertThat(principal.isNewUser()).isFalse();

            verify(authUserRepository).findByEmail("existing@example.com");
            verify(oauthConnectionRepository).save(any(OAuthConnection.class));
        }

    }
}
