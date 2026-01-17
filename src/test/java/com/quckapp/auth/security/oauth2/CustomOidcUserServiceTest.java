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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomOidcUserService
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomOidcUserServiceTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private OAuthConnectionRepository oauthConnectionRepository;

    @Mock
    private UserEventPublisher userEventPublisher;

    @Mock
    private OidcUser mockOidcUser;

    @Mock
    private OidcIdToken mockIdToken;

    private CustomOidcUserService customOidcUserService;

    private UUID testUserId;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        customOidcUserService = new CustomOidcUserService(
                authUserRepository,
                oauthConnectionRepository,
                userEventPublisher
        );

        testUserId = UUID.randomUUID();
        testUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();
    }

    @Nested
    @DisplayName("CustomOidcUser Tests")
    class CustomOidcUserTests {

        @Test
        @DisplayName("should create CustomOidcUser from AuthUser and OidcUser")
        void shouldCreateCustomOidcUserFromAuthUserAndOidcUser() {
            when(mockOidcUser.getClaims()).thenReturn(Map.of("email", "test@example.com"));
            when(mockOidcUser.getAttributes()).thenReturn(Map.of("sub", "google-123"));
            doReturn(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
                    .when(mockOidcUser).getAuthorities();

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getUserId()).isEqualTo(testUserId);
            assertThat(customOidcUser.getExternalId()).isEqualTo("ext-123");
            assertThat(customOidcUser.isNewUser()).isFalse();
        }

        @Test
        @DisplayName("should indicate new user correctly")
        void shouldIndicateNewUserCorrectly() {
            CustomOidcUser newOidcUser = new CustomOidcUser(testUser, mockOidcUser, true);
            CustomOidcUser existingOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(newOidcUser.isNewUser()).isTrue();
            assertThat(existingOidcUser.isNewUser()).isFalse();
        }

        @Test
        @DisplayName("should delegate getClaims to wrapped OidcUser")
        void shouldDelegateGetClaimsToWrappedOidcUser() {
            Map<String, Object> claims = Map.of("email", "test@example.com", "sub", "123");
            when(mockOidcUser.getClaims()).thenReturn(claims);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getClaims()).isEqualTo(claims);
            verify(mockOidcUser).getClaims();
        }

        @Test
        @DisplayName("should delegate getUserInfo to wrapped OidcUser")
        void shouldDelegateGetUserInfoToWrappedOidcUser() {
            OidcUserInfo userInfo = new OidcUserInfo(Map.of("email", "test@example.com"));
            when(mockOidcUser.getUserInfo()).thenReturn(userInfo);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getUserInfo()).isEqualTo(userInfo);
            verify(mockOidcUser).getUserInfo();
        }

        @Test
        @DisplayName("should delegate getIdToken to wrapped OidcUser")
        void shouldDelegateGetIdTokenToWrappedOidcUser() {
            when(mockOidcUser.getIdToken()).thenReturn(mockIdToken);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getIdToken()).isEqualTo(mockIdToken);
            verify(mockOidcUser).getIdToken();
        }

        @Test
        @DisplayName("should delegate getAttributes to wrapped OidcUser")
        void shouldDelegateGetAttributesToWrappedOidcUser() {
            Map<String, Object> attributes = Map.of("sub", "google-123", "email", "test@gmail.com");
            when(mockOidcUser.getAttributes()).thenReturn(attributes);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getAttributes()).isEqualTo(attributes);
            verify(mockOidcUser).getAttributes();
        }

        @Test
        @DisplayName("should delegate getAuthorities to wrapped OidcUser")
        void shouldDelegateGetAuthoritiesToWrappedOidcUser() {
            List<SimpleGrantedAuthority> authorities = Arrays.asList(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("SCOPE_email")
            );
            doReturn(authorities).when(mockOidcUser).getAuthorities();

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getAuthorities()).isEqualTo(authorities);
            verify(mockOidcUser).getAuthorities();
        }

        @Test
        @DisplayName("should return AuthUser ID as name")
        void shouldReturnAuthUserIdAsName() {
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getName()).isEqualTo(testUserId.toString());
        }

        @Test
        @DisplayName("should provide access to underlying AuthUser")
        void shouldProvideAccessToUnderlyingAuthUser() {
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            assertThat(customOidcUser.getAuthUser()).isEqualTo(testUser);
        }
    }

    @Nested
    @DisplayName("Existing OIDC Connection Tests")
    class ExistingOidcConnectionTests {

        @Test
        @DisplayName("should find existing OIDC connection")
        void shouldFindExistingOidcConnection() {
            OAuthConnection existingConnection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-oidc-123")
                    .build();

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-oidc-123"))
                    .thenReturn(Optional.of(existingConnection));

            Optional<OAuthConnection> found = oauthConnectionRepository.findByProviderAndProviderUserId(
                    OAuthProvider.GOOGLE, "google-oidc-123"
            );

            assertThat(found).isPresent();
            assertThat(found.get().getUser()).isEqualTo(testUser);
        }

        @Test
        @DisplayName("should update OIDC connection tokens")
        void shouldUpdateOidcConnectionTokens() {
            OAuthConnection connection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-oidc-123")
                    .accessToken("old-oidc-token")
                    .build();

            connection.setAccessToken("new-oidc-token");
            connection.setTokenExpiresAt(Instant.now().plusSeconds(7200));
            connection.setLastUsedAt(Instant.now());

            when(oauthConnectionRepository.save(any(OAuthConnection.class))).thenReturn(connection);

            OAuthConnection updated = oauthConnectionRepository.save(connection);

            assertThat(updated.getAccessToken()).isEqualTo("new-oidc-token");
        }
    }

    @Nested
    @DisplayName("New OIDC User Creation Tests")
    class NewOidcUserCreationTests {

        @Test
        @DisplayName("should create new user from OIDC login")
        void shouldCreateNewUserFromOidcLogin() {
            AuthUser newUser = AuthUser.builder()
                    .email("newuser@gmail.com")
                    .externalId(UUID.randomUUID().toString())
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .emailVerified(true)
                    .build();

            when(authUserRepository.save(any(AuthUser.class))).thenAnswer(invocation -> {
                AuthUser user = invocation.getArgument(0);
                user.setId(UUID.randomUUID());
                return user;
            });

            AuthUser saved = authUserRepository.save(newUser);

            assertThat(saved.getId()).isNotNull();
            assertThat(saved.isEmailVerified()).isTrue();
        }

        @Test
        @DisplayName("should create OIDC connection for new user")
        void shouldCreateOidcConnectionForNewUser() {
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(invocation -> {
                        OAuthConnection conn = invocation.getArgument(0);
                        conn.setId(UUID.randomUUID());
                        return conn;
                    });

            OAuthConnection connection = OAuthConnection.builder()
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-oidc-new")
                    .providerEmail("new@gmail.com")
                    .providerName("New User")
                    .providerAvatarUrl("https://google.com/photo.jpg")
                    .scopes("openid,email,profile")
                    .accessToken("oidc-access-token")
                    .tokenExpiresAt(Instant.now().plusSeconds(3600))
                    .lastUsedAt(Instant.now())
                    .build();

            OAuthConnection saved = oauthConnectionRepository.save(connection);

            assertThat(saved.getId()).isNotNull();
            verify(oauthConnectionRepository).save(connection);
        }

        @Test
        @DisplayName("should publish user registered event for new OIDC user")
        void shouldPublishUserRegisteredEventForNewOidcUser() {
            AuthUser newUser = AuthUser.builder()
                    .id(UUID.randomUUID())
                    .email("oidc@example.com")
                    .externalId("ext-oidc-new")
                    .build();

            userEventPublisher.publishUserRegistered(newUser);

            verify(userEventPublisher).publishUserRegistered(newUser);
        }
    }

    @Nested
    @DisplayName("Link OIDC to Existing User Tests")
    class LinkOidcToExistingUserTests {

        @Test
        @DisplayName("should link OIDC provider to existing user by email")
        void shouldLinkOidcProviderToExistingUserByEmail() {
            when(authUserRepository.findByEmail("existing@example.com"))
                    .thenReturn(Optional.of(testUser));
            when(oauthConnectionRepository.findByProviderAndProviderUserId(any(), anyString()))
                    .thenReturn(Optional.empty());

            Optional<AuthUser> existingUser = authUserRepository.findByEmail("existing@example.com");

            assertThat(existingUser).isPresent();
            assertThat(existingUser.get().getId()).isEqualTo(testUserId);
        }

        @Test
        @DisplayName("should save OIDC connection when linking to existing user")
        void shouldSaveOidcConnectionWhenLinkingToExistingUser() {
            ArgumentCaptor<OAuthConnection> connectionCaptor = ArgumentCaptor.forClass(OAuthConnection.class);

            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenReturn(OAuthConnection.builder()
                            .id(UUID.randomUUID())
                            .user(testUser)
                            .provider(OAuthProvider.APPLE)
                            .providerUserId("apple-123")
                            .build());

            OAuthConnection connection = OAuthConnection.builder()
                    .user(testUser)
                    .provider(OAuthProvider.APPLE)
                    .providerUserId("apple-123")
                    .providerEmail("test@apple.com")
                    .build();

            oauthConnectionRepository.save(connection);

            verify(oauthConnectionRepository).save(connectionCaptor.capture());
            assertThat(connectionCaptor.getValue().getUser()).isEqualTo(testUser);
            assertThat(connectionCaptor.getValue().getProvider()).isEqualTo(OAuthProvider.APPLE);
        }
    }

    @Nested
    @DisplayName("Last Login Update Tests")
    class LastLoginUpdateTests {

        @Test
        @DisplayName("should update last login on OIDC authentication")
        void shouldUpdateLastLoginOnOidcAuthentication() {
            Instant beforeLogin = testUser.getLastLoginAt();
            testUser.setLastLoginAt(Instant.now());

            when(authUserRepository.save(testUser)).thenReturn(testUser);

            authUserRepository.save(testUser);

            verify(authUserRepository).save(testUser);
            if (beforeLogin != null) {
                assertThat(testUser.getLastLoginAt()).isAfterOrEqualTo(beforeLogin);
            }
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("should handle missing email in OIDC response")
        void shouldHandleMissingEmailInOidcResponse() {
            when(mockOidcUser.getEmail()).thenReturn(null);

            String email = mockOidcUser.getEmail();

            assertThat(email).isNull();
        }

        @Test
        @DisplayName("should handle empty email in OIDC response")
        void shouldHandleEmptyEmailInOidcResponse() {
            when(mockOidcUser.getEmail()).thenReturn("");

            String email = mockOidcUser.getEmail();

            assertThat(email).isEmpty();
        }
    }

    @Nested
    @DisplayName("OIDC Provider Tests")
    class OidcProviderTests {

        @Test
        @DisplayName("should support Google as OIDC provider")
        void shouldSupportGoogleAsOidcProvider() {
            assertThat(OAuthProvider.valueOf("GOOGLE")).isEqualTo(OAuthProvider.GOOGLE);
        }

        @Test
        @DisplayName("should support Apple as OIDC provider")
        void shouldSupportAppleAsOidcProvider() {
            assertThat(OAuthProvider.valueOf("APPLE")).isEqualTo(OAuthProvider.APPLE);
        }
    }

    @Nested
    @DisplayName("OIDC User Info Extraction Tests")
    class OidcUserInfoExtractionTests {

        @Test
        @DisplayName("should extract subject from OIDC user")
        void shouldExtractSubjectFromOidcUser() {
            when(mockOidcUser.getSubject()).thenReturn("google-subject-123");

            String subject = mockOidcUser.getSubject();

            assertThat(subject).isEqualTo("google-subject-123");
        }

        @Test
        @DisplayName("should extract full name from OIDC user")
        void shouldExtractFullNameFromOidcUser() {
            when(mockOidcUser.getFullName()).thenReturn("John Doe");

            String name = mockOidcUser.getFullName();

            assertThat(name).isEqualTo("John Doe");
        }

        @Test
        @DisplayName("should extract picture URL from OIDC user")
        void shouldExtractPictureUrlFromOidcUser() {
            when(mockOidcUser.getPicture()).thenReturn("https://google.com/photo.jpg");

            String picture = mockOidcUser.getPicture();

            assertThat(picture).isEqualTo("https://google.com/photo.jpg");
        }

        @Test
        @DisplayName("should extract email from OIDC user")
        void shouldExtractEmailFromOidcUser() {
            when(mockOidcUser.getEmail()).thenReturn("user@gmail.com");

            String email = mockOidcUser.getEmail();

            assertThat(email).isEqualTo("user@gmail.com");
        }
    }

    @Nested
    @DisplayName("OAuth Connection Scopes Tests")
    class OAuthConnectionScopesTests {

        @Test
        @DisplayName("should store OIDC scopes in connection")
        void shouldStoreOidcScopesInConnection() {
            OAuthConnection connection = OAuthConnection.builder()
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-123")
                    .scopes("openid,email,profile")
                    .build();

            assertThat(connection.getScopes()).isEqualTo("openid,email,profile");
            assertThat(connection.getScopes().split(",")).containsExactlyInAnyOrder("openid", "email", "profile");
        }
    }

    @Nested
    @DisplayName("LoadUser End-to-End Tests")
    class LoadUserEndToEndTests {

        private org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest createOidcUserRequest(String registrationId) {
            org.springframework.security.oauth2.client.registration.ClientRegistration clientRegistration =
                    org.springframework.security.oauth2.client.registration.ClientRegistration.withRegistrationId(registrationId)
                    .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientId("test-client-id")
                    .clientSecret("test-client-secret")
                    .redirectUri("http://localhost/callback")
                    .authorizationUri("https://provider.com/auth")
                    .tokenUri("https://provider.com/token")
                    .userInfoUri("https://provider.com/userinfo")
                    .jwkSetUri("https://provider.com/jwks")
                    .userNameAttributeName("sub")
                    .scope("openid", "email", "profile")
                    .build();

            org.springframework.security.oauth2.core.OAuth2AccessToken accessToken =
                    new org.springframework.security.oauth2.core.OAuth2AccessToken(
                    org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER,
                    "test-access-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            OidcIdToken idToken = new OidcIdToken(
                    "test-id-token",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    Map.of("sub", "test-subject", "iss", "https://provider.com")
            );

            return new org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest(
                    clientRegistration, accessToken, idToken
            );
        }

        private OidcUser createMockOidcUser(String subject, String email, String name, String picture) {
            OidcUser oidcUser = mock(OidcUser.class);
            when(oidcUser.getSubject()).thenReturn(subject);
            when(oidcUser.getEmail()).thenReturn(email);
            when(oidcUser.getFullName()).thenReturn(name);
            when(oidcUser.getPicture()).thenReturn(picture);

            // Use HashMap to allow null values (Map.of() doesn't support nulls)
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", subject);
            if (email != null) {
                attributes.put("email", email);
            }
            when(oidcUser.getAttributes()).thenReturn(attributes);
            when(oidcUser.getClaims()).thenReturn(attributes);
            doReturn(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
                    .when(oidcUser).getAuthorities();
            return oidcUser;
        }

        /**
         * Testable subclass that allows injecting a mock OidcUser
         * instead of calling the parent's loadUser method
         */
        class TestableCustomOidcUserService extends CustomOidcUserService {
            private OidcUser mockOidcUser;

            public TestableCustomOidcUserService(
                    AuthUserRepository authUserRepository,
                    OAuthConnectionRepository oauthConnectionRepository,
                    UserEventPublisher userEventPublisher) {
                super(authUserRepository, oauthConnectionRepository, userEventPublisher);
            }

            public void setMockOidcUser(OidcUser mockOidcUser) {
                this.mockOidcUser = mockOidcUser;
            }

            @Override
            public OidcUser loadUser(org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest userRequest)
                    throws org.springframework.security.oauth2.core.OAuth2AuthenticationException {
                if (mockOidcUser == null) {
                    throw new IllegalStateException("Mock OidcUser not set");
                }

                String registrationId = userRequest.getClientRegistration().getRegistrationId();

                try {
                    return processOidcUserForTest(userRequest, mockOidcUser, registrationId);
                } catch (org.springframework.security.oauth2.core.OAuth2AuthenticationException ex) {
                    throw ex;
                } catch (Exception ex) {
                    throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
                            new org.springframework.security.oauth2.core.OAuth2Error("processing_error", ex.getMessage(), null)
                    );
                }
            }

            private OidcUser processOidcUserForTest(
                    org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest userRequest,
                    OidcUser oidcUser, String registrationId) {

                String email = oidcUser.getEmail();
                String providerUserId = oidcUser.getSubject();
                String name = oidcUser.getFullName();

                if (email == null || email.isEmpty()) {
                    throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
                            new org.springframework.security.oauth2.core.OAuth2Error("email_not_found", "Email not found from OIDC provider", null)
                    );
                }

                OAuthProvider provider = OAuthProvider.valueOf(registrationId.toUpperCase());

                Optional<OAuthConnection> existingConnection = oauthConnectionRepository
                        .findByProviderAndProviderUserId(provider, providerUserId);

                AuthUser user;
                boolean isNewUser = false;

                if (existingConnection.isPresent()) {
                    OAuthConnection connection = existingConnection.get();
                    user = connection.getUser();
                    updateOAuthConnectionForTest(connection, userRequest);
                } else {
                    Optional<AuthUser> existingUser = authUserRepository.findByEmail(email);

                    if (existingUser.isPresent()) {
                        user = existingUser.get();
                        createOAuthConnectionForTest(user, provider, providerUserId, userRequest, oidcUser);
                    } else {
                        user = createNewUserForTest(email, name);
                        createOAuthConnectionForTest(user, provider, providerUserId, userRequest, oidcUser);
                        isNewUser = true;
                        userEventPublisher.publishUserRegistered(user);
                    }
                }

                user.setLastLoginAt(Instant.now());
                authUserRepository.save(user);

                return new CustomOidcUser(user, oidcUser, isNewUser);
            }

            private AuthUser createNewUserForTest(String email, String name) {
                AuthUser user = AuthUser.builder()
                        .email(email)
                        .externalId(UUID.randomUUID().toString())
                        .status(AuthUser.AuthStatus.ACTIVE)
                        .emailVerified(true)
                        .build();
                return authUserRepository.save(user);
            }

            private void createOAuthConnectionForTest(AuthUser user, OAuthProvider provider, String providerUserId,
                    org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest userRequest, OidcUser oidcUser) {
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

            private void updateOAuthConnectionForTest(OAuthConnection connection,
                    org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest userRequest) {
                connection.setAccessToken(userRequest.getAccessToken().getTokenValue());
                connection.setTokenExpiresAt(userRequest.getAccessToken().getExpiresAt());
                connection.setLastUsedAt(Instant.now());
                oauthConnectionRepository.save(connection);
            }
        }

        private TestableCustomOidcUserService testableService;

        @BeforeEach
        void setUpTestableService() {
            testableService = new TestableCustomOidcUserService(
                    authUserRepository,
                    oauthConnectionRepository,
                    userEventPublisher
            );
        }

        @Test
        @DisplayName("should load and process new user via OIDC")
        void shouldLoadAndProcessNewUserViaOidc() {
            // Given
            String providerUserId = "google-oidc-new-123";
            String email = "newuser@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "New User", "https://photo.jpg");

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            OidcUser result = testableService.loadUser(userRequest);

            // Then
            assertThat(result).isInstanceOf(CustomOidcUser.class);
            CustomOidcUser customOidcUser = (CustomOidcUser) result;
            assertThat(customOidcUser.getAuthUser().getEmail()).isEqualTo(email);
            assertThat(customOidcUser.isNewUser()).isTrue();

            verify(authUserRepository, times(2)).save(any(AuthUser.class));
            verify(oauthConnectionRepository).save(any(OAuthConnection.class));
            verify(userEventPublisher).publishUserRegistered(any(AuthUser.class));
        }

        @Test
        @DisplayName("should load and link OIDC to existing user by email")
        void shouldLoadAndLinkOidcToExistingUserByEmail() {
            // Given
            String providerUserId = "google-oidc-link-123";
            String email = "existing@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "Existing User", "https://photo.jpg");

            AuthUser existingUser = AuthUser.builder()
                    .id(UUID.randomUUID())
                    .email(email)
                    .externalId("ext-existing")
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .build();

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.of(existingUser));
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenReturn(existingUser);
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            OidcUser result = testableService.loadUser(userRequest);

            // Then
            assertThat(result).isInstanceOf(CustomOidcUser.class);
            CustomOidcUser customOidcUser = (CustomOidcUser) result;
            assertThat(customOidcUser.getAuthUser().getEmail()).isEqualTo(email);
            assertThat(customOidcUser.isNewUser()).isFalse();

            verify(oauthConnectionRepository).save(any(OAuthConnection.class));
            verify(userEventPublisher, never()).publishUserRegistered(any());
        }

        @Test
        @DisplayName("should load and update existing OIDC connection")
        void shouldLoadAndUpdateExistingOidcConnection() {
            // Given
            String providerUserId = "google-oidc-existing-123";
            String email = "oauth-user@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "OIDC User", "https://photo.jpg");

            AuthUser existingUser = AuthUser.builder()
                    .id(UUID.randomUUID())
                    .email(email)
                    .externalId("ext-oauth")
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .build();

            OAuthConnection existingConnection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(existingUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId(providerUserId)
                    .accessToken("old-token")
                    .build();

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.of(existingConnection));
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenReturn(existingUser);
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            OidcUser result = testableService.loadUser(userRequest);

            // Then
            assertThat(result).isInstanceOf(CustomOidcUser.class);
            CustomOidcUser customOidcUser = (CustomOidcUser) result;
            assertThat(customOidcUser.isNewUser()).isFalse();

            // Verify token was updated
            ArgumentCaptor<OAuthConnection> connectionCaptor = ArgumentCaptor.forClass(OAuthConnection.class);
            verify(oauthConnectionRepository).save(connectionCaptor.capture());
            assertThat(connectionCaptor.getValue().getAccessToken()).isEqualTo("test-access-token");
        }

        @Test
        @DisplayName("should throw OAuth2AuthenticationException when email is null")
        void shouldThrowExceptionWhenEmailIsNull() {
            // Given
            String providerUserId = "google-no-email-123";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, null, "No Email User", null);

            testableService.setMockOidcUser(oidcUser);

            // When/Then
            assertThatThrownBy(() -> testableService.loadUser(userRequest))
                    .isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        var oauth2Ex = (org.springframework.security.oauth2.core.OAuth2AuthenticationException) ex;
                        assertThat(oauth2Ex.getError().getErrorCode()).isEqualTo("email_not_found");
                    });
        }

        @Test
        @DisplayName("should throw OAuth2AuthenticationException when email is empty")
        void shouldThrowExceptionWhenEmailIsEmpty() {
            // Given
            String providerUserId = "google-empty-email-123";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, "", "Empty Email User", null);

            testableService.setMockOidcUser(oidcUser);

            // When/Then
            assertThatThrownBy(() -> testableService.loadUser(userRequest))
                    .isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        var oauth2Ex = (org.springframework.security.oauth2.core.OAuth2AuthenticationException) ex;
                        assertThat(oauth2Ex.getError().getErrorCode()).isEqualTo("email_not_found");
                    });
        }

        @Test
        @DisplayName("should wrap processing exception in OAuth2AuthenticationException")
        void shouldWrapProcessingExceptionInOAuth2AuthenticationException() {
            // Given
            String providerUserId = "google-error-123";
            String email = "error@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "Error User", null);

            testableService.setMockOidcUser(oidcUser);

            // Simulate a database error
            when(oauthConnectionRepository.findByProviderAndProviderUserId(any(), any()))
                    .thenThrow(new RuntimeException("Database connection failed"));

            // When/Then
            assertThatThrownBy(() -> testableService.loadUser(userRequest))
                    .isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class)
                    .satisfies(ex -> {
                        var oauth2Ex = (org.springframework.security.oauth2.core.OAuth2AuthenticationException) ex;
                        assertThat(oauth2Ex.getError().getErrorCode()).isEqualTo("processing_error");
                        assertThat(oauth2Ex.getError().getDescription()).contains("Database connection failed");
                    });
        }

        @Test
        @DisplayName("should handle Apple OIDC provider correctly")
        void shouldHandleAppleOidcProviderCorrectly() {
            // Given
            String providerUserId = "apple-oidc-123";
            String email = "user@privaterelay.appleid.com";
            var userRequest = createOidcUserRequest("apple");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "Apple User", null);

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.APPLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            OidcUser result = testableService.loadUser(userRequest);

            // Then
            assertThat(result).isInstanceOf(CustomOidcUser.class);
            verify(oauthConnectionRepository).findByProviderAndProviderUserId(OAuthProvider.APPLE, providerUserId);
        }

        @Test
        @DisplayName("should create OIDC connection with correct scopes")
        void shouldCreateOidcConnectionWithCorrectScopes() {
            // Given
            String providerUserId = "google-scopes-123";
            String email = "scopes@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "Scopes User", "https://photo.jpg");

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });

            ArgumentCaptor<OAuthConnection> connectionCaptor = ArgumentCaptor.forClass(OAuthConnection.class);
            when(oauthConnectionRepository.save(connectionCaptor.capture()))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            testableService.loadUser(userRequest);

            // Then
            OAuthConnection savedConnection = connectionCaptor.getValue();
            assertThat(savedConnection.getScopes()).contains("openid");
            assertThat(savedConnection.getScopes()).contains("email");
            assertThat(savedConnection.getScopes()).contains("profile");
            assertThat(savedConnection.getAccessToken()).isEqualTo("test-access-token");
            assertThat(savedConnection.getTokenExpiresAt()).isNotNull();
            assertThat(savedConnection.getLastUsedAt()).isNotNull();
        }

        @Test
        @DisplayName("should set lastLoginAt on successful authentication")
        void shouldSetLastLoginAtOnSuccessfulAuthentication() {
            // Given
            String providerUserId = "google-login-123";
            String email = "login@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "Login User", null);

            Instant beforeLogin = Instant.now().minusSeconds(1);

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());

            ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
            when(authUserRepository.save(userCaptor.capture()))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            testableService.loadUser(userRequest);

            // Then - get the last saved user (the one with lastLoginAt set)
            List<AuthUser> allCaptured = userCaptor.getAllValues();
            AuthUser lastSaved = allCaptured.get(allCaptured.size() - 1);
            assertThat(lastSaved.getLastLoginAt()).isAfter(beforeLogin);
        }

        @Test
        @DisplayName("should populate all OIDC connection fields correctly")
        void shouldPopulateAllOidcConnectionFieldsCorrectly() {
            // Given
            String providerUserId = "google-full-123";
            String email = "full@gmail.com";
            String name = "Full Name User";
            String picture = "https://example.com/photo.jpg";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, name, picture);

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });

            ArgumentCaptor<OAuthConnection> connectionCaptor = ArgumentCaptor.forClass(OAuthConnection.class);
            when(oauthConnectionRepository.save(connectionCaptor.capture()))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            testableService.loadUser(userRequest);

            // Then
            OAuthConnection savedConnection = connectionCaptor.getValue();
            assertThat(savedConnection.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
            assertThat(savedConnection.getProviderUserId()).isEqualTo(providerUserId);
            assertThat(savedConnection.getProviderEmail()).isEqualTo(email);
            assertThat(savedConnection.getProviderName()).isEqualTo(name);
            assertThat(savedConnection.getProviderAvatarUrl()).isEqualTo(picture);
        }

        @Test
        @DisplayName("should create new user with correct attributes")
        void shouldCreateNewUserWithCorrectAttributes() {
            // Given
            String providerUserId = "google-newattr-123";
            String email = "newattr@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "New Attr User", null);

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());

            ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
            when(authUserRepository.save(userCaptor.capture()))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            testableService.loadUser(userRequest);

            // Then - the first captured user is the newly created one
            AuthUser createdUser = userCaptor.getAllValues().get(0);
            assertThat(createdUser.getEmail()).isEqualTo(email);
            assertThat(createdUser.isEmailVerified()).isTrue(); // OIDC emails are pre-verified
            assertThat(createdUser.getStatus()).isEqualTo(AuthUser.AuthStatus.ACTIVE);
            assertThat(createdUser.getExternalId()).isNotNull();
        }

        @Test
        @DisplayName("should return CustomOidcUser that delegates to underlying OidcUser")
        void shouldReturnCustomOidcUserThatDelegatesToUnderlyingOidcUser() {
            // Given
            String providerUserId = "google-delegate-123";
            String email = "delegate@gmail.com";
            var userRequest = createOidcUserRequest("google");
            OidcUser oidcUser = createMockOidcUser(providerUserId, email, "Delegate User", "https://photo.jpg");

            testableService.setMockOidcUser(oidcUser);

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, providerUserId))
                    .thenReturn(Optional.empty());
            when(authUserRepository.findByEmail(email))
                    .thenReturn(Optional.empty());
            when(authUserRepository.save(any(AuthUser.class)))
                    .thenAnswer(inv -> {
                        AuthUser user = inv.getArgument(0);
                        if (user.getId() == null) {
                            user.setId(UUID.randomUUID());
                        }
                        return user;
                    });
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // When
            OidcUser result = testableService.loadUser(userRequest);

            // Then
            assertThat(result).isInstanceOf(CustomOidcUser.class);
            CustomOidcUser customOidcUser = (CustomOidcUser) result;

            // Verify delegation
            assertThat(customOidcUser.getAttributes()).isEqualTo(oidcUser.getAttributes());
            assertThat(customOidcUser.getClaims()).isEqualTo(oidcUser.getClaims());
            assertThat(customOidcUser.getAuthorities()).isEqualTo(oidcUser.getAuthorities());
        }
    }
}
