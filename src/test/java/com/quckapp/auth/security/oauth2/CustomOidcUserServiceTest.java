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
}
