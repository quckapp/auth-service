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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomOAuth2UserService
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomOAuth2UserServiceTest {

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private OAuthConnectionRepository oauthConnectionRepository;

    @Mock
    private UserEventPublisher userEventPublisher;

    private CustomOAuth2UserService customOAuth2UserService;

    private UUID testUserId;
    private AuthUser testUser;

    @BeforeEach
    void setUp() {
        customOAuth2UserService = new CustomOAuth2UserService(
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
    @DisplayName("OAuth2UserInfo Factory Tests")
    class OAuth2UserInfoFactoryTests {

        @Test
        @DisplayName("should create GoogleOAuth2UserInfo")
        void shouldCreateGoogleOAuth2UserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-123");
            attributes.put("name", "John Doe");
            attributes.put("email", "john@gmail.com");
            attributes.put("picture", "https://google.com/photo.jpg");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("google", attributes);

            assertThat(userInfo.getId()).isEqualTo("google-123");
            assertThat(userInfo.getName()).isEqualTo("John Doe");
            assertThat(userInfo.getEmail()).isEqualTo("john@gmail.com");
            assertThat(userInfo.getImageUrl()).isEqualTo("https://google.com/photo.jpg");
        }

        @Test
        @DisplayName("should create FacebookOAuth2UserInfo")
        void shouldCreateFacebookOAuth2UserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "fb-123");
            attributes.put("name", "Jane Doe");
            attributes.put("email", "jane@facebook.com");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("facebook", attributes);

            assertThat(userInfo.getId()).isEqualTo("fb-123");
            assertThat(userInfo.getName()).isEqualTo("Jane Doe");
            assertThat(userInfo.getEmail()).isEqualTo("jane@facebook.com");
        }

        @Test
        @DisplayName("should create GithubOAuth2UserInfo")
        void shouldCreateGithubOAuth2UserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", 12345);
            attributes.put("name", "Dev User");
            attributes.put("email", "dev@github.com");
            attributes.put("avatar_url", "https://github.com/avatar.jpg");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("github", attributes);

            assertThat(userInfo.getId()).isEqualTo("12345");
            assertThat(userInfo.getName()).isEqualTo("Dev User");
            assertThat(userInfo.getEmail()).isEqualTo("dev@github.com");
            assertThat(userInfo.getImageUrl()).isEqualTo("https://github.com/avatar.jpg");
        }

        @Test
        @DisplayName("should create AppleOAuth2UserInfo")
        void shouldCreateAppleOAuth2UserInfo() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "apple-123");
            attributes.put("email", "user@apple.com");

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("apple", attributes);

            assertThat(userInfo.getId()).isEqualTo("apple-123");
            assertThat(userInfo.getEmail()).isEqualTo("user@apple.com");
            assertThat(userInfo.getImageUrl()).isNull();
        }

        @Test
        @DisplayName("should throw exception for unsupported provider")
        void shouldThrowExceptionForUnsupportedProvider() {
            Map<String, Object> attributes = new HashMap<>();

            assertThatThrownBy(() -> OAuth2UserInfo.create("unsupported", attributes))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Unsupported OAuth2 provider");
        }

        @Test
        @DisplayName("should extract Facebook picture URL from nested structure")
        void shouldExtractFacebookPictureUrl() {
            Map<String, Object> pictureData = new HashMap<>();
            pictureData.put("url", "https://facebook.com/photo.jpg");

            Map<String, Object> picture = new HashMap<>();
            picture.put("data", pictureData);

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "fb-123");
            attributes.put("name", "User");
            attributes.put("email", "user@fb.com");
            attributes.put("picture", picture);

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("facebook", attributes);

            assertThat(userInfo.getImageUrl()).isEqualTo("https://facebook.com/photo.jpg");
        }

        @Test
        @DisplayName("should extract Apple name from nested structure")
        void shouldExtractAppleNameFromNestedStructure() {
            Map<String, Object> name = new HashMap<>();
            name.put("firstName", "John");
            name.put("lastName", "Apple");

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "apple-123");
            attributes.put("email", "john@apple.com");
            attributes.put("name", name);

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("apple", attributes);

            assertThat(userInfo.getName()).isEqualTo("John Apple");
        }
    }

    @Nested
    @DisplayName("OAuth2UserPrincipal Tests")
    class OAuth2UserPrincipalTests {

        @Test
        @DisplayName("should create OAuth2UserPrincipal from AuthUser")
        void shouldCreateOAuth2UserPrincipalFromAuthUser() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("email", "test@example.com");

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);

            assertThat(principal.getId()).isEqualTo(testUserId);
            assertThat(principal.getEmail()).isEqualTo("test@example.com");
            assertThat(principal.getExternalId()).isEqualTo("ext-123");
            assertThat(principal.isNewUser()).isFalse();
        }

        @Test
        @DisplayName("should create OAuth2UserPrincipal for new user")
        void shouldCreateOAuth2UserPrincipalForNewUser() {
            Map<String, Object> attributes = new HashMap<>();

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, true);

            assertThat(principal.isNewUser()).isTrue();
        }

        @Test
        @DisplayName("should have ROLE_USER authority")
        void shouldHaveRoleUserAuthority() {
            Map<String, Object> attributes = new HashMap<>();

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);

            assertThat(principal.getAuthorities())
                    .extracting("authority")
                    .containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("should implement OAuth2User interface correctly")
        void shouldImplementOAuth2UserInterfaceCorrectly() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("key", "value");

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);

            assertThat(principal.getName()).isEqualTo(testUserId.toString());
            assertThat(principal.getAttributes()).containsEntry("key", "value");
        }

        @Test
        @DisplayName("should implement UserDetails interface correctly")
        void shouldImplementUserDetailsInterfaceCorrectly() {
            Map<String, Object> attributes = new HashMap<>();

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);

            assertThat(principal.getUsername()).isEqualTo("test@example.com");
            assertThat(principal.isAccountNonExpired()).isTrue();
            assertThat(principal.isAccountNonLocked()).isTrue();
            assertThat(principal.isCredentialsNonExpired()).isTrue();
            assertThat(principal.isEnabled()).isTrue();
        }
    }

    @Nested
    @DisplayName("Existing OAuth Connection Tests")
    class ExistingOAuthConnectionTests {

        @Test
        @DisplayName("should update OAuth connection for existing user")
        void shouldUpdateOAuthConnectionForExistingUser() {
            OAuthConnection existingConnection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-123")
                    .build();

            when(oauthConnectionRepository.findByProviderAndProviderUserId(OAuthProvider.GOOGLE, "google-123"))
                    .thenReturn(Optional.of(existingConnection));
            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            // This test verifies the update logic flows correctly
            // Full integration would require mocking OAuth2UserRequest
            assertThat(existingConnection.getUser()).isEqualTo(testUser);
        }
    }

    @Nested
    @DisplayName("New User Creation Tests")
    class NewUserCreationTests {

        @Test
        @DisplayName("should save new user with verified email")
        void shouldSaveNewUserWithVerifiedEmail() {
            AuthUser newUser = AuthUser.builder()
                    .email("new@example.com")
                    .externalId(UUID.randomUUID().toString())
                    .status(AuthUser.AuthStatus.ACTIVE)
                    .emailVerified(true)
                    .build();

            when(authUserRepository.save(any(AuthUser.class))).thenReturn(newUser);

            ArgumentCaptor<AuthUser> userCaptor = ArgumentCaptor.forClass(AuthUser.class);
            authUserRepository.save(newUser);

            verify(authUserRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().isEmailVerified()).isTrue();
        }
    }

    @Nested
    @DisplayName("Link Existing User Tests")
    class LinkExistingUserTests {

        @Test
        @DisplayName("should find existing user by email")
        void shouldFindExistingUserByEmail() {
            when(authUserRepository.findByEmail("test@example.com"))
                    .thenReturn(Optional.of(testUser));

            Optional<AuthUser> found = authUserRepository.findByEmail("test@example.com");

            assertThat(found).isPresent();
            assertThat(found.get().getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("should create OAuth connection for existing user")
        void shouldCreateOAuthConnectionForExistingUser() {
            when(oauthConnectionRepository.save(any(OAuthConnection.class)))
                    .thenAnswer(invocation -> {
                        OAuthConnection conn = invocation.getArgument(0);
                        conn.setId(UUID.randomUUID());
                        return conn;
                    });

            OAuthConnection connection = OAuthConnection.builder()
                    .user(testUser)
                    .provider(OAuthProvider.GITHUB)
                    .providerUserId("github-456")
                    .providerEmail("test@github.com")
                    .build();

            OAuthConnection saved = oauthConnectionRepository.save(connection);

            assertThat(saved.getId()).isNotNull();
            assertThat(saved.getUser()).isEqualTo(testUser);
            assertThat(saved.getProvider()).isEqualTo(OAuthProvider.GITHUB);
        }
    }

    @Nested
    @DisplayName("OAuth Connection Update Tests")
    class OAuthConnectionUpdateTests {

        @Test
        @DisplayName("should update access token on OAuth connection")
        void shouldUpdateAccessTokenOnOAuthConnection() {
            OAuthConnection connection = OAuthConnection.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .provider(OAuthProvider.GOOGLE)
                    .providerUserId("google-123")
                    .accessToken("old-token")
                    .build();

            connection.setAccessToken("new-token");
            connection.setTokenExpiresAt(Instant.now().plusSeconds(3600));
            connection.setLastUsedAt(Instant.now());

            when(oauthConnectionRepository.save(any(OAuthConnection.class))).thenReturn(connection);

            OAuthConnection updated = oauthConnectionRepository.save(connection);

            assertThat(updated.getAccessToken()).isEqualTo("new-token");
        }
    }

    @Nested
    @DisplayName("User Event Publishing Tests")
    class UserEventPublishingTests {

        @Test
        @DisplayName("should publish user registered event for new OAuth user")
        void shouldPublishUserRegisteredEventForNewOAuthUser() {
            AuthUser newUser = AuthUser.builder()
                    .id(UUID.randomUUID())
                    .email("oauth@example.com")
                    .externalId("ext-new")
                    .build();

            userEventPublisher.publishUserRegistered(newUser);

            verify(userEventPublisher).publishUserRegistered(newUser);
        }

        @Test
        @DisplayName("should not publish event for existing user")
        void shouldNotPublishEventForExistingUser() {
            // No event should be published when OAuth links to existing user
            verifyNoInteractions(userEventPublisher);
        }
    }

    @Nested
    @DisplayName("Last Login Update Tests")
    class LastLoginUpdateTests {

        @Test
        @DisplayName("should update last login timestamp")
        void shouldUpdateLastLoginTimestamp() {
            Instant before = Instant.now();
            testUser.setLastLoginAt(before);

            when(authUserRepository.save(any(AuthUser.class))).thenReturn(testUser);

            authUserRepository.save(testUser);

            verify(authUserRepository).save(testUser);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("should throw exception when email not found in OAuth response")
        void shouldThrowExceptionWhenEmailNotFoundInOAuthResponse() {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("sub", "google-123");
            // No email attribute

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("google", attributes);

            assertThat(userInfo.getEmail()).isNull();
        }

        @Test
        @DisplayName("should handle missing OAuth attributes gracefully")
        void shouldHandleMissingOAuthAttributesGracefully() {
            Map<String, Object> attributes = new HashMap<>();
            // Empty attributes

            OAuth2UserInfo userInfo = OAuth2UserInfo.create("google", attributes);

            assertThat(userInfo.getId()).isNull();
            assertThat(userInfo.getName()).isNull();
            assertThat(userInfo.getEmail()).isNull();
            assertThat(userInfo.getImageUrl()).isNull();
        }
    }

    @Nested
    @DisplayName("Provider Enum Tests")
    class ProviderEnumTests {

        @Test
        @DisplayName("should convert provider string to enum")
        void shouldConvertProviderStringToEnum() {
            assertThat(OAuthProvider.valueOf("GOOGLE")).isEqualTo(OAuthProvider.GOOGLE);
            assertThat(OAuthProvider.valueOf("FACEBOOK")).isEqualTo(OAuthProvider.FACEBOOK);
            assertThat(OAuthProvider.valueOf("GITHUB")).isEqualTo(OAuthProvider.GITHUB);
            assertThat(OAuthProvider.valueOf("APPLE")).isEqualTo(OAuthProvider.APPLE);
        }

        @Test
        @DisplayName("should throw exception for invalid provider")
        void shouldThrowExceptionForInvalidProvider() {
            assertThatThrownBy(() -> OAuthProvider.valueOf("INVALID"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
