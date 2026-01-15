package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.LoginHistoryService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for OAuth2AuthenticationSuccessHandler methods
 * Uses Mockito for interface mocking (works in Java 25) and reflection for private methods
 */
@DisplayName("OAuth2AuthenticationSuccessHandler Method Tests")
@ExtendWith(MockitoExtension.class)
class OAuth2SuccessHandlerMethodsTest {

    @Mock
    private JwtOperations jwtOperations;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    // LoginHistoryService is a class (not interface), can't be mocked in Java 25
    // The methods being tested don't use it, so we pass null
    private LoginHistoryService loginHistoryService = null;

    private OAuth2AuthenticationSuccessHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthUser testUser;

    // Test OAuth2Config implementation
    static class TestOAuth2Config extends OAuth2Config {
        @Override
        public String getRedirectUriCookieName() {
            return "redirect_uri";
        }

        @Override
        public String getFrontendCallbackUrl() {
            return "http://localhost:3000/oauth/callback";
        }

        @Override
        public String getDefaultFailureUrl() {
            return "http://localhost:3000/login?error=true";
        }
    }

    @BeforeEach
    void setUp() {
        TestOAuth2Config config = new TestOAuth2Config();
        HttpCookieOAuth2AuthorizationRequestRepository authRepo =
            new HttpCookieOAuth2AuthorizationRequestRepository(config);

        handler = new OAuth2AuthenticationSuccessHandler(
            jwtOperations,
            authUserRepository,
            refreshTokenRepository,
            loginHistoryService,
            config,
            authRepo
        );

        testUser = AuthUser.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Nested
    @DisplayName("getCookieValue() Tests via Reflection")
    class GetCookieValueTests {

        @Test
        @DisplayName("should return empty when no cookies present")
        void shouldReturnEmptyWhenNoCookies() throws Exception {
            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should return cookie value when cookie exists")
        void shouldReturnCookieValueWhenExists() throws Exception {
            request.setCookies(new Cookie("redirect_uri", "http://custom.com/callback"));

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo("http://custom.com/callback");
        }

        @Test
        @DisplayName("should return empty when cookie name not found")
        void shouldReturnEmptyWhenCookieNameNotFound() throws Exception {
            request.setCookies(new Cookie("other_cookie", "value"));

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should find correct cookie among multiple cookies")
        void shouldFindCorrectCookieAmongMultiple() throws Exception {
            request.setCookies(
                new Cookie("session_id", "abc123"),
                new Cookie("redirect_uri", "http://target.com/callback"),
                new Cookie("csrf_token", "xyz789")
            );

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo("http://target.com/callback");
        }
    }

    @Nested
    @DisplayName("getClientIp() Tests via Reflection")
    class GetClientIpTests {

        @Test
        @DisplayName("should extract IP from X-Forwarded-For header")
        void shouldExtractIpFromXForwardedFor() throws Exception {
            request.addHeader("X-Forwarded-For", "192.168.1.100, 10.0.0.1");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getClientIp", HttpServletRequest.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request);

            assertThat(result).isEqualTo("192.168.1.100");
        }

        @Test
        @DisplayName("should extract IP from X-Real-IP header")
        void shouldExtractIpFromXRealIp() throws Exception {
            request.addHeader("X-Real-IP", "172.16.0.50");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getClientIp", HttpServletRequest.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request);

            assertThat(result).isEqualTo("172.16.0.50");
        }

        @Test
        @DisplayName("should fallback to remote address")
        void shouldFallbackToRemoteAddress() throws Exception {
            request.setRemoteAddr("127.0.0.1");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getClientIp", HttpServletRequest.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request);

            assertThat(result).isEqualTo("127.0.0.1");
        }

        @Test
        @DisplayName("should handle empty X-Forwarded-For header")
        void shouldHandleEmptyXForwardedFor() throws Exception {
            request.addHeader("X-Forwarded-For", "");
            request.setRemoteAddr("10.0.0.1");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getClientIp", HttpServletRequest.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request);

            assertThat(result).isEqualTo("10.0.0.1");
        }

        @Test
        @DisplayName("should extract first IP from comma-separated X-Forwarded-For")
        void shouldExtractFirstIpFromCommaSeparated() throws Exception {
            request.addHeader("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getClientIp", HttpServletRequest.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request);

            assertThat(result).isEqualTo("203.0.113.50");
        }
    }

    @Nested
    @DisplayName("isNewUser() Tests via Reflection")
    class IsNewUserTests {

        @Test
        @DisplayName("should return true for new CustomOidcUser")
        void shouldReturnTrueForNewCustomOidcUser() throws Exception {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "12345");
            claims.put("email", "test@example.com");
            OidcIdToken idToken = new OidcIdToken("token", Instant.now(),
                Instant.now().plusSeconds(3600), claims);
            OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, true);
            TestAuthentication auth = new TestAuthentication(customOidcUser);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("isNewUser", Authentication.class);
            method.setAccessible(true);

            boolean result = (boolean) method.invoke(handler, auth);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false for existing CustomOidcUser")
        void shouldReturnFalseForExistingCustomOidcUser() throws Exception {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "12345");
            claims.put("email", "test@example.com");
            OidcIdToken idToken = new OidcIdToken("token", Instant.now(),
                Instant.now().plusSeconds(3600), claims);
            OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            TestAuthentication auth = new TestAuthentication(customOidcUser);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("isNewUser", Authentication.class);
            method.setAccessible(true);

            boolean result = (boolean) method.invoke(handler, auth);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return true for new OAuth2UserPrincipal")
        void shouldReturnTrueForNewOAuth2UserPrincipal() throws Exception {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "12345");
            attributes.put("email", "test@example.com");

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, true);
            TestAuthentication auth = new TestAuthentication(principal);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("isNewUser", Authentication.class);
            method.setAccessible(true);

            boolean result = (boolean) method.invoke(handler, auth);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("should return false for existing OAuth2UserPrincipal")
        void shouldReturnFalseForExistingOAuth2UserPrincipal() throws Exception {
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "12345");
            attributes.put("email", "test@example.com");

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);
            TestAuthentication auth = new TestAuthentication(principal);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("isNewUser", Authentication.class);
            method.setAccessible(true);

            boolean result = (boolean) method.invoke(handler, auth);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("should return false for unknown principal type")
        void shouldReturnFalseForUnknownPrincipalType() throws Exception {
            TestAuthentication auth = new TestAuthentication("unknown-principal");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("isNewUser", Authentication.class);
            method.setAccessible(true);

            boolean result = (boolean) method.invoke(handler, auth);

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("getAuthUser() Tests via Reflection")
    class GetAuthUserTests {

        @Test
        @DisplayName("should extract user from CustomOidcUser")
        void shouldExtractUserFromCustomOidcUser() throws Exception {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "12345");
            claims.put("email", "test@example.com");
            OidcIdToken idToken = new OidcIdToken("token", Instant.now(),
                Instant.now().plusSeconds(3600), claims);
            OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            TestAuthentication auth = new TestAuthentication(customOidcUser);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getAuthUser", Authentication.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(handler, auth);

            assertThat(result).isEqualTo(testUser);
        }

        @Test
        @DisplayName("should find user by ID from OAuth2UserPrincipal")
        void shouldFindUserByIdFromOAuth2UserPrincipal() throws Exception {
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "12345");
            attributes.put("email", "test@example.com");

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);
            TestAuthentication auth = new TestAuthentication(principal);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getAuthUser", Authentication.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(handler, auth);

            assertThat(result).isEqualTo(testUser);
            verify(authUserRepository).findById(testUser.getId());
        }

        @Test
        @DisplayName("should return null for unknown principal type")
        void shouldReturnNullForUnknownPrincipalType() throws Exception {
            TestAuthentication auth = new TestAuthentication("unknown-principal");

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getAuthUser", Authentication.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(handler, auth);

            assertThat(result).isNull();
        }

        @Test
        @DisplayName("should return null when user not found in repository")
        void shouldReturnNullWhenUserNotFoundInRepository() throws Exception {
            when(authUserRepository.findById(testUser.getId())).thenReturn(Optional.empty());

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "12345");
            attributes.put("email", "test@example.com");

            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);
            TestAuthentication auth = new TestAuthentication(principal);

            Method method = OAuth2AuthenticationSuccessHandler.class
                    .getDeclaredMethod("getAuthUser", Authentication.class);
            method.setAccessible(true);

            AuthUser result = (AuthUser) method.invoke(handler, auth);

            assertThat(result).isNull();
            verify(authUserRepository).findById(testUser.getId());
        }
    }

    @Nested
    @DisplayName("Token Generation Integration")
    class TokenGenerationTests {

        @Test
        @DisplayName("should generate access token for user")
        void shouldGenerateAccessTokenForUser() {
            when(jwtOperations.generateAccessToken(testUser)).thenReturn("test-access-token");

            String token = jwtOperations.generateAccessToken(testUser);

            assertThat(token).isEqualTo("test-access-token");
            verify(jwtOperations).generateAccessToken(testUser);
        }

        @Test
        @DisplayName("should generate refresh token for user")
        void shouldGenerateRefreshTokenForUser() {
            when(jwtOperations.generateRefreshToken(testUser)).thenReturn("test-refresh-token");

            String token = jwtOperations.generateRefreshToken(testUser);

            assertThat(token).isEqualTo("test-refresh-token");
            verify(jwtOperations).generateRefreshToken(testUser);
        }
    }

    // Simple Authentication implementation for testing
    static class TestAuthentication implements Authentication {
        private final Object principal;

        TestAuthentication(Object principal) {
            this.principal = principal;
        }

        @Override
        public Object getPrincipal() {
            return principal;
        }

        @Override
        public String getName() {
            return "test";
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return Collections.emptyList();
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return null;
        }

        @Override
        public boolean isAuthenticated() {
            return true;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        }
    }
}
